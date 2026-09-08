import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
import models
import schemas
from services.verification import SecurityDiffService, VerificationEngine
from core.fingerprint import generate_finding_fingerprint

@pytest.fixture
def db_session():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool
    )
    models.Base.metadata.create_all(bind=engine)
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    session = SessionLocal()
    yield session
    session.close()

def test_security_diff_calculation(db_session):
    # Setup base findings
    fp1 = generate_finding_fingerprint("default", "bandit", "B301: Pickle usage", "app/auth.py", 42)
    fp2 = generate_finding_fingerprint("default", "bandit", "B108: Hardcoded tmp dir", "app/temp.py", 15)

    f1 = models.Finding(
        finding_id="f-1",
        repository_id="default",
        fingerprint=fp1,
        vulnerability_name="B301: Pickle usage",
        scanner="bandit",
        file_path="app/auth.py",
        line_number=42,
        severity="HIGH",
        status="ANALYZED"
    )
    f2 = models.Finding(
        finding_id="f-2",
        repository_id="default",
        fingerprint=fp2,
        vulnerability_name="B108: Hardcoded tmp dir",
        scanner="bandit",
        file_path="app/temp.py",
        line_number=15,
        severity="MEDIUM",
        status="ANALYZED"
    )
    db_session.add_all([f1, f2])
    db_session.commit()

    # Rescan only contains f2 (f1 is fixed) + f3 is new
    f3_schema = schemas.FindingCreate(
        repository_id="default",
        tool_name="bandit",
        scanner="bandit",
        vulnerability_name="B602: Subprocess popen",
        file_path="app/worker.py",
        line_number=99,
        severity="LOW"
    )
    f2_schema = schemas.FindingCreate(
        repository_id="default",
        tool_name="bandit",
        scanner="bandit",
        vulnerability_name="B108: Hardcoded tmp dir",
        file_path="app/temp.py",
        line_number=15,
        severity="MEDIUM"
    )

    diff = SecurityDiffService.compare_finding_sets(
        base_findings=[f1, f2],
        rescan_findings=[f2_schema, f3_schema],
        db=db_session
    )

    assert diff["total_base"] == 2
    assert diff["total_rescan"] == 2
    assert diff["resolved_count"] == 1
    assert diff["resolved_findings"][0]["fingerprint"] == fp1
    assert diff["unchanged_count"] == 1
    assert diff["unchanged_findings"][0]["fingerprint"] == fp2
    assert diff["new_count"] == 1
    assert diff["new_findings"][0]["file_path"] == "app/worker.py"
    assert diff["verdict"] == "FAILED"  # Because f2 remained unchanged

def test_verification_engine_task_success(db_session):
    fp = generate_finding_fingerprint("default", "trivy", "requests info leak", "requirements.txt", 0, "requests")
    task = models.RemediationTask(
        task_id="task-verify-1",
        title="Upgrade requests",
        package="requests",
        target_version="2.31.0",
        status="IN_PROGRESS"
    )
    db_session.add(task)
    db_session.commit()

    f = models.Finding(
        finding_id="f-verify-1",
        repository_id="default",
        task_id="task-verify-1",
        fingerprint=fp,
        vulnerability_name="requests info leak",
        scanner="trivy",
        cve="CVE-2023-32681",
        file_path="requirements.txt",
        package="requests",
        status="IN_PROGRESS"
    )
    db_session.add(f)
    db_session.commit()

    # Rescan finds 0 findings (clean)
    res = VerificationEngine.verify_task(
        db=db_session,
        task_id="task-verify-1",
        rescan_findings=[]
    )

    assert res["verified"] is True
    assert res["resolved_count"] == 1
    assert res["remaining_count"] == 0
    assert res["status"] == "RESOLVED"

    # Database checks
    db_session.refresh(task)
    db_session.refresh(f)
    assert task.status == "RESOLVED"
    assert f.status == "RESOLVED"

    # Check AuditEvent
    audit = db_session.query(models.AuditEvent).filter(
        models.AuditEvent.entity_id == "task-verify-1",
        models.AuditEvent.event_type == "TASK_VERIFIED"
    ).first()
    assert audit is not None
