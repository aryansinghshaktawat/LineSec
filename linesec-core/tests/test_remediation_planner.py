import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
import models
from services.planner import RemediationPlanner
from core.safety import SafetyLevel

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

def test_remediation_planner_creates_fix_plan(db_session):
    # Setup repository and task
    repo = models.Repository(repository_id="repo-1", name="LineSec-Test")
    db_session.add(repo)
    db_session.commit()

    task = models.RemediationTask(
        task_id="task-123",
        title="Upgrade requests",
        package="requests",
        ecosystem="pip",
        action="upgrade",
        target_version="2.31.0",
        priority="P1",
        status="OPEN"
    )
    db_session.add(task)
    db_session.commit()

    finding = models.Finding(
        finding_id="find-1",
        task_id="task-123",
        repository_id="repo-1",
        vulnerability_name="CVE-2023-32681 requests vulnerability",
        scanner="trivy",
        file_path="requirements.txt",
        package="requests",
        installed_version="2.25.0",
        fixed_version="2.31.0",
        cve="CVE-2023-32681",
        severity="HIGH",
        status="DETECTED"
    )
    db_session.add(finding)
    db_session.commit()

    plan = RemediationPlanner.create_fix_plan(db=db_session, task_id="task-123", environment="development")
    assert plan is not None
    assert plan.package == "requests"
    assert plan.target_version == "2.31.0"
    assert plan.safety_level == SafetyLevel.SAFE
    assert "requests>=2.31.0" in plan.verification_steps

    # Check AuditEvent generated
    audit = db_session.query(models.AuditEvent).filter(models.AuditEvent.entity_id == "task-123").first()
    assert audit is not None
    assert audit.event_type == "FIX_PLAN_CREATED"
