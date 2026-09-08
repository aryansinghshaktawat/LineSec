import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
import models
from main import app, get_db

@pytest.fixture
def client():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool
    )
    models.Base.metadata.create_all(bind=engine)
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

    def override_get_db():
        db = TestingSessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as c:
        yield c, TestingSessionLocal
    app.dependency_overrides.clear()

def test_plan_and_remediate_endpoints(client):
    c, SessionLocal = client
    db = SessionLocal()

    repo = models.Repository(repository_id="repo-main", name="LineSec-Platform")
    db.add(repo)
    db.commit()

    task = models.RemediationTask(
        task_id="task-safe-1",
        title="Upgrade urllib3 for CVE-2023-45803",
        package="urllib3",
        ecosystem="pip",
        action="upgrade",
        target_version="1.26.18",
        priority="P2",
        status="OPEN"
    )
    db.add(task)
    db.commit()

    finding = models.Finding(
        finding_id="f-1",
        task_id="task-safe-1",
        repository_id="repo-main",
        vulnerability_name="urllib3 stream request body leak",
        scanner="trivy",
        file_path="requirements.txt",
        package="urllib3",
        installed_version="1.26.5",
        fixed_version="1.26.18",
        cve="CVE-2023-45803",
        severity="MEDIUM",
        status="DETECTED"
    )
    db.add(finding)
    db.commit()
    db.close()

    # 1. Test POST /api/v1/tasks/{task_id}/plan
    plan_resp = c.post("/api/v1/tasks/task-safe-1/plan?environment=staging")
    assert plan_resp.status_code == 200
    plan_data = plan_resp.json()
    assert plan_data["task_id"] == "task-safe-1"
    assert plan_data["package"] == "urllib3"
    assert plan_data["safety_level"] == "SAFE"
    assert "verification_steps" in plan_data

    # 2. Test POST /api/v1/tasks/{task_id}/remediate dry_run
    dry_resp = c.post("/api/v1/tasks/task-safe-1/remediate?dry_run=true")
    assert dry_resp.status_code == 200
    dry_data = dry_resp.json()
    assert dry_data["dry_run"] is True
    assert "linesec/fix-urllib3" in dry_data["branch_name"]
    assert "LineSec Automated Security Remediation" in dry_data["pr_body"]
    assert dry_data["status"] == "OPEN"

    # 3. Test POST /api/v1/tasks/{task_id}/remediate real run
    rem_resp = c.post("/api/v1/tasks/task-safe-1/remediate?dry_run=false")
    assert rem_resp.status_code == 200
    rem_data = rem_resp.json()
    assert rem_data["status"] == "PR_OPENED"
