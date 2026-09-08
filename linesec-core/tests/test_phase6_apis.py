import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
import models
from main import app, get_db
from core.fingerprint import generate_finding_fingerprint

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

def test_security_diff_and_verify_endpoints(client):
    c, SessionLocal = client
    db = SessionLocal()

    repo = models.Repository(repository_id="repo-verify", name="LineSec-Verify")
    db.add(repo)
    db.commit()

    fp1 = generate_finding_fingerprint("repo-verify", "bandit", "B101: Test for assert used", "main.py", 10)
    task = models.RemediationTask(
        task_id="task-test-v1",
        title="Fix assert statement in main.py",
        action="manual",
        status="IN_PROGRESS"
    )
    db.add(task)
    db.commit()

    finding = models.Finding(
        finding_id="f-v1",
        task_id="task-test-v1",
        repository_id="repo-verify",
        fingerprint=fp1,
        vulnerability_name="B101: Test for assert used",
        scanner="bandit",
        file_path="main.py",
        line_number=10,
        severity="LOW",
        status="IN_PROGRESS"
    )
    db.add(finding)
    db.commit()
    db.close()

    # 1. Test POST /api/v1/verification/diff
    diff_resp = c.post(
        "/api/v1/verification/diff?repository_id=repo-verify",
        json=[]  # Clean scan
    )
    assert diff_resp.status_code == 200
    diff_data = diff_resp.json()
    assert diff_data["total_base"] == 1
    assert diff_data["total_rescan"] == 0
    assert diff_data["resolved_count"] == 1
    assert diff_data["verdict"] == "PASSED"

    # 2. Test POST /api/v1/tasks/{task_id}/verify
    verify_resp = c.post(
        "/api/v1/tasks/task-test-v1/verify",
        json={"rescan_findings": []}
    )
    assert verify_resp.status_code == 200
    v_data = verify_resp.json()
    assert v_data["verified"] is True
    assert v_data["status"] == "RESOLVED"
    assert v_data["resolved_count"] == 1
