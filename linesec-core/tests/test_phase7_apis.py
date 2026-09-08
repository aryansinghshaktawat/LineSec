from datetime import datetime, timezone, timedelta
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

def test_sla_report_and_risk_acceptance_apis(client):
    c, SessionLocal = client
    db = SessionLocal()

    now = datetime.now(timezone.utc)
    old_time = now - timedelta(days=2) # 48h ago, P0 breached

    repo = models.Repository(repository_id="repo-sla", name="LineSec-SLA")
    db.add(repo)
    db.commit()

    # Task 1: P0 created 48h ago (Breached)
    t1 = models.RemediationTask(
        task_id="t-sla-1",
        title="Critical RCE in auth",
        priority="P0",
        status="PENDING",
        created_at=old_time
    )
    # Task 2: P1 created 1h ago (On track)
    t2 = models.RemediationTask(
        task_id="t-sla-2",
        title="High Severity XSS",
        priority="P1",
        status="PENDING",
        created_at=now - timedelta(hours=1)
    )
    db.add_all([t1, t2])
    db.commit()
    db.close()

    # 1. Test GET /api/v1/posture/sla
    sla_resp = c.get("/api/v1/posture/sla?repository_id=repo-sla")
    assert sla_resp.status_code == 200
    sla_data = sla_resp.json()
    assert sla_data["active_tasks_count"] == 2
    assert sla_data["breached_tasks_count"] == 1
    assert sla_data["on_track_tasks_count"] == 1
    assert sla_data["priority_breakdown"]["P0"]["breached"] == 1
    assert sla_data["priority_breakdown"]["P1"]["on_track"] == 1

    # 2. Test POST /api/v1/risk-acceptance
    waiver_payload = {
        "task_id": "t-sla-1",
        "reason": "Legacy auth system slated for deprecation next sprint",
        "owner": "security-lead@linesec.io",
        "expires_at": (now + timedelta(days=30)).isoformat()
    }
    waiver_resp = c.post("/api/v1/risk-acceptance", json=waiver_payload)
    assert waiver_resp.status_code == 200
    waiver_data = waiver_resp.json()
    assert waiver_data["task_id"] == "t-sla-1"
    assert waiver_data["status"] == "ACTIVE"

    # 3. Test GET /api/v1/posture/sla after waiver (t1 is waived, so active_tasks_count becomes 1)
    sla_resp_after = c.get("/api/v1/posture/sla?repository_id=repo-sla")
    assert sla_resp_after.status_code == 200
    sla_data_after = sla_resp_after.json()
    assert sla_data_after["active_tasks_count"] == 1
    assert sla_data_after["breached_tasks_count"] == 0
    assert sla_data_after["waived_items_count"] == 1

    # 4. Test GET /api/v1/risk-acceptance
    list_resp = c.get("/api/v1/risk-acceptance")
    assert list_resp.status_code == 200
    assert len(list_resp.json()) == 1
