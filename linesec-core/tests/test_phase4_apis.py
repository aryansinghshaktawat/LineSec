import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from database import Base
from main import app, get_db

@pytest.fixture
def client():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool
    )
    Base.metadata.create_all(bind=engine)
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

    def override_get_db():
        db = TestingSessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()

def test_task_analyze_endpoint(client):
    # 1. Ingest finding & group task
    ingest_payload = [
        {
            "tool_name": "trivy",
            "vulnerability_name": "CVE-2023-32681",
            "cve": "CVE-2023-32681",
            "severity": "HIGH",
            "package": "requests",
            "ecosystem": "pip",
            "fixed_version": "2.31.0"
        }
    ]
    client.post("/api/ingest", json=ingest_payload)
    group_res = client.post("/api/v1/tasks/group?repository_id=default")
    tasks = group_res.json()
    assert len(tasks) == 1
    task_id = tasks[0]["task_id"]

    # 2. Call /api/v1/tasks/{task_id}/analyze
    analyze_res = client.post(f"/api/v1/tasks/{task_id}/analyze?environment=staging")
    assert analyze_res.status_code == 200
    decision = analyze_res.json()
    assert decision["task_id"] == task_id
    assert "requests" in decision["summary"]
    assert decision["provider"] in ("gemini", "deterministic_fallback")
    assert decision["deployment_risk"] in ("LOW", "MEDIUM", "HIGH")
