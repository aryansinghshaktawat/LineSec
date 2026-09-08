import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from database import Base
import models
from main import app, get_db

@pytest.fixture
def client():
    # Setup thread-safe in-memory test database using StaticPool
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

def test_health_check(client):
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["api"] == "healthy"

def test_legacy_ingest_and_get_findings_compatibility(client):
    """
    Verify /api/ingest and /api/findings maintain 100% backward-compatibility
    with existing Bandit runner and Dashboard frontend payloads.
    """
    ingest_payload = [
        {
            "tool_name": "bandit",
            "vulnerability_name": "B104_hardcoded_bind_all_interfaces",
            "severity": "MEDIUM",
            "description": "Possible binding to all interfaces",
            "file_path": "main.py",
            "line_number": 45
        }
    ]

    # POST /api/ingest
    post_res = client.post("/api/ingest", json=ingest_payload)
    assert post_res.status_code == 200
    post_data = post_res.json()
    assert len(post_data) == 1
    assert "finding_id" in post_data[0]
    assert post_data[0]["vulnerability_name"] == "B104_hardcoded_bind_all_interfaces"
    assert post_data[0]["fingerprint"] is not None

    # GET /api/findings
    get_res = client.get("/api/findings")
    assert get_res.status_code == 200
    get_data = get_res.json()
    assert len(get_data) == 1
    assert get_data[0]["tool_name"] == "bandit"
    assert get_data[0]["file_path"] == "main.py"

def test_batch_ingest_endpoint(client):
    """Verify /api/v1/ingest/batch returns rich ingestion telemetry."""
    batch_payload = {
        "repository_id": "line-repo",
        "scanner": "trivy",
        "scanner_type": "SCA",
        "branch": "main",
        "findings": [
            {
                "tool_name": "trivy",
                "vulnerability_name": "CVE-2023-32681",
                "cve": "CVE-2023-32681",
                "severity": "HIGH",
                "package": "requests",
                "ecosystem": "pip",
                "installed_version": "2.25.0",
                "fixed_version": "2.31.0",
                "file_path": "requirements.txt",
                "line_number": 4
            }
        ]
    }
    res = client.post("/api/v1/ingest/batch", json=batch_payload)
    assert res.status_code == 200
    data = res.json()
    assert data["total_received"] == 1
    assert data["new_findings"] == 1
    assert data["scanner"] == "trivy"
    assert len(data["findings"]) == 1
    assert data["findings"][0]["cve"] == "CVE-2023-32681"

def test_posture_endpoint(client):
    """Verify /api/v1/posture calculates metrics correctly."""
    ingest_payload = [
        {
            "tool_name": "bandit",
            "vulnerability_name": "B101",
            "severity": "CRITICAL",
            "description": "Critical issue",
            "file_path": "auth.py",
            "line_number": 10
        },
        {
            "tool_name": "bandit",
            "vulnerability_name": "B102",
            "severity": "LOW",
            "description": "Low issue",
            "file_path": "view.py",
            "line_number": 20
        }
    ]
    client.post("/api/ingest", json=ingest_payload)

    res = client.get("/api/v1/posture?repository_id=default")
    assert res.status_code == 200
    data = res.json()
    assert data["total_findings"] == 2
    assert data["critical_count"] == 1
    assert data["low_count"] == 1
    assert data["security_score"] < 100.0
    assert data["security_debt_hours"] > 0
