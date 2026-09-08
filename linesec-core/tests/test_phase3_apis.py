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

def test_risk_evaluate_and_policy_evaluate_api(client):
    # 1. Ingest findings
    ingest_payload = [
        {
            "tool_name": "trivy",
            "vulnerability_name": "CVE-2023-32681",
            "cve": "CVE-2023-32681",
            "severity": "CRITICAL",
            "package": "requests",
            "ecosystem": "pip",
            "fixed_version": "2.31.0"
        }
    ]
    client.post("/api/ingest", json=ingest_payload)

    # 2. Risk Evaluation Endpoint in Production
    risk_res = client.post("/api/v1/risk/evaluate?repository_id=default&environment=production&criticality=CRITICAL&internet_exposed=true")
    assert risk_res.status_code == 200
    risk_data = risk_res.json()
    assert risk_data["evaluated_findings"] == 1
    assert risk_data["findings"][0]["priority"] == "P0"
    assert risk_data["findings"][0]["risk_score"] >= 85.0

    # 3. Policy Evaluation Endpoint in Production (Must BLOCK)
    policy_res = client.post("/api/v1/policy/evaluate?repository_id=default&environment=production")
    assert policy_res.status_code == 200
    policy_data = policy_res.json()
    assert policy_data["action"] == "BLOCK"
    assert "block-p0-production" in policy_data["matched_rules"]
