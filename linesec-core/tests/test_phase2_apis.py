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

def test_trivy_import_and_task_grouping_api(client):
    # 1. Post Trivy Scan Payload
    trivy_payload = {
        "SchemaVersion": 2,
        "Results": [
            {
                "Target": "package.json",
                "Type": "npm",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2023-26136",
                        "PkgName": "tough-cookie",
                        "InstalledVersion": "2.5.0",
                        "FixedVersion": "4.1.3",
                        "Severity": "CRITICAL"
                    },
                    {
                        "VulnerabilityID": "CVE-2023-45857",
                        "PkgName": "tough-cookie",
                        "InstalledVersion": "2.5.0",
                        "FixedVersion": "4.1.3",
                        "Severity": "HIGH"
                    }
                ]
            }
        ]
    }

    import_res = client.post("/api/v1/adapters/trivy/import?repository_id=frontend-app", json=trivy_payload)
    assert import_res.status_code == 200
    import_data = import_res.json()
    assert import_data["total_received"] == 2
    assert import_data["new_findings"] == 2

    # 2. Trigger Task Grouping
    group_res = client.post("/api/v1/tasks/group?repository_id=frontend-app")
    assert group_res.status_code == 200
    tasks = group_res.json()
    assert len(tasks) == 1
    task = tasks[0]
    assert task["package"] == "tough-cookie"
    assert task["target_version"] == "4.1.3"
    assert task["priority"] == "P0"
    assert task["findings_count"] == 2

    # 3. Retrieve Tasks List API
    tasks_list_res = client.get("/api/v1/tasks")
    assert tasks_list_res.status_code == 200
    assert len(tasks_list_res.json()) == 1

    # 4. Retrieve Task Detail API
    task_id = task["task_id"]
    detail_res = client.get(f"/api/v1/tasks/{task_id}")
    assert detail_res.status_code == 200
    detail_data = detail_res.json()
    assert len(detail_data["findings"]) == 2

def test_sarif_export_api(client):
    bandit_payload = {
        "results": [
            {
                "test_name": "B101_assert",
                "issue_severity": "LOW",
                "issue_text": "Use of assert detected",
                "filename": "test.py",
                "line_number": 5
            }
        ]
    }
    client.post("/api/v1/adapters/bandit/import", json=bandit_payload)

    export_res = client.get("/api/v1/adapters/sarif/export")
    assert export_res.status_code == 200
    sarif = export_res.json()
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"][0]["results"]) == 1
    assert sarif["runs"][0]["results"][0]["ruleId"] == "B101_assert"
