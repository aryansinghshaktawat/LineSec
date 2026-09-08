import json
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
import models
from main import app, get_db
from core.fingerprint import generate_finding_fingerprint
from core.lifecycle import FindingStatus, TaskStatus

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

def test_complete_linesec2_e2e_lifecycle(client):
    """
    End-to-End Pipeline Verification:
    DETECT -> DEDUPLICATE -> GROUP -> ENRICH & RISK -> POLICY -> AI DECISION -> 
    FIX PLAN & SAFETY -> REMEDIATE -> RESCAN & VERIFY -> RESOLVED & POSTURE
    """
    c, SessionLocal = client
    repo_id = "repo-e2e"

    # Step 1: Ingest SAST & SCA Scans
    trivy_scan_payload = {
        "repository_id": repo_id,
        "scanner": "trivy",
        "scanner_type": "SCA",
        "findings": [
            {
                "tool_name": "trivy",
                "scanner": "trivy",
                "scanner_type": "SCA",
                "vulnerability_name": "CVE-2023-32681: Information Disclosure in Requests",
                "cve": "CVE-2023-32681",
                "severity": "HIGH",
                "description": "Proxy-Authorization header leak to untrusted target hosts.",
                "file_path": "requirements.txt",
                "package": "requests",
                "installed_version": "2.25.0",
                "fixed_version": "2.31.0",
                "environment": "production"
            },
            {
                "tool_name": "trivy",
                "scanner": "trivy",
                "scanner_type": "SCA",
                "vulnerability_name": "CVE-2023-45803: Stream Request Leakage",
                "cve": "CVE-2023-45803",
                "severity": "MEDIUM",
                "description": "Memory stream leak on redirect.",
                "file_path": "requirements.txt",
                "package": "requests",
                "installed_version": "2.25.0",
                "fixed_version": "2.31.0",
                "environment": "production"
            }
        ]
    }

    ingest_resp = c.post("/api/v1/ingest/batch", json=trivy_scan_payload)
    assert ingest_resp.status_code == 200
    ingest_data = ingest_resp.json()
    assert ingest_data["new_findings"] == 2

    # Step 2: Ingest duplicate scan to verify deduplication
    dup_resp = c.post("/api/v1/ingest/batch", json=trivy_scan_payload)
    assert dup_resp.status_code == 200
    assert dup_resp.json()["new_findings"] == 0
    assert dup_resp.json()["existing_findings"] == 2

    # Step 3: Group Findings into Unified Remediation Task
    group_resp = c.post(f"/api/v1/tasks/group?repository_id={repo_id}")
    assert group_resp.status_code == 200
    tasks = group_resp.json()
    assert len(tasks) == 1
    task = tasks[0]
    task_id = task["task_id"]
    assert task["package"] == "requests"
    assert task["target_version"] == "2.31.0"
    assert task["findings_count"] == 2

    # Step 4: Contextual Risk Scoring & Policy Evaluation
    risk_resp = c.post(f"/api/v1/risk/evaluate?repository_id={repo_id}&environment=production")
    assert risk_resp.status_code == 200
    risk_data = risk_resp.json()
    assert risk_data["evaluated_findings"] == 2
    assert all(f["risk_score"] > 0 for f in risk_data["findings"])


    policy_resp = c.post(f"/api/v1/policy/evaluate?repository_id={repo_id}&environment=production")
    assert policy_resp.status_code == 200
    assert policy_resp.json()["action"] in ["PASS", "WARN", "BLOCK"]

    # Step 5: AI / Fallback Task Decision Analysis
    analyze_resp = c.post(f"/api/v1/tasks/{task_id}/analyze?environment=production")
    assert analyze_resp.status_code == 200
    decision = analyze_resp.json()
    assert decision["task_id"] == task_id
    assert "summary" in decision
    assert decision["confidence"] > 0

    # Step 6: FixPlan Generation & Safety Validation
    plan_resp = c.post(f"/api/v1/tasks/{task_id}/plan?environment=production")
    assert plan_resp.status_code == 200
    plan = plan_resp.json()
    assert plan["package"] == "requests"
    assert plan["safety_level"] == "SAFE"

    # Step 7: Auto-Remediate PR Generation
    remediate_resp = c.post(f"/api/v1/tasks/{task_id}/remediate?dry_run=false")
    assert remediate_resp.status_code == 200
    rem_data = remediate_resp.json()
    assert "linesec/fix-requests" in rem_data["branch_name"]
    assert rem_data["status"] == "PR_OPENED"

    # Step 8: Post-Fix Rescan Verification & Security Diff
    # Clean rescan simulates successful upgrade
    verify_resp = c.post(
        f"/api/v1/tasks/{task_id}/verify",
        json={"rescan_findings": []}
    )
    assert verify_resp.status_code == 200
    v_data = verify_resp.json()
    assert v_data["verified"] is True
    assert v_data["status"] == "RESOLVED"
    assert v_data["resolved_count"] == 2
    assert v_data["remaining_count"] == 0

    # Step 9: Verify Posture & SLA Metrics after Resolution
    posture_resp = c.get(f"/api/v1/posture?repository_id={repo_id}")
    assert posture_resp.status_code == 200
    p_data = posture_resp.json()
    assert p_data["remediation_progress_percent"] == 100.0

    # Step 10: Verify Audit Log Completeness
    audit_resp = c.get("/api/v1/audit?limit=20")
    assert audit_resp.status_code == 200
    events = audit_resp.json()
    event_types = [e["event_type"] for e in events]
    assert "FINDINGS_INGESTED" in event_types
    assert "TASK_VERIFIED" in event_types

