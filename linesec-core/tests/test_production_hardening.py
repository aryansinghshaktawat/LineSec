import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import json
import uuid
import pytest
import tempfile
import shutil
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import models
import schemas
from database import Base
from main import app, get_db
from core.config import settings
from core.auth import Role, UserContext
from core.fingerprint import generate_finding_fingerprint
from services.remediation_service import RemediationExecutionService
from services.verification import VerificationEngine

# In-memory SQLite for testing
SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"
test_engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)

def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()

app.dependency_overrides[get_db] = override_get_db
client = TestClient(app)

@pytest.fixture(autouse=True)
def setup_database():
    Base.metadata.drop_all(bind=test_engine)
    Base.metadata.create_all(bind=test_engine)
    yield
    Base.metadata.drop_all(bind=test_engine)


# ==========================================
# 1. RBAC & Security Authentication Tests
# ==========================================

def test_rbac_unauthenticated_access_in_prod_mode(monkeypatch):
    monkeypatch.setattr(settings, "DEV_MODE", False)
    
    # Unauthenticated request to protected route
    resp = client.get("/api/v1/tasks")
    assert resp.status_code == 401
    assert "Missing authentication credentials" in resp.json()["detail"]


def test_rbac_role_hierarchy_and_permissions(monkeypatch):
    monkeypatch.setattr(settings, "DEV_MODE", False)
    
    # Viewer role token
    viewer_headers = {"X-LineSec-Key": "test-key-view"}
    
    # Viewer can read tasks
    resp = client.get("/api/v1/tasks", headers=viewer_headers)
    assert resp.status_code == 200
    
    # Viewer CANNOT execute developer remediation
    resp = client.post("/api/v1/tasks/task-fake/remediate", headers=viewer_headers)
    assert resp.status_code == 403
    assert "Permission denied" in resp.json()["detail"]
    
    # Viewer CANNOT create risk acceptance (requires SECURITY_ENGINEER)
    waiver_payload = {
        "reason": "Business requirement",
        "owner": "sec-team",
        "task_id": "task-test-waiver",
        "expires_at": "2027-01-01T00:00:00Z"
    }
    resp = client.post("/api/v1/risk-acceptance", json=waiver_payload, headers=viewer_headers)
    assert resp.status_code == 403

    # Developer role token CANNOT create risk acceptance (requires SECURITY_ENGINEER)
    dev_headers = {"X-LineSec-Key": "test-key-dev"}
    resp = client.post("/api/v1/risk-acceptance", json=waiver_payload, headers=dev_headers)
    assert resp.status_code == 403

    # Security Engineer CAN create risk acceptance
    sec_headers = {"X-LineSec-Key": "test-key-seceng"}
    resp = client.post("/api/v1/risk-acceptance", json=waiver_payload, headers=sec_headers)
    assert resp.status_code == 200
    assert resp.json()["status"] == "ACTIVE"


# ==========================================
# 2. Repository Management & Data Integrity Tests
# ==========================================

def test_repository_crud_and_foreign_key_linkage():
    # 1. Create Repository
    unique_name = f"LineSec-Core-{uuid.uuid4().hex[:6]}"
    repo_payload = {
        "name": unique_name,
        "url": "https://github.com/LineSec-Platform/linesec-core",
        "default_branch": "main",
        "environment": "production",
        "criticality": "HIGH",
        "internet_exposed": True,
        "owner": "security-team"
    }
    resp = client.post("/api/v1/repositories", json=repo_payload)
    assert resp.status_code == 200
    repo_data = resp.json()
    repo_id = repo_data["repository_id"]
    assert repo_data["name"] == unique_name
    assert repo_data["criticality"] == "HIGH"

    # 2. List Repositories
    list_resp = client.get("/api/v1/repositories")
    assert list_resp.status_code == 200
    assert any(r["repository_id"] == repo_id for r in list_resp.json())

    # 3. Get Repository By ID
    get_resp = client.get(f"/api/v1/repositories/{repo_id}")
    assert get_resp.status_code == 200
    assert get_resp.json()["repository_id"] == repo_id

    # 4. Ingest findings linked to this repository
    ingest_payload = {
        "repository_id": repo_id,
        "scanner": "bandit",
        "findings": [
            {
                "vulnerability_name": "B105:hardcoded_password_string",
                "severity": "HIGH",
                "file_path": "core/auth.py",
                "line_number": 42,
                "description": "Possible hardcoded password."
            }
        ]
    }
    ingest_resp = client.post("/api/v1/ingest/batch", json=ingest_payload)
    assert ingest_resp.status_code == 200
    assert ingest_resp.json()["new_findings"] == 1


# ==========================================
# 3. Path Traversal & Workspace Isolation Tests
# ==========================================

def test_remediation_path_traversal_prevention():
    db = TestingSessionLocal()
    
    # Create test task
    task = models.RemediationTask(
        task_id="task-traversal-test",
        title="Fix Requests Vulnerability",
        package="requests",
        target_version="2.31.0",
        action="UPGRADE_PACKAGE",
        status="READY"
    )
    db.add(task)
    db.commit()

    # Attempt path traversal outside WORKSPACE_ROOT
    result = RemediationExecutionService.execute_remediation(
        db=db,
        task_id="task-traversal-test",
        workspace_dir="/tmp/../etc/passwd",
        dry_run=False
    )
    assert result["success"] is False
    assert "Path traversal attempt detected" in result["error"]
    db.close()


def test_remediation_real_workspace_git_and_patching():
    db = TestingSessionLocal()
    
    # 1. Create a temporary local workspace git repository
    temp_dir = tempfile.mkdtemp(prefix="linesec_test_workspace_")
    try:
        import subprocess
        # Initialize git repo in temp_dir
        subprocess.run(["git", "init", "-b", "main"], cwd=temp_dir, check=True, capture_output=True)
        subprocess.run(["git", "config", "user.name", "LineSec Bot"], cwd=temp_dir, check=True, capture_output=True)
        subprocess.run(["git", "config", "user.email", "bot@linesec.io"], cwd=temp_dir, check=True, capture_output=True)
        
        # Create requirements.txt
        req_path = os.path.join(temp_dir, "requirements.txt")
        with open(req_path, "w") as f:
            f.write("requests==2.25.0\nurllib3==1.26.4\n")
            
        subprocess.run(["git", "add", "requirements.txt"], cwd=temp_dir, check=True, capture_output=True)
        subprocess.run(["git", "commit", "-m", "Initial commit"], cwd=temp_dir, check=True, capture_output=True)

        # 2. Create task
        task = models.RemediationTask(
            task_id="task-workspace-patch-test",
            title="Upgrade requests to 2.31.0",
            package="requests",
            target_version="2.31.0",
            action="UPGRADE_PACKAGE",
            status="READY",
            safety_level="SAFE"
        )
        db.add(task)
        db.commit()

        # 3. Allow this temp_dir in WORKSPACE_ROOT
        orig_root = settings.WORKSPACE_ROOT
        settings.WORKSPACE_ROOT = os.path.dirname(temp_dir)

        try:
            # 4. Execute remediation
            exec_res = RemediationExecutionService.execute_remediation(
                db=db,
                task_id="task-workspace-patch-test",
                workspace_dir=temp_dir,
                dry_run=False
            )
            assert exec_res["success"] is True
            assert exec_res["manifest_patched"] is True
            assert exec_res["branch_created"].startswith("linesec/fix-requests-2.31.0")

            # Check that requirements.txt was actually updated on the new branch
            with open(req_path, "r") as f:
                updated_content = f.read()
            assert "requests>=2.31.0" in updated_content
            assert "urllib3==1.26.4" in updated_content
        finally:
            settings.WORKSPACE_ROOT = orig_root

    finally:
        db.close()
        shutil.rmtree(temp_dir, ignore_errors=True)


# ==========================================
# 4. Fingerprint Type-Aware Differentiation Tests
# ==========================================

def test_fingerprint_type_aware_generation():
    # SCA fingerprint
    fp_sca1 = generate_finding_fingerprint(
        repository="repo-1",
        scanner="trivy",
        vulnerability_identifier="CVE-2023-32681",
        package="requests",
        ecosystem="pip",
        scanner_type="sca"
    )
    fp_sca2 = generate_finding_fingerprint(
        repository="repo-1",
        scanner="trivy",
        vulnerability_identifier="CVE-2023-32681",
        package="requests",
        ecosystem="pip",
        scanner_type="sca"
    )
    assert fp_sca1 == fp_sca2
    assert isinstance(fp_sca1, str)
    assert len(fp_sca1) == 64

    # SAST fingerprint depends on file path and line number
    fp_sast = generate_finding_fingerprint(
        repository="repo-1",
        scanner="bandit",
        vulnerability_identifier="B105",
        file_path="core/auth.py",
        line_number=42,
        scanner_type="sast"
    )
    assert fp_sast != fp_sca1
    assert len(fp_sast) == 64


# ==========================================
# 5. Live Scanner Verification Engine Tests
# ==========================================

def test_verification_engine_local_bandit_scan():
    temp_dir = tempfile.mkdtemp(prefix="linesec_bandit_test_")
    try:
        # Create a Python file with a known security issue (eval usage)
        vuln_py = os.path.join(temp_dir, "vulnerable.py")
        with open(vuln_py, "w") as f:
            f.write("import os\neval('1 + 1')\n")

        returncode, findings, duration = VerificationEngine.run_local_scanner(temp_dir, scanner="bandit")
        assert duration >= 0.0
        # Bandit detects eval (B307)
        assert len(findings) > 0
        assert any("B307" in f.vulnerability_name or "eval" in f.description.lower() or "blacklist" in f.vulnerability_name.lower() for f in findings)
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)
