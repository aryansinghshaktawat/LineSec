import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database import Base
import models
import schemas
from services.ingestion import IngestionService
from services.grouping import TaskGroupingEngine

@pytest.fixture
def db_session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    try:
        yield session
    finally:
        session.close()

def test_task_grouping_multiple_cves_single_package(db_session):
    """
    Verify 3 distinct CVEs affecting 'urllib3' are grouped into a single RemediationTask
    targeting the highest fixed version.
    """
    payload = [
        schemas.FindingCreate(
            tool_name="trivy",
            vulnerability_name="CVE-2023-43804",
            cve="CVE-2023-43804",
            severity="HIGH",
            package="urllib3",
            ecosystem="pip",
            installed_version="1.26.5",
            fixed_version="1.26.17"
        ),
        schemas.FindingCreate(
            tool_name="trivy",
            vulnerability_name="CVE-2023-45803",
            cve="CVE-2023-45803",
            severity="MEDIUM",
            package="urllib3",
            ecosystem="pip",
            installed_version="1.26.5",
            fixed_version="1.26.18"
        ),
        schemas.FindingCreate(
            tool_name="trivy",
            vulnerability_name="CVE-2024-37891",
            cve="CVE-2024-37891",
            severity="CRITICAL",
            package="urllib3",
            ecosystem="pip",
            installed_version="1.26.5",
            fixed_version="1.26.19"
        )
    ]

    # Ingest findings
    IngestionService.ingest_findings(db_session, payload, repository_id="repo-main")

    # Run Grouping Engine
    tasks = TaskGroupingEngine.group_repository_findings(db_session, repository_id="repo-main")
    
    # Assert exactly ONE task created for urllib3
    assert len(tasks) == 1
    task = tasks[0]
    assert task.package == "urllib3"
    assert task.ecosystem == "pip"
    assert task.action == "upgrade"
    # Target version must be the highest fixed version
    assert task.target_version == "1.26.19"
    # Priority elevated to P0 due to CRITICAL finding
    assert task.priority == "P0"
    # All 3 findings must be linked to this task
    assert len(task.findings) == 3
