import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database import Base
import models
import schemas
from services.ingestion import IngestionService
from core.lifecycle import FindingStatus

@pytest.fixture
def db_session():
    # In-memory SQLite for high-speed isolated tests
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    try:
        yield session
    finally:
        session.close()

def test_ingestion_deduplication(db_session):
    """Verify scanning the exact same findings twice does not duplicate rows."""
    payload = [
        schemas.FindingCreate(
            tool_name="bandit",
            vulnerability_name="B104_hardcoded_bind_all_interfaces",
            severity="MEDIUM",
            description="Possible binding to all interfaces",
            file_path="main.py",
            line_number=50
        )
    ]

    # First Ingest
    processed1, stats1 = IngestionService.ingest_findings(db_session, payload, repository_id="repo-1")
    assert stats1["new"] == 1
    assert stats1["existing"] == 0
    assert len(processed1) == 1
    assert db_session.query(models.Finding).count() == 1

    first_fingerprint = processed1[0].fingerprint
    assert first_fingerprint is not None

    # Second Ingest of identical finding
    processed2, stats2 = IngestionService.ingest_findings(db_session, payload, repository_id="repo-1")
    assert stats2["new"] == 0
    assert stats2["existing"] == 1
    assert len(processed2) == 1
    # Total count in database MUST STILL BE 1
    assert db_session.query(models.Finding).count() == 1
    assert processed2[0].fingerprint == first_fingerprint

def test_ingestion_regression_detection(db_session):
    """Verify a finding marked as RESOLVED transitions to REGRESSED upon rescan."""
    payload = [
        schemas.FindingCreate(
            tool_name="bandit",
            vulnerability_name="B301_pickle",
            severity="HIGH",
            description="Pickle and modules that wrap it can be unsafe",
            file_path="utils.py",
            line_number=20
        )
    ]

    # Initial Ingest
    processed, stats = IngestionService.ingest_findings(db_session, payload, repository_id="repo-1")
    finding = processed[0]
    assert finding.status == FindingStatus.NEW.value

    # Manually transition to RESOLVED (e.g. after successful remediation and rescan)
    finding.status = FindingStatus.RESOLVED.value
    finding.remediation_status = FindingStatus.RESOLVED.value
    db_session.commit()

    # Rescan finds the vulnerability again -> Regression!
    processed_after_rescan, stats_rescan = IngestionService.ingest_findings(db_session, payload, repository_id="repo-1")
    assert stats_rescan["regressed"] == 1
    assert processed_after_rescan[0].status == FindingStatus.REGRESSED.value
    assert processed_after_rescan[0].remediation_status == FindingStatus.REGRESSED.value
