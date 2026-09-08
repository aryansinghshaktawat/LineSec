import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database import Base
import models
from ai.service import AIAnalysisService

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

def test_ai_service_orchestration_with_fallback(db_session):
    # 1. Create a task and finding in DB
    task = models.RemediationTask(
        title="Upgrade requests to 2.31.0",
        package="requests",
        ecosystem="pip",
        action="upgrade",
        target_version="2.31.0",
        priority="P1"
    )
    db_session.add(task)
    db_session.flush()

    finding = models.Finding(
        vulnerability_name="CVE-2023-32681",
        cve="CVE-2023-32681",
        severity="HIGH",
        package="requests",
        task_id=task.task_id
    )
    db_session.add(finding)
    db_session.commit()

    # 2. Analyze task
    service = AIAnalysisService()
    decision = service.analyze_task(db_session, task_id=task.task_id, environment="staging")

    assert decision.task_id == task.task_id
    assert decision.provider == "deterministic_fallback"
    assert "requests" in decision.summary
    assert task.status == "ANALYZED"
    assert finding.status == "ANALYZED"
    assert finding.root_cause is not None
    assert finding.remediation_plan is not None
