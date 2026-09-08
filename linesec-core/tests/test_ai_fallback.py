import pytest
from ai.fallback import DeterministicFallbackProvider
import models

def test_deterministic_fallback_upgrade_task():
    provider = DeterministicFallbackProvider()
    assert provider.is_available() is True

    task = models.RemediationTask(
        title="Upgrade urllib3 to 1.26.19",
        package="urllib3",
        ecosystem="pip",
        action="upgrade",
        target_version="1.26.19",
        priority="P1"
    )
    finding = models.Finding(
        vulnerability_name="CVE-2023-43804",
        cve="CVE-2023-43804",
        severity="HIGH"
    )

    decision = provider.analyze_task(task=task, findings=[finding], environment="production")
    assert "urllib3" in decision.summary
    assert "1.26.19" in decision.summary
    assert decision.deployment_risk in ("LOW", "MEDIUM", "HIGH")
    assert decision.provider == "deterministic_fallback"
    assert decision.ai_enriched is False
    assert "test suite" in decision.verification_guidance.lower()
