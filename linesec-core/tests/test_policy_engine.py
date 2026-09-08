import pytest
from core.context import RepositoryContext
from core.policy import PolicyEngine
import schemas

def test_policy_engine_pass():
    """Verify low-risk development findings pass policy."""
    findings = [
        schemas.FindingResponse(
            finding_id="f-1",
            tool_name="bandit",
            vulnerability_name="B101",
            severity="LOW",
            priority="P3",
            remediation_status="NEW"
        )
    ]
    ctx = RepositoryContext(environment="development")
    res = PolicyEngine.evaluate(findings=findings, context=ctx)
    assert res.action == "PASS"
    assert len(res.matched_rules) == 0

def test_policy_engine_block_on_p0_production():
    """Verify P0 finding in production blocks CI/CD deployment."""
    findings = [
        schemas.FindingResponse(
            finding_id="f-1",
            tool_name="trivy",
            vulnerability_name="CVE-2021-44228",
            severity="CRITICAL",
            priority="P0",
            remediation_status="NEW"
        )
    ]
    ctx = RepositoryContext(environment="production")
    res = PolicyEngine.evaluate(findings=findings, context=ctx)
    assert res.action == "BLOCK"
    assert "block-p0-production" in res.matched_rules

def test_policy_engine_warn_on_high_severity():
    """Verify HIGH severity in development issues a WARN action."""
    findings = [
        schemas.FindingResponse(
            finding_id="f-1",
            tool_name="bandit",
            vulnerability_name="B301",
            severity="HIGH",
            priority="P2",
            remediation_status="NEW"
        )
    ]
    ctx = RepositoryContext(environment="development")
    res = PolicyEngine.evaluate(findings=findings, context=ctx)
    assert res.action == "WARN"
