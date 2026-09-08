import pytest
from core.context import RepositoryContext
from core.risk import RiskEngine

def test_deterministic_risk_calculation_baseline():
    """Verify standard MEDIUM vulnerability in development scores normally."""
    ctx = RepositoryContext(environment="development", criticality="MEDIUM", internet_exposed=False)
    res = RiskEngine.calculate_risk(severity="MEDIUM", context=ctx)
    assert 25.0 <= res.risk_score <= 45.0
    assert res.priority in ("P2", "P3")
    assert len(res.reasons) >= 1

def test_deterministic_risk_calculation_high_exploit_production():
    """
    Verify CRITICAL vulnerability + CISA KEV active exploitation + Internet Exposed + Production
    scores at or near 100.0 and assigns P0 priority.
    """
    ctx = RepositoryContext(
        environment="production",
        criticality="CRITICAL",
        internet_exposed=True,
        data_sensitivity="HIGH"
    )
    res = RiskEngine.calculate_risk(
        severity="CRITICAL",
        cve_id="CVE-2021-44228",
        epss_score=0.95,
        cisa_kev=True,
        fixed_version="2.17.1",
        context=ctx
    )
    assert res.risk_score >= 90.0
    assert res.priority == "P0"
    assert any("CISA KEV" in r for r in res.reasons)
    assert any("Internet-exposed" in r for r in res.reasons)
    assert any("Environment multiplier" in r for r in res.reasons)

def test_risk_score_determinism():
    """Verify exact identical inputs yield identical risk score output."""
    ctx = RepositoryContext(environment="staging", criticality="HIGH", internet_exposed=True)
    res1 = RiskEngine.calculate_risk(severity="HIGH", epss_score=0.30, context=ctx)
    res2 = RiskEngine.calculate_risk(severity="HIGH", epss_score=0.30, context=ctx)
    assert res1.risk_score == res2.risk_score
    assert res1.priority == res2.priority
    assert res1.reasons == res2.reasons
