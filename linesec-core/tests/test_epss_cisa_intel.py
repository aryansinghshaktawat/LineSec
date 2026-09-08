import pytest
from intel.epss import EPSSProvider
from intel.cisa_kev import CISAKEVProvider
from intel.manager import IntelligenceManager

def test_epss_provider_cache():
    provider = EPSSProvider(ttl_seconds=3600)
    # Mock pre-cached response
    provider.set_cached("CVE-2021-44228", {"epss_score": 0.97, "epss_percentile": 0.99, "source": "cached"})
    
    res = provider.query("CVE-2021-44228")
    assert res["epss_score"] == 0.97
    assert res["epss_percentile"] == 0.99
    assert res["source"] == "cached"

def test_cisa_kev_provider_lookup():
    provider = CISAKEVProvider(ttl_seconds=3600)
    provider.set_cached("CVE-2021-44228", {"cisa_kev": True, "source": "cached"})
    
    res = provider.query("CVE-2021-44228")
    assert res["cisa_kev"] is True

def test_intel_manager_enrichment():
    mgr = IntelligenceManager()
    mgr.epss.set_cached("CVE-2023-32681", {"epss_score": 0.85, "epss_percentile": 0.95, "source": "cached"})
    mgr.cisa_kev.set_cached("CVE-2023-32681", {"cisa_kev": True, "source": "cached"})

    intel = mgr.enrich_finding(cve_id="CVE-2023-32681", package="requests", ecosystem="pip")
    assert intel["epss_score"] == 0.85
    assert intel["cisa_kev"] is True
