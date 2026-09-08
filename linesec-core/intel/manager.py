from typing import Dict, Any, Optional
from intel.epss import EPSSProvider
from intel.cisa_kev import CISAKEVProvider
from intel.osv import OSVProvider

class IntelligenceManager:
    """
    Coordinates modular intelligence providers to enrich findings with
    threat intelligence, active weaponization signals, and advisories.
    """
    
    def __init__(self):
        self.epss = EPSSProvider()
        self.cisa_kev = CISAKEVProvider()
        self.osv = OSVProvider()

    def enrich_finding(
        self,
        cve_id: Optional[str] = None,
        package: Optional[str] = None,
        ecosystem: Optional[str] = None
    ) -> Dict[str, Any]:
        intel: Dict[str, Any] = {
            "epss_score": 0.0,
            "epss_percentile": 0.0,
            "cisa_kev": False,
            "osv_summary": None,
            "aliases": []
        }

        if cve_id and cve_id.upper().startswith("CVE-"):
            # 1. Query EPSS
            epss_res = self.epss.query(cve_id)
            intel["epss_score"] = epss_res.get("epss_score", 0.0)
            intel["epss_percentile"] = epss_res.get("epss_percentile", 0.0)

            # 2. Query CISA KEV
            kev_res = self.cisa_kev.query(cve_id)
            intel["cisa_kev"] = kev_res.get("cisa_kev", False)

            # 3. Query OSV
            osv_res = self.osv.query(cve_id, ecosystem=ecosystem)
            intel["osv_summary"] = osv_res.get("summary")
            intel["aliases"] = osv_res.get("aliases", [])

        return intel
