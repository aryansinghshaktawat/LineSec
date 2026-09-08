import requests
from typing import Dict, Any, Set
from intel.base import IntelligenceProvider

class CISAKEVProvider(IntelligenceProvider):
    """
    Queries CISA Known Exploited Vulnerabilities (KEV) Catalog.
    Identifies vulnerabilities actively exploited in the wild.
    """
    
    _kev_set: Set[str] = set()
    _catalog_loaded: bool = False

    @property
    def name(self) -> str:
        return "cisa_kev"

    def _ensure_catalog_loaded(self, timeout: int = 4):
        if self._catalog_loaded:
            return
        try:
            url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
            res = requests.get(url, timeout=timeout)
            if res.status_code == 200:
                data = res.json()
                vulns = data.get("vulnerabilities", [])
                for v in vulns:
                    cve = v.get("cveID")
                    if cve:
                        self._kev_set.add(cve.strip().upper())
                self._catalog_loaded = True
        except Exception:
            # If offline, use empty or cached set
            self._catalog_loaded = True

    def query(self, cve_id: str, timeout: int = 4) -> Dict[str, Any]:
        cve = cve_id.strip().upper()
        if not cve.startswith("CVE-"):
            return {"cisa_kev": False, "source": "invalid_cve"}

        cached = self.get_cached(cve)
        if cached:
            return cached

        self._ensure_catalog_loaded(timeout=timeout)
        is_kev = cve in self._kev_set
        result = {"cisa_kev": is_kev, "source": "cisa_kev_catalog"}
        self.set_cached(cve, result)
        return result
