import requests
from typing import Dict, Any
from intel.base import IntelligenceProvider

class EPSSProvider(IntelligenceProvider):
    """
    Queries FIRST.org Exploit Prediction Scoring System (EPSS) API.
    Provides real-time probability (0.0 to 1.0) and percentile of weaponization.
    """
    
    @property
    def name(self) -> str:
        return "epss"

    def query(self, cve_id: str, timeout: int = 3) -> Dict[str, Any]:
        cve = cve_id.strip().upper()
        if not cve.startswith("CVE-"):
            return {"epss_score": 0.0, "epss_percentile": 0.0, "source": "invalid_cve"}

        cached = self.get_cached(cve)
        if cached:
            return cached

        default_result = {"epss_score": 0.01, "epss_percentile": 0.10, "source": "fallback"}

        try:
            url = f"https://api.first.org/data/v1/epss?cve={cve}"
            response = requests.get(url, timeout=timeout)
            if response.status_code == 200:
                payload = response.json()
                data_list = payload.get("data", [])
                if data_list:
                    item = data_list[0]
                    result = {
                        "epss_score": float(item.get("epss", 0.0)),
                        "epss_percentile": float(item.get("percentile", 0.0)),
                        "source": "live_epss_api"
                    }
                    self.set_cached(cve, result)
                    return result
        except Exception:
            # Graceful offline degradation
            pass

        return default_result
