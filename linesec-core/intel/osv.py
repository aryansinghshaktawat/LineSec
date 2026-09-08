import requests
from typing import Dict, Any, Optional
from intel.base import IntelligenceProvider

class OSVProvider(IntelligenceProvider):
    """
    Queries Google Open Source Vulnerabilities (OSV) API.
    Provides authoritative advisory, aliases, and fix data for package ecosystems.
    """

    @property
    def name(self) -> str:
        return "osv"

    def query(self, identifier: str, ecosystem: Optional[str] = None, timeout: int = 3) -> Dict[str, Any]:
        cache_key = f"{ecosystem or 'generic'}:{identifier}"
        cached = self.get_cached(cache_key)
        if cached:
            return cached

        default_result = {"osv_id": identifier, "aliases": [], "source": "fallback"}

        try:
            url = f"https://api.osv.dev/v1/vulns/{identifier}"
            res = requests.get(url, timeout=timeout)
            if res.status_code == 200:
                data = res.json()
                result = {
                    "osv_id": data.get("id", identifier),
                    "summary": data.get("summary", ""),
                    "details": data.get("details", ""),
                    "aliases": data.get("aliases", []),
                    "modified": data.get("modified"),
                    "source": "live_osv_api"
                }
                self.set_cached(cache_key, result)
                return result
        except Exception:
            pass

        return default_result
