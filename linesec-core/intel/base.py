from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
from datetime import datetime, timezone, timedelta

def utc_now():
    return datetime.now(timezone.utc)

class IntelligenceProvider(ABC):
    """
    Abstract Base Class for external vulnerability intelligence providers
    (e.g., EPSS, CISA KEV, OSV, NVD).
    
    Includes built-in timeout, offline fallback, and in-memory TTL caching.
    """
    
    def __init__(self, ttl_seconds: int = 86400):  # Default 24h cache
        self.ttl_seconds = ttl_seconds
        self._cache: Dict[str, Dict[str, Any]] = {}

    @property
    @abstractmethod
    def name(self) -> str:
        pass

    def get_cached(self, key: str) -> Optional[Dict[str, Any]]:
        cached = self._cache.get(key)
        if cached:
            expires_at = cached.get("expires_at")
            if expires_at and expires_at > utc_now():
                return cached.get("data")
        return None

    def set_cached(self, key: str, data: Dict[str, Any]):
        self._cache[key] = {
            "data": data,
            "expires_at": utc_now() + timedelta(seconds=self.ttl_seconds)
        }

    @abstractmethod
    def query(self, identifier: str, **kwargs) -> Dict[str, Any]:
        """Queries intelligence for a given CVE or package identifier."""
        pass
