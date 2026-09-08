from abc import ABC, abstractmethod
from typing import List, Dict, Any, Union
import schemas

class ScannerAdapter(ABC):
    """
    Abstract Base Class for all LineSec Scanner Adapters.
    
    Transforms heterogeneous, scanner-specific scan outputs into LineSec's
    canonical, normalized FindingCreate schema.
    """
    
    @property
    @abstractmethod
    def name(self) -> str:
        """Name of the security tool (e.g., 'bandit', 'trivy', 'sarif')."""
        pass

    @property
    @abstractmethod
    def scanner_type(self) -> str:
        """Type of scanner: SAST, SCA, CONTAINER, SECRET, DAST."""
        pass

    @abstractmethod
    def parse_raw(self, raw_data: Union[str, bytes, Dict[str, Any]]) -> List[schemas.FindingCreate]:
        """
        Parses raw scanner output and returns normalized FindingCreate objects.
        """
        pass
