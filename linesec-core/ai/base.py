from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional, List, Any

@dataclass
class TaskDecisionData:
    summary: str
    root_cause: str
    business_impact: str
    recommended_action: str
    estimated_effort: str
    deployment_risk: str
    reasoning: str
    verification_guidance: str
    priority: str
    confidence: float
    provider: str
    model: Optional[str]
    ai_enriched: bool

class AIAnalysisProvider(ABC):
    @property
    @abstractmethod
    def name(self) -> str:
        pass

    @abstractmethod
    def is_available(self) -> bool:
        """Checks if the provider is configured and reachable."""
        pass

    @abstractmethod
    def analyze_task(
        self,
        task: Any,
        findings: List[Any],
        environment: str = "development",
        criticality: str = "MEDIUM"
    ) -> TaskDecisionData:
        pass
