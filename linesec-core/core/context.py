from dataclasses import dataclass
from typing import Optional

@dataclass
class RepositoryContext:
    repository_id: str = "default"
    environment: str = "development"       # production, staging, development, sandbox
    criticality: str = "MEDIUM"            # CRITICAL, HIGH, MEDIUM, LOW
    internet_exposed: bool = False
    data_sensitivity: str = "MEDIUM"       # HIGH (PII/PCI), MEDIUM, LOW
    deployment_frequency: str = "daily"    # daily, weekly, monthly

    @property
    def environment_multiplier(self) -> float:
        env = self.environment.lower()
        if env == "production":
            return 1.30
        elif env == "staging":
            return 1.15
        elif env == "development":
            return 1.00
        return 0.85  # sandbox / test

    @property
    def criticality_multiplier(self) -> float:
        crit = self.criticality.upper()
        if crit == "CRITICAL":
            return 1.25
        elif crit == "HIGH":
            return 1.10
        elif crit == "MEDIUM":
            return 1.00
        return 0.85  # LOW
