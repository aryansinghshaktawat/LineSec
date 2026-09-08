from typing import Optional

class SafetyLevel:
    SAFE = "SAFE"                       # Fully automatable (minor/patch upgrade, low risk)
    APPROVAL_REQUIRED = "APPROVAL_REQUIRED" # Major version upgrade or high severity
    MANUAL = "MANUAL"                   # Complex code refactoring / deprecated
    BLOCKED = "BLOCKED"                 # Unsafe to automate in current environment

class SafetyValidator:
    """
    Deterministic Safety Validation Engine.
    Classifies remediation actions into safety levels based on semantic versioning,
    severity, and deployment context.
    """

    @staticmethod
    def classify_safety(
        action: str,
        current_version: Optional[str] = None,
        target_version: Optional[str] = None,
        priority: str = "P2",
        deployment_risk: str = "LOW",
        environment: str = "development"
    ) -> str:
        if action != "upgrade":
            return SafetyLevel.MANUAL

        if not target_version or target_version == "latest-secure":
            return SafetyLevel.APPROVAL_REQUIRED

        # Version comparison for breaking change risk
        is_major_upgrade = False
        if current_version and target_version:
            curr_clean = current_version.lstrip("v").split(".")[0]
            tgt_clean = target_version.lstrip("v").split(".")[0]
            if curr_clean.isdigit() and tgt_clean.isdigit():
                if int(tgt_clean) > int(curr_clean):
                    is_major_upgrade = True

        # Major version upgrades always require explicit approval
        if is_major_upgrade:
            return SafetyLevel.APPROVAL_REQUIRED

        # High deployment risk requires approval
        if deployment_risk.upper() == "HIGH":
            return SafetyLevel.APPROVAL_REQUIRED

        # In production, P0 critical issues require approval if risk is non-low
        if environment.lower() == "production" and priority == "P0" and deployment_risk.upper() != "LOW":
            return SafetyLevel.APPROVAL_REQUIRED

        # Minor or patch version upgrade with low deployment risk is SAFE
        return SafetyLevel.SAFE
