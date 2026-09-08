from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from core.context import RepositoryContext

@dataclass
class PolicyEvaluationResult:
    action: str                        # PASS, WARN, BLOCK
    policy_name: str = "default-security-gate"
    matched_rules: List[str] = field(default_factory=list)
    reasons: List[str] = field(default_factory=list)

class PolicyEngine:
    """
    Evaluates repository vulnerability posture against declarative security policies.
    Determines CI/CD gate actions: PASS, WARN, or BLOCK.
    """

    DEFAULT_POLICY = {
        "name": "default-enterprise-gate",
        "rules": [
            {
                "id": "block-p0-production",
                "name": "Block P0 Critical Findings in Production",
                "condition": {"priority": "P0", "environment": "production"},
                "action": "BLOCK",
                "reason": "Critical P0 vulnerability present in production environment"
            },
            {
                "id": "block-cisa-kev-internet",
                "name": "Block Weaponized CISA KEV on Internet-Exposed Assets",
                "condition": {"cisa_kev": True, "internet_exposed": True},
                "action": "BLOCK",
                "reason": "Active in-the-wild exploited CVE present on internet-exposed system"
            },
            {
                "id": "warn-p1-production",
                "name": "Warn on P1 High Priority in Production",
                "condition": {"priority": "P1", "environment": "production"},
                "action": "WARN",
                "reason": "High priority P1 vulnerability detected in production"
            },
            {
                "id": "warn-high-severity-open",
                "name": "Warn on Open High Severity",
                "condition": {"severity": "HIGH"},
                "action": "WARN",
                "reason": "Open HIGH severity security finding detected"
            }
        ]
    }

    @classmethod
    def evaluate(
        cls,
        findings: List[Any],
        context: Optional[RepositoryContext] = None,
        custom_policy: Optional[Dict[str, Any]] = None
    ) -> PolicyEvaluationResult:
        ctx = context or RepositoryContext()
        policy = custom_policy or cls.DEFAULT_POLICY
        policy_name = policy.get("name", "default-gate")
        rules = policy.get("rules", [])

        action = "PASS"
        matched_rules: List[str] = []
        reasons: List[str] = []

        for finding in findings:
            f_sev = (getattr(finding, "severity", "") or "").upper()
            f_prio = getattr(finding, "priority", None) or "P2"
            f_cisa = getattr(finding, "cisa_kev", False)

            for rule in rules:
                cond = rule.get("condition", {})
                rule_action = rule.get("action", "WARN")
                rule_id = rule.get("id", "rule")
                rule_reason = rule.get("reason", "Policy violation")

                match = True
                if "priority" in cond and cond["priority"] != f_prio:
                    match = False
                if "severity" in cond and cond["severity"] != f_sev:
                    match = False
                if "environment" in cond and cond["environment"].lower() != ctx.environment.lower():
                    match = False
                if "internet_exposed" in cond and cond["internet_exposed"] != ctx.internet_exposed:
                    match = False
                if "cisa_kev" in cond and cond["cisa_kev"] != f_cisa:
                    match = False

                if match:
                    if rule_id not in matched_rules:
                        matched_rules.append(rule_id)
                        reasons.append(f"[{rule_action}] {rule_reason}")

                    # Promote action level: PASS -> WARN -> BLOCK
                    if rule_action == "BLOCK":
                        action = "BLOCK"
                    elif rule_action == "WARN" and action != "BLOCK":
                        action = "WARN"

        return PolicyEvaluationResult(
            action=action,
            policy_name=policy_name,
            matched_rules=matched_rules,
            reasons=reasons
        )
