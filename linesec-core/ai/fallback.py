from typing import List, Any
from ai.base import AIAnalysisProvider, TaskDecisionData

class DeterministicFallbackProvider(AIAnalysisProvider):
    """
    Deterministic rule-based reasoning engine used as a resilient fallback
    when LLM services (Gemini / Ollama) are offline, rate-limited, or unconfigured.
    """

    @property
    def name(self) -> str:
        return "deterministic_fallback"

    def is_available(self) -> bool:
        return True

    def analyze_task(
        self,
        task: Any,
        findings: List[Any],
        environment: str = "development",
        criticality: str = "MEDIUM"
    ) -> TaskDecisionData:
        pkg = getattr(task, "package", None) or "target component"
        target_ver = getattr(task, "target_version", None) or "latest secure patch"
        action = getattr(task, "action", "upgrade")
        priority = getattr(task, "priority", "P2")

        cve_list = [f.cve for f in findings if getattr(f, "cve", None)]
        cve_str = ", ".join(cve_list[:3]) if cve_list else "reported security issues"

        if action == "upgrade":
            summary = f"Automated dependency upgrade for package '{pkg}' to version '{target_ver}' resolving {len(findings)} CVEs ({cve_str})."
            root_cause = f"Outdated or vulnerable dependency version of '{pkg}' contains known published vulnerabilities ({cve_str})."
            business_impact = f"Potential risk of unauthorized data access, execution of untrusted logic, or service degradation in {environment} environment."
            recommended_action = f"Upgrade '{pkg}' to '{target_ver}' or higher across repository lockfiles and requirements specifications."
            estimated_effort = "30 minutes"
            deployment_risk = "LOW" if priority in ("P2", "P3") else "MEDIUM"
            reasoning = f"Deterministic analysis determined upgrade to {target_ver} is the optimal path with minimal breaking changes."
            verification_guidance = f"Run local test suite (`pytest` / `npm test`), re-run vulnerability scanner (`trivy` / `bandit`), and verify zero remaining findings for {pkg}."
        else:
            summary = f"Code-level remediation required for {len(findings)} static analysis findings."
            root_cause = "Static analysis identified insecure coding patterns or dangerous function calls in source files."
            business_impact = f"Possible software reliability or security flaw exposed in {environment}."
            recommended_action = "Review flagged source code lines, refactor vulnerable patterns, and implement input sanitization."
            estimated_effort = "1 hour"
            deployment_risk = "LOW"
            reasoning = "Deterministic analysis recommends code-level refactoring of flagged static analysis rules."
            verification_guidance = "Run SAST scanner (`bandit`) against modified source files to confirm vulnerability clearance."

        return TaskDecisionData(
            summary=summary,
            root_cause=root_cause,
            business_impact=business_impact,
            recommended_action=recommended_action,
            estimated_effort=estimated_effort,
            deployment_risk=deployment_risk,
            reasoning=reasoning,
            verification_guidance=verification_guidance,
            priority=priority,
            confidence=1.0,
            provider=self.name,
            model="deterministic-rules-v2",
            ai_enriched=False
        )
