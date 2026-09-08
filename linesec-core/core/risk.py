from dataclasses import dataclass
from typing import List, Dict, Any, Optional
from core.context import RepositoryContext

BASE_SEVERITY_SCORES = {
    "CRITICAL": 70.0,
    "HIGH": 50.0,
    "MEDIUM": 30.0,
    "LOW": 15.0,
    "INFO": 5.0
}

@dataclass
class RiskResult:
    risk_score: float         # 0.0 to 100.0
    priority: str             # P0, P1, P2, P3
    reasons: List[str]        # Step-by-step explainable justification

class RiskEngine:
    """
    Deterministic Risk Scoring Engine.
    
    Combines Base Scanner Severity, Exploitability Intelligence (EPSS, CISA KEV),
    Asset Exposure, Environment Multipliers, and Fix Availability into an
    explainable, testable, deterministic 0–100 risk score.
    """

    @staticmethod
    def calculate_risk(
        severity: str,
        cve_id: Optional[str] = None,
        epss_score: float = 0.0,
        cisa_kev: bool = False,
        fixed_version: Optional[str] = None,
        context: Optional[RepositoryContext] = None
    ) -> RiskResult:
        ctx = context or RepositoryContext()
        reasons: List[str] = []
        
        # 1. Base Severity
        sev_norm = (severity or "MEDIUM").upper()
        base_points = BASE_SEVERITY_SCORES.get(sev_norm, 30.0)
        reasons.append(f"+{base_points:.0f} Base severity ({sev_norm})")

        # 2. Exploitability (CISA KEV & EPSS)
        exploit_points = 0.0
        if cisa_kev:
            exploit_points += 25.0
            reasons.append("+25 Active in-the-wild exploitation detected (CISA KEV)")
        
        if epss_score >= 0.50:
            exploit_points += 15.0
            reasons.append(f"+15 High exploit probability (EPSS: {epss_score:.2f})")
        elif epss_score >= 0.10:
            exploit_points += 8.0
            reasons.append(f"+8 Moderate exploit probability (EPSS: {epss_score:.2f})")
        elif epss_score >= 0.05:
            exploit_points += 4.0
            reasons.append(f"+4 Minor exploit probability (EPSS: {epss_score:.2f})")

        # 3. Asset Exposure & Data Sensitivity
        exposure_points = 0.0
        if ctx.internet_exposed:
            exposure_points += 12.0
            reasons.append("+12 Internet-exposed asset")
        if ctx.data_sensitivity.upper() == "HIGH":
            exposure_points += 8.0
            reasons.append("+8 High data sensitivity (PII/Financial)")

        # 4. Fix Availability Urgency
        fix_points = 0.0
        if fixed_version:
            fix_points += 5.0
            reasons.append(f"+5 Immediate fix available ({fixed_version})")

        # Subtotal before multipliers
        subtotal = base_points + exploit_points + exposure_points + fix_points

        # 5. Environment & Criticality Multipliers
        env_mult = ctx.environment_multiplier
        if env_mult != 1.0:
            reasons.append(f"x{env_mult:.2f} Environment multiplier ({ctx.environment.lower()})")
        
        crit_mult = ctx.criticality_multiplier
        if crit_mult != 1.0:
            reasons.append(f"x{crit_mult:.2f} Asset criticality multiplier ({ctx.criticality.upper()})")

        total_multiplier = env_mult * crit_mult
        raw_score = subtotal * total_multiplier

        # 6. Clamp to 0.0 - 100.0
        final_score = min(100.0, max(0.0, round(raw_score, 1)))

        # 7. Priority Banding
        if final_score >= 85.0:
            priority = "P0"
        elif final_score >= 70.0:
            priority = "P1"
        elif final_score >= 40.0:
            priority = "P2"
        else:
            priority = "P3"

        return RiskResult(
            risk_score=final_score,
            priority=priority,
            reasons=reasons
        )
