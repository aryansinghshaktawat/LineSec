from pydantic import BaseModel, ConfigDict
from typing import Optional, List, Dict, Any
from datetime import datetime

# ==========================================
# Canonical Finding Schemas (Backward Compatible)
# ==========================================

class FindingCreate(BaseModel):
    tool_name: str = "bandit"
    vulnerability_name: str
    severity: str = "MEDIUM"
    description: Optional[str] = ""
    file_path: Optional[str] = ""
    line_number: Optional[int] = 0
    
    # Extended Canonical Fields
    repository_id: Optional[str] = None
    scanner: Optional[str] = None
    scanner_type: Optional[str] = "SAST"
    cve: Optional[str] = None
    cwe: Optional[str] = None
    package: Optional[str] = None
    ecosystem: Optional[str] = None
    installed_version: Optional[str] = None
    fixed_version: Optional[str] = None
    environment: Optional[str] = "development"

class FindingResponse(FindingCreate):
    model_config = ConfigDict(from_attributes=True)

    finding_id: str
    fingerprint: Optional[str] = None
    root_cause: Optional[str] = None
    remediation_plan: Optional[str] = None
    remediation_status: str = "NEW"
    status: Optional[str] = "NEW"
    risk_score: Optional[float] = None
    priority: Optional[str] = None
    task_id: Optional[str] = None
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None


# ==========================================
# Ingestion & Scanner Schemas
# ==========================================

class IngestBatchRequest(BaseModel):
    repository_id: str = "default"
    scanner: str
    scanner_type: str = "SAST"
    branch: str = "main"
    commit_sha: Optional[str] = None
    findings: List[FindingCreate]

class IngestBatchResponse(BaseModel):
    repository_id: str
    scanner: str
    total_received: int
    new_findings: int
    existing_findings: int
    regressed_findings: int
    findings: List[FindingResponse]


# ==========================================
# Remediation Task Schemas
# ==========================================

class TaskDecisionResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    decision_id: str
    task_id: str
    priority: str
    confidence: float
    summary: str
    business_impact: Optional[str] = None
    recommended_action: str
    estimated_effort: str
    deployment_risk: str
    reasoning: Optional[str] = None
    verification_guidance: Optional[str] = None
    ai_enriched: bool
    provider: str

class FixPlanResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    plan_id: str
    task_id: str
    ecosystem: str
    package: str
    current_version: Optional[str] = None
    target_version: str
    action: str
    safety_level: str
    reason: Optional[str] = None
    verification_steps: Optional[str] = None

class RemediationTaskResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    task_id: str
    title: str
    package: Optional[str] = None
    ecosystem: Optional[str] = None
    action: str
    target_version: Optional[str] = None
    status: str
    priority: str
    risk_score: Optional[float] = None
    safety_level: str
    findings_count: int = 0
    decision: Optional[TaskDecisionResponse] = None
    fix_plan: Optional[FixPlanResponse] = None


# ==========================================
# Policy & Posture Schemas
# ==========================================

class PolicyRule(BaseModel):
    name: str
    condition: Dict[str, Any]
    action: str  # PASS, WARN, BLOCK

class PolicyEvaluationResponse(BaseModel):
    policy_name: str
    action: str  # PASS, WARN, BLOCK
    matched_rules: List[str]
    reasons: List[str]

class PostureSummaryResponse(BaseModel):
    total_findings: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    security_score: float  # 0 - 100
    security_debt_hours: float
    remediation_progress_percent: float
    regressions_count: int


# ==========================================
# Phase 6: Verification & Diff Schemas
# ==========================================

class SecurityDiffItem(BaseModel):
    fingerprint: str
    vulnerability_name: str
    severity: str
    file_path: Optional[str] = None
    package: Optional[str] = None
    cve: Optional[str] = None
    diff_status: str  # RESOLVED, NEW, UNCHANGED, REGRESSED

class SecurityDiffResponse(BaseModel):
    total_base: int
    total_rescan: int
    resolved_count: int
    unchanged_count: int
    new_count: int
    regressed_count: int
    resolved_findings: List[SecurityDiffItem]
    unchanged_findings: List[SecurityDiffItem]
    new_findings: List[SecurityDiffItem]
    regressed_findings: List[SecurityDiffItem]
    verdict: str  # PASSED, FAILED

class TaskVerificationRequest(BaseModel):
    rescan_findings: Optional[List[FindingCreate]] = None

class TaskVerificationResponse(BaseModel):
    task_id: str
    target_version: Optional[str] = None
    initial_findings_count: int
    resolved_count: int
    remaining_count: int
    new_count: int
    status: str
    verified: bool
    summary: str
    timestamp: datetime


# ==========================================
# Phase 7: SLA & Risk Acceptance Schemas
# ==========================================

class RiskAcceptanceCreate(BaseModel):
    reason: str
    owner: str
    expires_at: datetime
    finding_id: Optional[str] = None
    task_id: Optional[str] = None

class RiskAcceptanceResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    acceptance_id: str
    finding_id: Optional[str] = None
    task_id: Optional[str] = None
    reason: str
    owner: str
    expires_at: datetime
    status: str
    created_at: datetime

class SLAPriorityStats(BaseModel):
    total: int
    breached: int
    approaching: int
    on_track: int

class SLAReportResponse(BaseModel):
    active_tasks_count: int
    breached_tasks_count: int
    approaching_breach_count: int
    on_track_tasks_count: int
    waived_items_count: int
    mttr_hours: float
    priority_breakdown: Dict[str, SLAPriorityStats]


