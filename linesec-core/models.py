import uuid
from datetime import datetime, timezone
from sqlalchemy import (
    Column,
    String,
    Integer,
    Float,
    Text,
    DateTime,
    Boolean,
    ForeignKey,
    Index
)
from sqlalchemy.orm import relationship
from database import Base

def utc_now():
    return datetime.now(timezone.utc)

class Repository(Base):
    __tablename__ = "repositories"

    repository_id = Column(String, primary_key=True, index=True, default=lambda: str(uuid.uuid4()))
    name = Column(String, unique=True, index=True)
    url = Column(String, nullable=True)
    default_branch = Column(String, default="main")
    environment = Column(String, default="production")  # production, staging, development
    criticality = Column(String, default="MEDIUM")       # CRITICAL, HIGH, MEDIUM, LOW
    internet_exposed = Column(Boolean, default=False)
    owner = Column(String, nullable=True)
    created_at = Column(DateTime, default=utc_now)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now)

    # Relationships
    scans = relationship("Scan", back_populates="repository", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="repository", cascade="all, delete-orphan")
    tasks = relationship("RemediationTask", back_populates="repository", cascade="all, delete-orphan")


class Scan(Base):
    __tablename__ = "scans"

    scan_id = Column(String, primary_key=True, index=True, default=lambda: str(uuid.uuid4()))
    repository_id = Column(String, ForeignKey("repositories.repository_id"), index=True, default="default")
    scanner = Column(String, index=True)
    scanner_type = Column(String, default="SAST")  # SAST, SCA, CONTAINER, SECRET, DAST
    commit_sha = Column(String, nullable=True)
    branch = Column(String, default="main")
    status = Column(String, default="COMPLETED")   # CREATED, RUNNING, COMPLETED, FAILED, PARTIAL
    total_findings = Column(Integer, default=0)
    new_findings = Column(Integer, default=0)
    resolved_findings = Column(Integer, default=0)
    regressed_findings = Column(Integer, default=0)
    started_at = Column(DateTime, default=utc_now)
    completed_at = Column(DateTime, default=utc_now)
    created_at = Column(DateTime, default=utc_now)

    # Relationships
    repository = relationship("Repository", back_populates="scans")
    findings = relationship("Finding", back_populates="scan")


class Finding(Base):
    __tablename__ = "findings"

    # Primary key
    finding_id = Column(String, primary_key=True, index=True, default=lambda: str(uuid.uuid4()))
    
    # Deterministic Identity
    fingerprint = Column(String(64), index=True, nullable=True)
    
    # Context & Provenance
    repository_id = Column(String, ForeignKey("repositories.repository_id"), index=True, default="default")
    scan_id = Column(String, ForeignKey("scans.scan_id"), nullable=True, index=True)
    branch = Column(String, default="main")
    commit_sha = Column(String, nullable=True)
    
    # Scanner Data
    tool_name = Column(String, index=True, default="bandit")
    scanner = Column(String, index=True, nullable=True)
    scanner_type = Column(String, default="SAST")  # SAST, SCA, CONTAINER, SECRET, DAST
    
    # Vulnerability Identity
    vulnerability_name = Column(String, index=True)
    title = Column(String, nullable=True)
    cve = Column(String, index=True, nullable=True)
    cwe = Column(String, nullable=True)
    severity = Column(String, default="MEDIUM")  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    description = Column(Text, nullable=True)
    references = Column(Text, nullable=True)
    
    # Location
    file_path = Column(String, nullable=True)
    line_number = Column(Integer, nullable=True)
    
    # Package & Dependency Context (SCA)
    package = Column(String, nullable=True)
    ecosystem = Column(String, nullable=True)
    installed_version = Column(String, nullable=True)
    fixed_version = Column(String, nullable=True)
    
    # Lifecycle & Status
    remediation_status = Column(String, default="NEW", index=True)  # Legacy & canonical sync
    status = Column(String, default="NEW", index=True)
    
    # Risk & Prioritization
    risk_score = Column(Float, nullable=True)  # 0.0 - 100.0 explainable risk score
    priority = Column(String, nullable=True)    # P0, P1, P2, P3
    environment = Column(String, default="development")
    asset_id = Column(String, nullable=True)
    service_id = Column(String, nullable=True)
    
    # Grouping
    task_id = Column(String, ForeignKey("remediation_tasks.task_id"), nullable=True, index=True)
    
    # AI Enrichment & Legacy fields
    root_cause = Column(Text, nullable=True)
    remediation_plan = Column(Text, nullable=True)
    
    # Timestamps
    first_seen = Column(DateTime, default=utc_now)
    last_seen = Column(DateTime, default=utc_now, onupdate=utc_now)
    created_at = Column(DateTime, default=utc_now)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now)

    # Relationships
    task = relationship("RemediationTask", back_populates="findings")
    repository = relationship("Repository", back_populates="findings")
    scan = relationship("Scan", back_populates="findings")

    # Composite Indexes
    __table_args__ = (
        Index("ix_findings_fingerprint_repo", "fingerprint", "repository_id"),
        Index("ix_findings_status_severity", "status", "severity"),
    )


class RemediationTask(Base):
    __tablename__ = "remediation_tasks"

    task_id = Column(String, primary_key=True, index=True, default=lambda: str(uuid.uuid4()))
    repository_id = Column(String, ForeignKey("repositories.repository_id"), nullable=True, index=True)
    title = Column(String, index=True)
    package = Column(String, nullable=True)
    ecosystem = Column(String, nullable=True)
    action = Column(String, default="upgrade")  # upgrade, code_patch, config_change, manual
    target_version = Column(String, nullable=True)
    status = Column(String, default="PENDING", index=True)  # PENDING, ANALYZED, IN_PROGRESS, PR_OPENED, VERIFIED, RESOLVED, FAILED
    priority = Column(String, default="P2")     # P0, P1, P2, P3
    risk_score = Column(Float, nullable=True)
    safety_level = Column(String, default="SAFE")  # SAFE, APPROVAL_REQUIRED, MANUAL, BLOCKED
    created_at = Column(DateTime, default=utc_now)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now)

    # Relationships
    findings = relationship("Finding", back_populates="task")
    decision = relationship("TaskDecision", uselist=False, back_populates="task", cascade="all, delete-orphan")
    fix_plan = relationship("FixPlan", uselist=False, back_populates="task", cascade="all, delete-orphan")
    repository = relationship("Repository", back_populates="tasks")

    __table_args__ = (
        Index("ix_tasks_status_priority", "status", "priority"),
    )


class TaskDecision(Base):
    __tablename__ = "task_decisions"

    decision_id = Column(String, primary_key=True, index=True, default=lambda: str(uuid.uuid4()))
    task_id = Column(String, ForeignKey("remediation_tasks.task_id"), index=True, unique=True)
    priority = Column(String, default="P2")
    confidence = Column(Float, default=1.0)
    summary = Column(Text)
    business_impact = Column(Text, nullable=True)
    recommended_action = Column(Text)
    estimated_effort = Column(String, default="1 hour")
    deployment_risk = Column(String, default="LOW")
    reasoning = Column(Text, nullable=True)
    verification_guidance = Column(Text, nullable=True)
    ai_enriched = Column(Boolean, default=False)
    provider = Column(String, default="deterministic_fallback")
    model = Column(String, nullable=True)
    created_at = Column(DateTime, default=utc_now)

    task = relationship("RemediationTask", back_populates="decision")


class FixPlan(Base):
    __tablename__ = "fix_plans"

    plan_id = Column(String, primary_key=True, index=True, default=lambda: str(uuid.uuid4()))
    task_id = Column(String, ForeignKey("remediation_tasks.task_id"), index=True, unique=True)
    ecosystem = Column(String, default="generic")
    package = Column(String)
    current_version = Column(String, nullable=True)
    target_version = Column(String)
    action = Column(String, default="upgrade")
    safety_level = Column(String, default="SAFE")
    reason = Column(Text, nullable=True)
    verification_steps = Column(Text, nullable=True)
    created_at = Column(DateTime, default=utc_now)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now)

    task = relationship("RemediationTask", back_populates="fix_plan")


class Policy(Base):
    __tablename__ = "policies"

    policy_id = Column(String, primary_key=True, index=True, default=lambda: str(uuid.uuid4()))
    name = Column(String, unique=True, index=True)
    description = Column(Text, nullable=True)
    rules_json = Column(Text)  # Serialized rule specification
    action = Column(String, default="BLOCK")  # PASS, WARN, BLOCK
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=utc_now)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now)


class AuditEvent(Base):
    __tablename__ = "audit_events"

    event_id = Column(String, primary_key=True, index=True, default=lambda: str(uuid.uuid4()))
    event_type = Column(String, index=True)  # FINDINGS_INGESTED, RISK_CALCULATED, POLICY_EVALUATED, TASK_VERIFIED, etc.
    entity_type = Column(String, index=True) # finding, task, policy, repo
    entity_id = Column(String, index=True)
    actor = Column(String, default="linesec-engine")
    action = Column(String)
    details_json = Column(Text, nullable=True)
    created_at = Column(DateTime, default=utc_now)


class RiskAcceptance(Base):
    __tablename__ = "risk_acceptances"

    acceptance_id = Column(String, primary_key=True, index=True, default=lambda: str(uuid.uuid4()))
    finding_id = Column(String, index=True, nullable=True)
    task_id = Column(String, index=True, nullable=True)
    reason = Column(Text)
    owner = Column(String)
    expires_at = Column(DateTime, nullable=False)
    status = Column(String, default="ACTIVE")  # ACTIVE, EXPIRED, REVOKED
    created_at = Column(DateTime, default=utc_now)


class VulnerabilityIntel(Base):
    __tablename__ = "vulnerability_intel"

    intel_id = Column(String, primary_key=True, index=True, default=lambda: str(uuid.uuid4()))
    cve_id = Column(String, index=True, nullable=True)
    package = Column(String, index=True, nullable=True)
    ecosystem = Column(String, nullable=True)
    epss_score = Column(Float, nullable=True)
    epss_percentile = Column(Float, nullable=True)
    cisa_kev = Column(Boolean, default=False)
    cvss_score = Column(Float, nullable=True)
    cvss_vector = Column(String, nullable=True)
    data_json = Column(Text, nullable=True)
    cached_at = Column(DateTime, default=utc_now)
    expires_at = Column(DateTime, nullable=False)
