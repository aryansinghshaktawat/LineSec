from contextlib import asynccontextmanager
from fastapi import FastAPI, Depends, Query, HTTPException, Body
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from typing import List, Optional, Dict, Any

import models
import schemas
from database import SessionLocal, engine, Base
from services.ingestion import IngestionService
from services.grouping import TaskGroupingEngine
from services.planner import RemediationPlanner
from adapters.bandit import BanditAdapter
from adapters.trivy import TrivyAdapter
from adapters.sarif import SARIFAdapter
from intel.manager import IntelligenceManager
from core.context import RepositoryContext
from core.risk import RiskEngine
from core.policy import PolicyEngine
from core.safety import SafetyValidator, SafetyLevel
from ai.service import AIAnalysisService

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Ensure all tables exist on startup
    Base.metadata.create_all(bind=engine)
    yield

app = FastAPI(
    title="LineSec 2+ Core API",
    description="Context-Aware DevSecOps Vulnerability Management & Automated Remediation Platform",
    version="2.0.0",
    lifespan=lifespan
)

# CORS Middleware (permitting dashboard integration)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Dependency for database session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ==========================================
# Legacy & Backward-Compatible Endpoints
# ==========================================

@app.get("/health")
def health_check():
    return {"database": "connected", "api": "healthy", "version": "2.0.0"}

@app.post("/api/ingest", response_model=List[schemas.FindingResponse])
def ingest_findings(findings: List[schemas.FindingCreate], db: Session = Depends(get_db)):
    processed, _ = IngestionService.ingest_findings(db, findings)
    return processed

@app.get("/api/findings", response_model=List[schemas.FindingResponse])
def get_findings(
    db: Session = Depends(get_db),
    status: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    scanner: Optional[str] = Query(None)
):
    query = db.query(models.Finding)
    if status:
        query = query.filter(
            (models.Finding.status == status.upper()) | 
            (models.Finding.remediation_status == status.upper())
        )
    if severity:
        query = query.filter(models.Finding.severity == severity.upper())
    if scanner:
        query = query.filter(
            (models.Finding.scanner == scanner.lower()) | 
            (models.Finding.tool_name == scanner.lower())
        )
    return query.order_by(models.Finding.created_at.desc()).all()


# ==========================================
# Phase 2: Scanner Adapters & SARIF
# ==========================================

@app.post("/api/v1/adapters/bandit/import", response_model=schemas.IngestBatchResponse)
def import_bandit_scan(
    raw_payload: Dict[str, Any] = Body(...),
    repository_id: str = Query("default"),
    db: Session = Depends(get_db)
):
    adapter = BanditAdapter()
    findings = adapter.parse_raw(raw_payload)
    processed, stats = IngestionService.ingest_findings(db, findings, repository_id=repository_id, scanner_override="bandit")
    return {
        "repository_id": repository_id,
        "scanner": "bandit",
        "total_received": stats["total_received"],
        "new_findings": stats["new"],
        "existing_findings": stats["existing"],
        "regressed_findings": stats["regressed"],
        "findings": processed
    }

@app.post("/api/v1/adapters/trivy/import", response_model=schemas.IngestBatchResponse)
def import_trivy_scan(
    raw_payload: Dict[str, Any] = Body(...),
    repository_id: str = Query("default"),
    db: Session = Depends(get_db)
):
    adapter = TrivyAdapter()
    findings = adapter.parse_raw(raw_payload)
    processed, stats = IngestionService.ingest_findings(db, findings, repository_id=repository_id, scanner_override="trivy")
    return {
        "repository_id": repository_id,
        "scanner": "trivy",
        "total_received": stats["total_received"],
        "new_findings": stats["new"],
        "existing_findings": stats["existing"],
        "regressed_findings": stats["regressed"],
        "findings": processed
    }

@app.post("/api/v1/adapters/sarif/import", response_model=schemas.IngestBatchResponse)
def import_sarif_scan(
    raw_sarif: Dict[str, Any] = Body(...),
    repository_id: str = Query("default"),
    db: Session = Depends(get_db)
):
    adapter = SARIFAdapter()
    findings = adapter.parse_raw(raw_sarif)
    processed, stats = IngestionService.ingest_findings(db, findings, repository_id=repository_id, scanner_override="sarif")
    return {
        "repository_id": repository_id,
        "scanner": "sarif",
        "total_received": stats["total_received"],
        "new_findings": stats["new"],
        "existing_findings": stats["existing"],
        "regressed_findings": stats["regressed"],
        "findings": processed
    }

@app.get("/api/v1/adapters/sarif/export")
def export_sarif(repository_id: str = "default", db: Session = Depends(get_db)):
    findings = db.query(models.Finding).filter(models.Finding.repository_id == repository_id).all()
    sarif_doc = SARIFAdapter.export_sarif(findings)
    return JSONResponse(content=sarif_doc)


# ==========================================
# Phase 2 & 4 & 5: Remediation Tasks, AI & FixPlans
# ==========================================

@app.post("/api/v1/tasks/group", response_model=List[schemas.RemediationTaskResponse])
def group_findings_into_tasks(repository_id: str = "default", db: Session = Depends(get_db)):
    tasks = TaskGroupingEngine.group_repository_findings(db, repository_id)
    response_items = []
    for t in tasks:
        t_dict = {
            "task_id": t.task_id,
            "title": t.title,
            "package": t.package,
            "ecosystem": t.ecosystem,
            "action": t.action,
            "target_version": t.target_version,
            "status": t.status,
            "priority": t.priority,
            "risk_score": t.risk_score,
            "safety_level": t.safety_level,
            "findings_count": len(t.findings)
        }
        response_items.append(t_dict)
    return response_items

@app.get("/api/v1/tasks", response_model=List[schemas.RemediationTaskResponse])
def get_remediation_tasks(status: Optional[str] = None, db: Session = Depends(get_db)):
    query = db.query(models.RemediationTask)
    if status:
        query = query.filter(models.RemediationTask.status == status.upper())
    tasks = query.order_by(models.RemediationTask.created_at.desc()).all()
    
    response_items = []
    for t in tasks:
        t_dict = {
            "task_id": t.task_id,
            "title": t.title,
            "package": t.package,
            "ecosystem": t.ecosystem,
            "action": t.action,
            "target_version": t.target_version,
            "status": t.status,
            "priority": t.priority,
            "risk_score": t.risk_score,
            "safety_level": t.safety_level,
            "findings_count": len(t.findings)
        }
        response_items.append(t_dict)
    return response_items

@app.get("/api/v1/tasks/{task_id}")
def get_task_detail(task_id: str, db: Session = Depends(get_db)):
    task = db.query(models.RemediationTask).filter(models.RemediationTask.task_id == task_id).first()
    if not task:
        raise HTTPException(status_code=404, detail="RemediationTask not found")
    
    return {
        "task_id": task.task_id,
        "title": task.title,
        "package": task.package,
        "ecosystem": task.ecosystem,
        "action": task.action,
        "target_version": task.target_version,
        "status": task.status,
        "priority": task.priority,
        "risk_score": task.risk_score,
        "safety_level": task.safety_level,
        "decision": task.decision,
        "fix_plan": task.fix_plan,
        "findings": [schemas.FindingResponse.model_validate(f) for f in task.findings]
    }

@app.post("/api/v1/tasks/{task_id}/analyze", response_model=schemas.TaskDecisionResponse)
def analyze_task_endpoint(
    task_id: str,
    environment: str = Query("development"),
    criticality: str = Query("MEDIUM"),
    db: Session = Depends(get_db)
):
    ai_service = AIAnalysisService()
    try:
        decision = ai_service.analyze_task(
            db=db,
            task_id=task_id,
            environment=environment,
            criticality=criticality
        )
        return decision
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

@app.post("/api/v1/tasks/{task_id}/plan", response_model=schemas.FixPlanResponse)
def create_task_fix_plan(
    task_id: str,
    environment: str = Query("development"),
    db: Session = Depends(get_db)
):
    """Generates a structured FixPlan with deterministic safety classification."""
    try:
        plan = RemediationPlanner.create_fix_plan(db=db, task_id=task_id, environment=environment)
        return plan
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

@app.post("/api/v1/tasks/{task_id}/remediate")
def remediate_task(
    task_id: str,
    dry_run: bool = Query(False),
    db: Session = Depends(get_db)
):
    """
    Executes automated remediation: generates FixPlan, evaluates safety,
    and returns branch, PR, and commit instructions.
    """
    task = db.query(models.RemediationTask).filter(models.RemediationTask.task_id == task_id).first()
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")

    plan = task.fix_plan or RemediationPlanner.create_fix_plan(db=db, task_id=task_id)
    
    branch_name = f"linesec/fix-{task.package or 'patch'}-{task.target_version or 'sec'}"
    pr_title = f"[LineSec Security Fix] {task.title}"

    findings = task.findings or []
    cve_list = [f.cve for f in findings if f.cve]

    pr_body = (
        f"## LineSec Automated Security Remediation\n\n"
        f"### 🛡️ Task Summary\n"
        f"- **Package:** `{task.package}`\n"
        f"- **Action:** `{task.action}`\n"
        f"- **Target Version:** `{task.target_version}`\n"
        f"- **Safety Classification:** `{plan.safety_level}`\n"
        f"- **Resolved Vulnerabilities:** {', '.join(cve_list) if cve_list else len(findings)}\n\n"
        f"### 🔍 Analysis & Root Cause\n"
        f"{task.decision.summary if task.decision else 'Automated security upgrade to resolve open vulnerabilities.'}\n\n"
        f"### 🧪 Verification Steps\n"
        f"{plan.verification_steps}\n"
    )

    if not dry_run:
        task.status = "PR_OPENED" if plan.safety_level == "SAFE" else "TICKET_OPENED"
        db.commit()

    return {
        "task_id": task_id,
        "action": plan.action,
        "safety_level": plan.safety_level,
        "branch_name": branch_name,
        "pr_title": pr_title,
        "pr_body": pr_body,
        "dry_run": dry_run,
        "status": task.status
    }


# ==========================================
# Phase 3: Vulnerability Intelligence, Risk & Policy
# ==========================================

@app.post("/api/v1/intel/enrich")
def enrich_repository_findings(
    repository_id: str = Query("default"),
    db: Session = Depends(get_db)
):
    findings = db.query(models.Finding).filter(
        models.Finding.repository_id == repository_id,
        models.Finding.cve.isnot(None)
    ).all()

    intel_mgr = IntelligenceManager()
    enriched_count = 0

    for f in findings:
        intel = intel_mgr.enrich_finding(cve_id=f.cve, package=f.package, ecosystem=f.ecosystem)
        existing_intel = db.query(models.VulnerabilityIntel).filter(models.VulnerabilityIntel.cve_id == f.cve).first()
        if not existing_intel:
            v_intel = models.VulnerabilityIntel(
                cve_id=f.cve,
                package=f.package,
                ecosystem=f.ecosystem,
                epss_score=intel.get("epss_score"),
                epss_percentile=intel.get("epss_percentile"),
                cisa_kev=intel.get("cisa_kev", False),
                expires_at=models.utc_now()
            )
            db.add(v_intel)
        enriched_count += 1

    db.commit()
    return {"repository_id": repository_id, "enriched_findings": enriched_count}

@app.post("/api/v1/risk/evaluate")
def evaluate_repository_risk(
    repository_id: str = Query("default"),
    environment: str = Query("development"),
    criticality: str = Query("MEDIUM"),
    internet_exposed: bool = Query(False),
    db: Session = Depends(get_db)
):
    findings = db.query(models.Finding).filter(models.Finding.repository_id == repository_id).all()
    context = RepositoryContext(
        repository_id=repository_id,
        environment=environment,
        criticality=criticality,
        internet_exposed=internet_exposed
    )

    results = []
    for f in findings:
        intel = db.query(models.VulnerabilityIntel).filter(models.VulnerabilityIntel.cve_id == f.cve).first() if f.cve else None
        epss = intel.epss_score if intel and intel.epss_score else 0.0
        cisa_kev = intel.cisa_kev if intel and intel.cisa_kev else False

        risk_calc = RiskEngine.calculate_risk(
            severity=f.severity,
            cve_id=f.cve,
            epss_score=epss,
            cisa_kev=cisa_kev,
            fixed_version=f.fixed_version,
            context=context
        )

        f.risk_score = risk_calc.risk_score
        f.priority = risk_calc.priority
        f.environment = environment

        results.append({
            "finding_id": f.finding_id,
            "vulnerability_name": f.vulnerability_name,
            "severity": f.severity,
            "risk_score": risk_calc.risk_score,
            "priority": risk_calc.priority,
            "reasons": risk_calc.reasons
        })

    db.commit()
    return {"repository_id": repository_id, "evaluated_findings": len(results), "findings": results}

@app.post("/api/v1/policy/evaluate", response_model=schemas.PolicyEvaluationResponse)
def evaluate_policy_gate(
    repository_id: str = Query("default"),
    environment: str = Query("development"),
    internet_exposed: bool = Query(False),
    db: Session = Depends(get_db)
):
    findings = db.query(models.Finding).filter(models.Finding.repository_id == repository_id).all()
    context = RepositoryContext(
        repository_id=repository_id,
        environment=environment,
        internet_exposed=internet_exposed
    )

    eval_result = PolicyEngine.evaluate(findings=findings, context=context)
    return {
        "policy_name": eval_result.policy_name,
        "action": eval_result.action,
        "matched_rules": eval_result.matched_rules,
        "reasons": eval_result.reasons
    }


# ==========================================
# Posture & Audit Endpoints
# ==========================================

@app.post("/api/v1/ingest/batch", response_model=schemas.IngestBatchResponse)
def ingest_batch(batch: schemas.IngestBatchRequest, db: Session = Depends(get_db)):
    processed, stats = IngestionService.ingest_findings(
        db=db,
        findings_in=batch.findings,
        repository_id=batch.repository_id,
        scanner_override=batch.scanner
    )
    return {
        "repository_id": batch.repository_id,
        "scanner": batch.scanner,
        "total_received": stats["total_received"],
        "new_findings": stats["new"],
        "existing_findings": stats["existing"],
        "regressed_findings": stats["regressed"],
        "findings": processed
    }

@app.get("/api/v1/posture", response_model=schemas.PostureSummaryResponse)
def get_posture_summary(repository_id: str = "default", db: Session = Depends(get_db)):
    findings = db.query(models.Finding).filter(models.Finding.repository_id == repository_id).all()
    total = len(findings)
    crit = sum(1 for f in findings if (f.severity or "").upper() == "CRITICAL")
    high = sum(1 for f in findings if (f.severity or "").upper() == "HIGH")
    med = sum(1 for f in findings if (f.severity or "").upper() == "MEDIUM")
    low = sum(1 for f in findings if (f.severity or "").upper() == "LOW")
    
    resolved = sum(1 for f in findings if (f.status or "").upper() in ("RESOLVED", "TICKET_OPENED"))
    regressed = sum(1 for f in findings if (f.status or "").upper() == "REGRESSED")
    
    penalty = (crit * 25) + (high * 10) + (med * 3) + (low * 1)
    security_score = max(0.0, round(100.0 - penalty, 1))
    debt_hours = (crit * 4.0) + (high * 2.0) + (med * 1.0) + (low * 0.5)
    progress = round((resolved / total * 100), 1) if total > 0 else 100.0

    return {
        "total_findings": total,
        "critical_count": crit,
        "high_count": high,
        "medium_count": med,
        "low_count": low,
        "security_score": security_score,
        "security_debt_hours": debt_hours,
        "remediation_progress_percent": progress,
        "regressions_count": regressed
    }

@app.get("/api/v1/audit")
def get_audit_events(limit: int = 50, db: Session = Depends(get_db)):
    return db.query(models.AuditEvent).order_by(models.AuditEvent.created_at.desc()).limit(limit).all()
