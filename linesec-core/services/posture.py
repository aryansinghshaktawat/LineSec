import json
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List
from sqlalchemy.orm import Session
import models
import schemas
from core.sla import SLAManager
from core.lifecycle import FindingStatus, TaskStatus

def utc_now():
    return datetime.now(timezone.utc)

class PostureService:
    """
    Computes enterprise posture metrics, SLA compliance, and manages Risk Acceptance waivers.
    """

    @staticmethod
    def get_sla_report(db: Session, repository_id: str = "default") -> Dict[str, Any]:
        now = utc_now()

        # Active risk acceptances
        active_waivers = db.query(models.RiskAcceptance).filter(
            models.RiskAcceptance.status == "ACTIVE",
            models.RiskAcceptance.expires_at > now
        ).all()
        waived_task_ids = {w.task_id for w in active_waivers if w.task_id}
        waived_finding_ids = {w.finding_id for w in active_waivers if w.finding_id}

        # Tasks
        tasks = db.query(models.RemediationTask).all()
        
        sla_breakdown = {
            "P0": {"total": 0, "breached": 0, "approaching": 0, "on_track": 0},
            "P1": {"total": 0, "breached": 0, "approaching": 0, "on_track": 0},
            "P2": {"total": 0, "breached": 0, "approaching": 0, "on_track": 0},
            "P3": {"total": 0, "breached": 0, "approaching": 0, "on_track": 0},
        }

        active_tasks_count = 0
        breached_count = 0
        approaching_count = 0
        on_track_count = 0
        resolved_durations = []

        for t in tasks:
            priority = t.priority if t.priority in sla_breakdown else "P2"
            
            # If resolved, record MTTR
            if t.status in [TaskStatus.RESOLVED.value, TaskStatus.VERIFIED.value]:
                if t.created_at and t.updated_at:
                    c_at = t.created_at.replace(tzinfo=timezone.utc) if t.created_at.tzinfo is None else t.created_at
                    u_at = t.updated_at.replace(tzinfo=timezone.utc) if t.updated_at.tzinfo is None else t.updated_at
                    dur = max(0.0, (u_at - c_at).total_seconds() / 3600.0)
                    resolved_durations.append(dur)
                continue

            # Skip waived tasks
            if t.task_id in waived_task_ids:
                continue

            active_tasks_count += 1
            sla_info = SLAManager.calculate_sla_status(
                priority=priority,
                created_at=t.created_at or now,
                now=now
            )
            
            sla_breakdown[priority]["total"] += 1
            if sla_info["status"] == "BREACHED":
                sla_breakdown[priority]["breached"] += 1
                breached_count += 1
            elif sla_info["status"] == "APPROACHING_BREACH":
                sla_breakdown[priority]["approaching"] += 1
                approaching_count += 1
            else:
                sla_breakdown[priority]["on_track"] += 1
                on_track_count += 1

        mttr_hours = SLAManager.calculate_mttr(resolved_durations)

        return {
            "active_tasks_count": active_tasks_count,
            "breached_tasks_count": breached_count,
            "approaching_breach_count": approaching_count,
            "on_track_tasks_count": on_track_count,
            "waived_items_count": len(active_waivers),
            "mttr_hours": mttr_hours,
            "priority_breakdown": sla_breakdown
        }

    @staticmethod
    def create_risk_acceptance(
        db: Session,
        reason: str,
        owner: str,
        expires_at: datetime,
        finding_id: Optional[str] = None,
        task_id: Optional[str] = None
    ) -> models.RiskAcceptance:
        if not finding_id and not task_id:
            raise ValueError("Either finding_id or task_id must be provided for Risk Acceptance")

        waiver = models.RiskAcceptance(
            finding_id=finding_id,
            task_id=task_id,
            reason=reason,
            owner=owner,
            expires_at=expires_at,
            status="ACTIVE"
        )
        db.add(waiver)

        if finding_id:
            finding = db.query(models.Finding).filter(models.Finding.finding_id == finding_id).first()
            if finding:
                finding.status = FindingStatus.RISK_ACCEPTED.value

        audit = models.AuditEvent(
            event_type="RISK_ACCEPTANCE_GRANTED",
            entity_type="finding" if finding_id else "task",
            entity_id=finding_id or task_id,
            actor=owner,
            action="grant_risk_waiver",
            details_json=json.dumps({
                "reason": reason,
                "expires_at": expires_at.isoformat()
            })
        )
        db.add(audit)
        db.commit()
        db.refresh(waiver)
        return waiver
