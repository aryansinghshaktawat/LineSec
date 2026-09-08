import json
from typing import Optional, List
from sqlalchemy.orm import Session
from datetime import datetime, timezone

import models
from ai.base import TaskDecisionData
from ai.gemini import GeminiAIProvider
from ai.fallback import DeterministicFallbackProvider
from core.lifecycle import TaskStatus, FindingStatus

def utc_now():
    return datetime.now(timezone.utc)

class AIAnalysisService:
    """
    Orchestrates AI analysis with automatic fallback to deterministic reasoning.
    Persists structured TaskDecision entities and updates finding remediation fields.
    """

    def __init__(self):
        self.gemini = GeminiAIProvider()
        self.fallback = DeterministicFallbackProvider()

    def analyze_task(
        self,
        db: Session,
        task_id: str,
        environment: str = "development",
        criticality: str = "MEDIUM"
    ) -> models.TaskDecision:
        task = db.query(models.RemediationTask).filter(models.RemediationTask.task_id == task_id).first()
        if not task:
            raise ValueError(f"Task with ID {task_id} does not exist")

        findings = task.findings or []

        decision_data: TaskDecisionData
        # Try primary AI provider (Gemini)
        if self.gemini.is_available():
            try:
                decision_data = self.gemini.analyze_task(
                    task=task,
                    findings=findings,
                    environment=environment,
                    criticality=criticality
                )
            except Exception:
                # Automatic fallback on error or timeout
                decision_data = self.fallback.analyze_task(
                    task=task,
                    findings=findings,
                    environment=environment,
                    criticality=criticality
                )
        else:
            # Deterministic fallback
            decision_data = self.fallback.analyze_task(
                task=task,
                findings=findings,
                environment=environment,
                criticality=criticality
            )

        # Upsert TaskDecision in DB
        existing_decision = db.query(models.TaskDecision).filter(models.TaskDecision.task_id == task_id).first()
        if existing_decision:
            decision = existing_decision
            decision.summary = decision_data.summary
            decision.business_impact = decision_data.business_impact
            decision.recommended_action = decision_data.recommended_action
            decision.estimated_effort = decision_data.estimated_effort
            decision.deployment_risk = decision_data.deployment_risk
            decision.reasoning = decision_data.reasoning
            decision.verification_guidance = decision_data.verification_guidance
            decision.ai_enriched = decision_data.ai_enriched
            decision.provider = decision_data.provider
            decision.model = decision_data.model
        else:
            decision = models.TaskDecision(
                task_id=task_id,
                priority=decision_data.priority,
                confidence=decision_data.confidence,
                summary=decision_data.summary,
                business_impact=decision_data.business_impact,
                recommended_action=decision_data.recommended_action,
                estimated_effort=decision_data.estimated_effort,
                deployment_risk=decision_data.deployment_risk,
                reasoning=decision_data.reasoning,
                verification_guidance=decision_data.verification_guidance,
                ai_enriched=decision_data.ai_enriched,
                provider=decision_data.provider,
                model=decision_data.model
            )
            db.add(decision)

        # Update Task status
        task.status = TaskStatus.ANALYZED.value
        task.updated_at = utc_now()

        # Update linked findings for backward compatibility
        for f in findings:
            f.root_cause = decision_data.root_cause
            f.remediation_plan = decision_data.recommended_action
            if f.status in ("NEW", "TRIAGED"):
                f.status = FindingStatus.ANALYZED.value
                f.remediation_status = FindingStatus.ANALYZED.value

        # Audit Event
        audit = models.AuditEvent(
            event_type="TASK_ANALYZED",
            entity_type="remediation_task",
            entity_id=task_id,
            actor="linesec-ai-service",
            action="generate_task_decision",
            details_json=json.dumps({
                "provider": decision_data.provider,
                "ai_enriched": decision_data.ai_enriched,
                "deployment_risk": decision_data.deployment_risk
            })
        )
        db.add(audit)

        db.commit()
        db.refresh(decision)
        return decision
