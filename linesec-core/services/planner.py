import json
from typing import Optional, List
from sqlalchemy.orm import Session
from datetime import datetime, timezone
import models
from core.safety import SafetyValidator

def utc_now():
    return datetime.now(timezone.utc)

class RemediationPlanner:
    """
    Constructs concrete, structured FixPlans for RemediationTasks.
    Determines semantic upgrade paths, safety classifications, and verification recipes.
    """

    @staticmethod
    def create_fix_plan(
        db: Session,
        task_id: str,
        environment: str = "development"
    ) -> models.FixPlan:
        task = db.query(models.RemediationTask).filter(models.RemediationTask.task_id == task_id).first()
        if not task:
            raise ValueError(f"Task with ID {task_id} not found")

        findings = task.findings or []
        package = task.package or "source_code"
        ecosystem = task.ecosystem or "generic"
        action = task.action or "upgrade"

        # Determine current installed version from findings if available
        installed_versions = [f.installed_version for f in findings if f.installed_version]
        current_version = installed_versions[0] if installed_versions else None
        target_version = task.target_version or "latest-secure"

        # Check deployment risk from decision if available
        decision = task.decision
        deployment_risk = decision.deployment_risk if decision else "LOW"

        # Classify Safety Level
        safety_level = SafetyValidator.classify_safety(
            action=action,
            current_version=current_version,
            target_version=target_version,
            priority=task.priority,
            deployment_risk=deployment_risk,
            environment=environment
        )

        task.safety_level = safety_level

        # Reason & Verification steps
        cve_list = [f.cve for f in findings if f.cve]
        reason = f"Automated remediation plan to resolve {len(findings)} findings ({', '.join(cve_list[:3])}) by upgrading {package} from {current_version or 'unpinned'} to {target_version}."
        
        verification_steps = (
            f"1. Apply version bump to {package}>={target_version} in manifest.\n"
            f"2. Execute automated unit test suite.\n"
            f"3. Run security rescan to verify {len(findings)} CVEs are completely cleared.\n"
            f"4. Confirm zero build regressions."
        )

        # Upsert FixPlan in DB
        existing_plan = db.query(models.FixPlan).filter(models.FixPlan.task_id == task_id).first()
        if existing_plan:
            plan = existing_plan
            plan.ecosystem = ecosystem
            plan.package = package
            plan.current_version = current_version
            plan.target_version = target_version
            plan.action = action
            plan.safety_level = safety_level
            plan.reason = reason
            plan.verification_steps = verification_steps
        else:
            plan = models.FixPlan(
                task_id=task_id,
                ecosystem=ecosystem,
                package=package,
                current_version=current_version,
                target_version=target_version,
                action=action,
                safety_level=safety_level,
                reason=reason,
                verification_steps=verification_steps
            )
            db.add(plan)

        # Audit Event
        audit = models.AuditEvent(
            event_type="FIX_PLAN_CREATED",
            entity_type="remediation_task",
            entity_id=task_id,
            actor="linesec-planner-engine",
            action="generate_fix_plan",
            details_json=json.dumps({
                "package": package,
                "target_version": target_version,
                "safety_level": safety_level
            })
        )
        db.add(audit)

        db.commit()
        db.refresh(plan)
        return plan
