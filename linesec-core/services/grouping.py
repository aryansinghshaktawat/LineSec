import json
from typing import List, Dict
from sqlalchemy.orm import Session
from datetime import datetime, timezone
import models
from core.lifecycle import TaskStatus

def utc_now():
    return datetime.now(timezone.utc)

SEVERITY_PRIORITY_MAP = {
    "CRITICAL": ("P0", 90.0),
    "HIGH": ("P1", 75.0),
    "MEDIUM": ("P2", 50.0),
    "LOW": ("P3", 25.0),
    "INFO": ("P3", 10.0)
}

class TaskGroupingEngine:
    @staticmethod
    def group_repository_findings(db: Session, repository_id: str = "default") -> List[models.RemediationTask]:
        """
        Groups individual unassigned findings into actionable RemediationTasks.
        
        Strategy:
        1. SCA / Dependency findings are clustered by (package, ecosystem).
           All CVEs affecting the same package are consolidated into a single upgrade task.
        2. SAST / Code findings are clustered by (scanner, file_path).
           Multiple code flaws in a single file are grouped into a coherent code patch task.
        """
        # Fetch open findings without a task or with pending tasks
        findings = db.query(models.Finding).filter(
            models.Finding.repository_id == repository_id,
            models.Finding.status.notin_(["RESOLVED", "FALSE_POSITIVE", "RISK_ACCEPTED"])
        ).all()

        if not findings:
            return []

        # Cluster findings into buckets
        clusters: Dict[str, List[models.Finding]] = {}
        for f in findings:
            if f.package and f.ecosystem:
                # Dependency upgrade cluster
                cluster_key = f"pkg:{f.ecosystem}:{f.package}"
            else:
                # Code patch cluster
                cluster_key = f"code:{f.tool_name or f.scanner}:{f.file_path or 'root'}"
            
            if cluster_key not in clusters:
                clusters[cluster_key] = []
            clusters[cluster_key].append(f)

        created_or_updated_tasks: List[models.RemediationTask] = []

        for cluster_key, cluster_findings in clusters.items():
            # Determine maximum severity across clustered findings
            severities = [(f.severity or "MEDIUM").upper() for f in cluster_findings]
            highest_sev = "LOW"
            for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
                if s in severities:
                    highest_sev = s
                    break

            priority, base_risk = SEVERITY_PRIORITY_MAP.get(highest_sev, ("P2", 50.0))

            if cluster_key.startswith("pkg:"):
                _, ecosystem, package = cluster_key.split(":", 2)
                
                # Determine target version (select latest available fixed version)
                fixed_versions = [f.fixed_version for f in cluster_findings if f.fixed_version]
                target_ver = fixed_versions[-1] if fixed_versions else "latest-secure"

                title = f"Upgrade {package} to {target_ver} ({len(cluster_findings)} CVEs)"
                action = "upgrade"
            else:
                _, tool, file_path = cluster_key.split(":", 2)
                package = None
                ecosystem = None
                target_ver = None
                title = f"Remediate {len(cluster_findings)} {tool.upper()} vulnerabilities in {file_path}"
                action = "code_patch"

            # Check if an active task for this cluster already exists
            existing_task = None
            for f in cluster_findings:
                if f.task_id:
                    existing_task = db.query(models.RemediationTask).filter(
                        models.RemediationTask.task_id == f.task_id
                    ).first()
                    if existing_task:
                        break

            if existing_task:
                task = existing_task
                task.title = title
                task.priority = priority
                task.risk_score = base_risk
                task.target_version = target_ver
                task.updated_at = utc_now()
            else:
                task = models.RemediationTask(
                    title=title,
                    package=package,
                    ecosystem=ecosystem,
                    action=action,
                    target_version=target_ver,
                    status=TaskStatus.PENDING.value,
                    priority=priority,
                    risk_score=base_risk,
                    safety_level="SAFE" if action == "upgrade" and priority in ("P2", "P3") else "APPROVAL_REQUIRED"
                )
                db.add(task)
                db.flush()  # Generate task.task_id

            # Associate all findings in the cluster to this task
            for f in cluster_findings:
                f.task_id = task.task_id

            created_or_updated_tasks.append(task)

        # Audit Event
        audit = models.AuditEvent(
            event_type="TASKS_GROUPED",
            entity_type="repository",
            entity_id=repository_id,
            actor="linesec-grouping-engine",
            action="group_findings_into_tasks",
            details_json=json.dumps({"total_tasks": len(created_or_updated_tasks)})
        )
        db.add(audit)

        db.commit()

        for t in created_or_updated_tasks:
            db.refresh(t)

        return created_or_updated_tasks
