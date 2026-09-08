import json
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime, timezone
from sqlalchemy.orm import Session
import models
import schemas
from core.fingerprint import generate_finding_fingerprint
from core.lifecycle import FindingStatus, TaskStatus, validate_finding_transition

def utc_now():
    return datetime.now(timezone.utc)

class SecurityDiffService:
    """
    Computes deterministic security diffs between two scans or finding sets.
    Identifies RESOLVED, UNCHANGED, NEW, and REGRESSED vulnerabilities.
    """

    @staticmethod
    def compare_finding_sets(
        base_findings: List[models.Finding],
        rescan_findings: List[schemas.FindingCreate],
        db: Optional[Session] = None
    ) -> Dict[str, Any]:
        base_fp_map = {f.fingerprint: f for f in base_findings if f.fingerprint}
        
        rescan_fps = set()
        rescan_items_map = {}
        for rf in rescan_findings:
            repo_id = rf.repository_id or "default"
            scanner = rf.scanner or rf.tool_name or "bandit"
            vuln_name = rf.vulnerability_name or "Unknown Vulnerability"
            fp = generate_finding_fingerprint(
                repository=repo_id,
                scanner=scanner,
                vulnerability_identifier=vuln_name,
                file_path=rf.file_path,
                line_number=rf.line_number,
                package=rf.package,
                ecosystem=rf.ecosystem
            )
            rescan_fps.add(fp)
            rescan_items_map[fp] = rf


        resolved = []
        unchanged = []
        new = []
        regressed = []

        # 1. Base findings comparison
        for fp, bf in base_fp_map.items():
            if fp not in rescan_fps:
                resolved.append({
                    "fingerprint": fp,
                    "vulnerability_name": bf.vulnerability_name,
                    "severity": bf.severity,
                    "file_path": bf.file_path,
                    "package": bf.package,
                    "cve": bf.cve,
                    "diff_status": "RESOLVED"
                })
            else:
                unchanged.append({
                    "fingerprint": fp,
                    "vulnerability_name": bf.vulnerability_name,
                    "severity": bf.severity,
                    "file_path": bf.file_path,
                    "package": bf.package,
                    "cve": bf.cve,
                    "diff_status": "UNCHANGED"
                })

        # 2. Rescan findings comparison
        for fp, rf in rescan_items_map.items():
            if fp not in base_fp_map:
                # Check if it was previously resolved in DB (Regression)
                is_regressed = False
                if db:
                    prior_resolved = db.query(models.Finding).filter(
                        models.Finding.fingerprint == fp,
                        models.Finding.status == FindingStatus.RESOLVED.value
                    ).first()
                    if prior_resolved:
                        is_regressed = True

                diff_status = "REGRESSED" if is_regressed else "NEW"
                item = {
                    "fingerprint": fp,
                    "vulnerability_name": rf.vulnerability_name,
                    "severity": rf.severity,
                    "file_path": rf.file_path,
                    "package": rf.package,
                    "cve": rf.cve,
                    "diff_status": diff_status
                }
                if is_regressed:
                    regressed.append(item)
                else:
                    new.append(item)

        verdict = "PASSED" if len(unchanged) == 0 and len(regressed) == 0 and len([n for n in new if n["severity"] in ["CRITICAL", "HIGH"]]) == 0 else "FAILED"

        return {
            "total_base": len(base_findings),
            "total_rescan": len(rescan_findings),
            "resolved_count": len(resolved),
            "unchanged_count": len(unchanged),
            "new_count": len(new),
            "regressed_count": len(regressed),
            "resolved_findings": resolved,
            "unchanged_findings": unchanged,
            "new_findings": new,
            "regressed_findings": regressed,
            "verdict": verdict
        }


class VerificationEngine:
    """
    Autonomous Verification Engine.
    Validates whether remediation tasks successfully eradicated vulnerabilities without regressions.
    """

    @staticmethod
    def verify_task(
        db: Session,
        task_id: str,
        rescan_findings: Optional[List[schemas.FindingCreate]] = None
    ) -> Dict[str, Any]:
        task = db.query(models.RemediationTask).filter(models.RemediationTask.task_id == task_id).first()
        if not task:
            raise ValueError(f"Task with ID {task_id} not found")

        task_findings = task.findings or []
        initial_count = len(task_findings)

        if rescan_findings is None:
            rescan_findings = []

        diff = SecurityDiffService.compare_finding_sets(
            base_findings=task_findings,
            rescan_findings=rescan_findings,
            db=db
        )

        resolved_fps = {r["fingerprint"] for r in diff["resolved_findings"]}
        unchanged_fps = {u["fingerprint"] for u in diff["unchanged_findings"]}

        # Update findings lifecycle
        for f in task_findings:
            if f.fingerprint in resolved_fps:
                f.status = FindingStatus.RESOLVED.value
                f.remediation_status = "RESOLVED"
            elif f.fingerprint in unchanged_fps:
                f.status = FindingStatus.FAILED.value
                f.remediation_status = "FAILED"

        # Determine task promotion
        verified = len(unchanged_fps) == 0 and diff["regressed_count"] == 0
        if verified:
            task.status = TaskStatus.RESOLVED.value
            summary = f"Verification PASSED: All {initial_count} findings resolved successfully."
        else:
            task.status = TaskStatus.FAILED.value
            summary = f"Verification FAILED: {len(unchanged_fps)} findings remained open and {diff['regressed_count']} regressions detected."

        # Audit Event
        audit = models.AuditEvent(
            event_type="TASK_VERIFIED" if verified else "TASK_VERIFICATION_FAILED",
            entity_type="remediation_task",
            entity_id=task_id,
            actor="linesec-verification-engine",
            action="verify_remediation",
            details_json=json.dumps({
                "verified": verified,
                "resolved_count": len(resolved_fps),
                "remaining_count": len(unchanged_fps),
                "regressed_count": diff["regressed_count"]
            })
        )
        db.add(audit)
        db.commit()
        db.refresh(task)

        return {
            "task_id": task_id,
            "target_version": task.target_version,
            "initial_findings_count": initial_count,
            "resolved_count": len(resolved_fps),
            "remaining_count": len(unchanged_fps),
            "new_count": diff["new_count"],
            "status": task.status,
            "verified": verified,
            "summary": summary,
            "timestamp": utc_now()
        }
