import json
from typing import List, Dict, Any, Tuple
from sqlalchemy.orm import Session
from datetime import datetime, timezone

import models
import schemas
from core.fingerprint import generate_finding_fingerprint
from core.lifecycle import FindingStatus

def utc_now():
    return datetime.now(timezone.utc)

class IngestionService:
    @staticmethod
    def ingest_findings(
        db: Session,
        findings_in: List[schemas.FindingCreate],
        repository_id: str = "default",
        scanner_override: str = None
    ) -> Tuple[List[models.Finding], Dict[str, int]]:
        """
        Deduplicating, fingerprint-driven ingestion engine for LineSec findings.
        
        Guarantees:
        - Deterministic SHA-256 fingerprinting for every incoming finding.
        - Idempotency: repeated scans of identical findings update 'last_seen' rather than creating duplicates.
        - Regression detection: previously 'RESOLVED' findings that reappear transition to 'REGRESSED'.
        - Audit trail generation.
        """
        processed_findings: List[models.Finding] = []
        stats = {
            "total_received": len(findings_in),
            "new": 0,
            "existing": 0,
            "regressed": 0
        }

        for item in findings_in:
            scanner = scanner_override or item.scanner or item.tool_name or "bandit"
            repo_id = repository_id if repository_id and repository_id != "default" else (item.repository_id or "default")
            vuln_name = item.vulnerability_name or "Unknown Vulnerability"
            
            # Generate deterministic fingerprint
            fp = generate_finding_fingerprint(
                repository=repo_id,
                scanner=scanner,
                vulnerability_identifier=vuln_name,
                file_path=item.file_path,
                line_number=item.line_number,
                package=item.package,
                ecosystem=item.ecosystem
            )

            # Query for existing finding by fingerprint in this repository
            existing = db.query(models.Finding).filter(
                models.Finding.fingerprint == fp,
                models.Finding.repository_id == repo_id
            ).first()

            if existing:
                # Update timestamp and metadata
                existing.last_seen = utc_now()
                existing.description = item.description or existing.description
                existing.line_number = item.line_number or existing.line_number
                
                # Check for regression
                if existing.status == FindingStatus.RESOLVED.value or existing.remediation_status == FindingStatus.RESOLVED.value:
                    existing.status = FindingStatus.REGRESSED.value
                    existing.remediation_status = FindingStatus.REGRESSED.value
                    stats["regressed"] += 1
                else:
                    stats["existing"] += 1
                
                processed_findings.append(existing)
            else:
                # New Finding Creation
                new_finding = models.Finding(
                    fingerprint=fp,
                    repository_id=repo_id,
                    tool_name=scanner,
                    scanner=scanner,
                    scanner_type=item.scanner_type or "SAST",
                    vulnerability_name=vuln_name,
                    title=vuln_name,
                    severity=(item.severity or "MEDIUM").upper(),
                    description=item.description,
                    file_path=item.file_path,
                    line_number=item.line_number,
                    package=item.package,
                    ecosystem=item.ecosystem,
                    installed_version=item.installed_version,
                    fixed_version=item.fixed_version,
                    cve=item.cve,
                    cwe=item.cwe,
                    status=FindingStatus.NEW.value,
                    remediation_status=FindingStatus.NEW.value,
                    environment=item.environment or "development",
                    first_seen=utc_now(),
                    last_seen=utc_now()
                )
                db.add(new_finding)
                processed_findings.append(new_finding)
                stats["new"] += 1

        # Audit Event Log
        audit = models.AuditEvent(
            event_type="FINDINGS_INGESTED",
            entity_type="repository",
            entity_id=repository_id,
            actor="linesec-ingestion-engine",
            action="ingest_scan_findings",
            details_json=json.dumps(stats)
        )
        db.add(audit)
        
        db.commit()

        for f in processed_findings:
            db.refresh(f)

        return processed_findings, stats
