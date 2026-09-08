import json
from typing import List, Dict, Any, Union
from adapters.base import ScannerAdapter
import schemas

class TrivyAdapter(ScannerAdapter):
    @property
    def name(self) -> str:
        return "trivy"

    @property
    def scanner_type(self) -> str:
        return "SCA"

    def parse_raw(self, raw_data: Union[str, bytes, Dict[str, Any]]) -> List[schemas.FindingCreate]:
        """
        Parses Trivy JSON output (filesystem, lockfiles, containers, misconfigurations)
        into normalized FindingCreate objects.
        """
        if isinstance(raw_data, (str, bytes)):
            try:
                data = json.loads(raw_data)
            except json.JSONDecodeError as e:
                raise ValueError(f"Failed to parse Trivy JSON output: {e}")
        elif isinstance(raw_data, dict):
            data = raw_data
        else:
            raise TypeError("raw_data must be str, bytes, or dict")

        findings: List[schemas.FindingCreate] = []
        results = data.get("Results", [])

        for target_result in results:
            target_file = target_result.get("Target", "unknown")
            ecosystem_type = target_result.get("Type", "generic").lower()
            
            # 1. Parse Vulnerabilities (SCA / CVEs)
            vulnerabilities = target_result.get("Vulnerabilities", [])
            for vuln in vulnerabilities:
                cve_id = vuln.get("VulnerabilityID", "UNKNOWN-VULN")
                pkg_name = vuln.get("PkgName", "")
                installed_ver = vuln.get("InstalledVersion")
                fixed_ver = vuln.get("FixedVersion")
                severity = (vuln.get("Severity") or "MEDIUM").upper()
                title = vuln.get("Title") or f"{cve_id} in {pkg_name}"
                desc = vuln.get("Description") or title
                
                cwe_list = vuln.get("CweIDs", [])
                cwe_val = cwe_list[0] if cwe_list else None

                finding = schemas.FindingCreate(
                    tool_name=self.name,
                    scanner=self.name,
                    scanner_type="SCA",
                    vulnerability_name=cve_id,
                    severity=severity,
                    description=desc,
                    file_path=target_file,
                    line_number=0,
                    package=pkg_name,
                    ecosystem=ecosystem_type,
                    installed_version=installed_ver,
                    fixed_version=fixed_ver,
                    cve=cve_id,
                    cwe=cwe_val,
                    environment="development"
                )
                findings.append(finding)

            # 2. Parse Misconfigurations (IaC / Dockerfile / Config)
            misconfigs = target_result.get("Misconfigurations", [])
            for mis in misconfigs:
                rule_id = mis.get("ID", "UNKNOWN-MISCONFIG")
                title = mis.get("Title", rule_id)
                severity = (mis.get("Severity") or "LOW").upper()
                desc = mis.get("Description", title)
                line_no = mis.get("CauseMetadata", {}).get("StartLine", 0)

                finding = schemas.FindingCreate(
                    tool_name=self.name,
                    scanner=self.name,
                    scanner_type="MISCONFIG",
                    vulnerability_name=rule_id,
                    severity=severity,
                    description=desc,
                    file_path=target_file,
                    line_number=int(line_no),
                    environment="development"
                )
                findings.append(finding)

            # 3. Parse Secrets
            secrets = target_result.get("Secrets", [])
            for secret in secrets:
                rule_id = secret.get("RuleID", "SECRET-DETECTED")
                title = secret.get("Title", "Exposed Secret")
                severity = (secret.get("Severity") or "CRITICAL").upper()
                line_no = secret.get("StartLine", 0)

                finding = schemas.FindingCreate(
                    tool_name=self.name,
                    scanner=self.name,
                    scanner_type="SECRET",
                    vulnerability_name=rule_id,
                    severity=severity,
                    description=f"Secret detected: {title}",
                    file_path=target_file,
                    line_number=int(line_no),
                    environment="development"
                )
                findings.append(finding)

        return findings
