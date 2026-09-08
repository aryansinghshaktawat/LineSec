import json
from typing import List, Dict, Any, Union
from adapters.base import ScannerAdapter
import schemas

class BanditAdapter(ScannerAdapter):
    @property
    def name(self) -> str:
        return "bandit"

    @property
    def scanner_type(self) -> str:
        return "SAST"

    def parse_raw(self, raw_data: Union[str, bytes, Dict[str, Any]]) -> List[schemas.FindingCreate]:
        """
        Parses Bandit JSON reports into canonical FindingCreate schemas.
        """
        if isinstance(raw_data, (str, bytes)):
            try:
                data = json.loads(raw_data)
            except json.JSONDecodeError as e:
                raise ValueError(f"Failed to parse Bandit JSON output: {e}")
        elif isinstance(raw_data, dict):
            data = raw_data
        else:
            raise TypeError("raw_data must be str, bytes, or dict")

        results = data.get("results", [])
        findings: List[schemas.FindingCreate] = []

        for issue in results:
            vuln_name = issue.get("test_name", issue.get("test_id", "Unknown Bandit Finding"))
            severity = issue.get("issue_severity", "MEDIUM").upper()
            cwe = str(issue.get("issue_cwe", {}).get("id", "")) if isinstance(issue.get("issue_cwe"), dict) else None

            finding = schemas.FindingCreate(
                tool_name=self.name,
                scanner=self.name,
                scanner_type=self.scanner_type,
                vulnerability_name=vuln_name,
                severity=severity,
                description=issue.get("issue_text", ""),
                file_path=issue.get("filename", ""),
                line_number=int(issue.get("line_number", 0)),
                cwe=f"CWE-{cwe}" if cwe and not str(cwe).startswith("CWE-") else cwe,
                ecosystem="pip",
                environment="development"
            )
            findings.append(finding)

        return findings
