import json
from typing import List, Dict, Any, Union
from adapters.base import ScannerAdapter
import schemas

class SARIFAdapter(ScannerAdapter):
    @property
    def name(self) -> str:
        return "sarif"

    @property
    def scanner_type(self) -> str:
        return "GENERIC_SARIF"

    def parse_raw(self, raw_data: Union[str, bytes, Dict[str, Any]]) -> List[schemas.FindingCreate]:
        """
        Parses standard SARIF 2.1.0 JSON reports into canonical FindingCreate objects.
        """
        if isinstance(raw_data, (str, bytes)):
            try:
                data = json.loads(raw_data)
            except json.JSONDecodeError as e:
                raise ValueError(f"Failed to parse SARIF JSON output: {e}")
        elif isinstance(raw_data, dict):
            data = raw_data
        else:
            raise TypeError("raw_data must be str, bytes, or dict")

        findings: List[schemas.FindingCreate] = []
        runs = data.get("runs", [])

        level_map = {
            "error": "HIGH",
            "warning": "MEDIUM",
            "note": "LOW",
            "none": "INFO"
        }

        for run in runs:
            tool = run.get("tool", {})
            driver = tool.get("driver", {})
            tool_name = driver.get("name", "sarif-scanner").lower()
            
            # Map rules for quick metadata lookup
            rules_list = driver.get("rules", [])
            rules_map = {r.get("id"): r for r in rules_list if "id" in r}

            results = run.get("results", [])
            for result in results:
                rule_id = result.get("ruleId", "UNKNOWN_RULE")
                rule_meta = rules_map.get(rule_id, {})
                
                # Severity determination
                sarif_level = result.get("level") or rule_meta.get("defaultConfiguration", {}).get("level", "warning")
                severity = level_map.get(str(sarif_level).lower(), "MEDIUM")

                # Message / Description
                msg = result.get("message", {}).get("text") or rule_meta.get("shortDescription", {}).get("text") or rule_id

                # File Location
                locations = result.get("locations", [])
                file_path = ""
                line_number = 0
                if locations:
                    phys_loc = locations[0].get("physicalLocation", {})
                    file_path = phys_loc.get("artifactLocation", {}).get("uri", "")
                    region = phys_loc.get("region", {})
                    line_number = int(region.get("startLine", 0))

                finding = schemas.FindingCreate(
                    tool_name=tool_name,
                    scanner=tool_name,
                    scanner_type="SAST",
                    vulnerability_name=rule_id,
                    severity=severity,
                    description=msg,
                    file_path=file_path,
                    line_number=line_number,
                    environment="development"
                )
                findings.append(finding)

        return findings

    @staticmethod
    def export_sarif(findings: List[Any], tool_name: str = "LineSec", version: str = "2.0.0") -> Dict[str, Any]:
        """
        Exports LineSec findings into standard OASIS SARIF 2.1.0 format.
        """
        results = []
        rules_map = {}

        severity_to_level = {
            "CRITICAL": "error",
            "HIGH": "error",
            "MEDIUM": "warning",
            "LOW": "note",
            "INFO": "none"
        }

        for f in findings:
            vuln_name = getattr(f, "vulnerability_name", "UNKNOWN")
            severity = (getattr(f, "severity", "MEDIUM") or "MEDIUM").upper()
            desc = getattr(f, "description", "") or vuln_name
            file_path = getattr(f, "file_path", "") or "unknown"
            line_no = getattr(f, "line_number", 1) or 1
            if line_no <= 0:
                line_no = 1

            rule_id = vuln_name
            if rule_id not in rules_map:
                rules_map[rule_id] = {
                    "id": rule_id,
                    "shortDescription": {"text": vuln_name},
                    "defaultConfiguration": {
                        "level": severity_to_level.get(severity, "warning")
                    }
                }

            result_entry = {
                "ruleId": rule_id,
                "level": severity_to_level.get(severity, "warning"),
                "message": {"text": desc},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": file_path},
                            "region": {"startLine": line_no}
                        }
                    }
                ]
            }
            results.append(result_entry)

        sarif_doc = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": tool_name,
                            "version": version,
                            "rules": list(rules_map.values())
                        }
                    },
                    "results": results
                }
            ]
        }
        return sarif_doc
