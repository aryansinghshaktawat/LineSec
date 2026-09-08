import pytest
from adapters.sarif import SARIFAdapter
import schemas

def test_sarif_adapter_import():
    sample_sarif = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "CodeQL",
                        "rules": [
                            {
                                "id": "py/sql-injection",
                                "shortDescription": {"text": "SQL query built from user input"}
                            }
                        ]
                    }
                },
                "results": [
                    {
                        "ruleId": "py/sql-injection",
                        "level": "error",
                        "message": {"text": "User input directly formatted into raw SQL query"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "src/database.py"},
                                    "region": {"startLine": 28}
                                }
                            }
                        ]
                    }
                ]
            }
        ]
    }

    adapter = SARIFAdapter()
    findings = adapter.parse_raw(sample_sarif)
    assert len(findings) == 1
    f = findings[0]
    assert f.scanner == "codeql"
    assert f.vulnerability_name == "py/sql-injection"
    assert f.severity == "HIGH"
    assert f.file_path == "src/database.py"
    assert f.line_number == 28

def test_sarif_adapter_export():
    finding = schemas.FindingResponse(
        finding_id="f-1",
        tool_name="bandit",
        vulnerability_name="B104",
        severity="HIGH",
        description="Bind all interfaces",
        file_path="main.py",
        line_number=50,
        remediation_status="NEW"
    )
    sarif_doc = SARIFAdapter.export_sarif([finding])
    assert sarif_doc["version"] == "2.1.0"
    assert len(sarif_doc["runs"]) == 1
    assert sarif_doc["runs"][0]["results"][0]["ruleId"] == "B104"
    assert sarif_doc["runs"][0]["results"][0]["level"] == "error"
