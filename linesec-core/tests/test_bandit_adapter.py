import pytest
from adapters.bandit import BanditAdapter

def test_bandit_adapter_parsing():
    sample_bandit_json = {
        "results": [
            {
                "test_name": "B104_hardcoded_bind_all_interfaces",
                "test_id": "B104",
                "issue_severity": "MEDIUM",
                "issue_text": "Possible binding to all interfaces",
                "filename": "app/main.py",
                "line_number": 42,
                "issue_cwe": {"id": 200}
            }
        ]
    }

    adapter = BanditAdapter()
    findings = adapter.parse_raw(sample_bandit_json)
    assert len(findings) == 1
    f = findings[0]
    assert f.scanner == "bandit"
    assert f.scanner_type == "SAST"
    assert f.vulnerability_name == "B104_hardcoded_bind_all_interfaces"
    assert f.severity == "MEDIUM"
    assert f.file_path == "app/main.py"
    assert f.line_number == 42
    assert f.cwe == "CWE-200"
