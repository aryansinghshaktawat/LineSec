import pytest
from adapters.trivy import TrivyAdapter

def test_trivy_adapter_sca_parsing():
    sample_trivy_json = {
        "SchemaVersion": 2,
        "Results": [
            {
                "Target": "requirements.txt",
                "Class": "lang-pkgs",
                "Type": "pip",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2023-32681",
                        "PkgName": "requests",
                        "InstalledVersion": "2.25.0",
                        "FixedVersion": "2.31.0",
                        "Severity": "HIGH",
                        "Title": "requests: Unintended leak of Proxy-Authorization header",
                        "Description": "Requests is a HTTP library...",
                        "CweIDs": ["CWE-200"]
                    }
                ]
            }
        ]
    }

    adapter = TrivyAdapter()
    findings = adapter.parse_raw(sample_trivy_json)
    assert len(findings) == 1
    f = findings[0]
    assert f.scanner == "trivy"
    assert f.scanner_type == "SCA"
    assert f.vulnerability_name == "CVE-2023-32681"
    assert f.cve == "CVE-2023-32681"
    assert f.package == "requests"
    assert f.ecosystem == "pip"
    assert f.installed_version == "2.25.0"
    assert f.fixed_version == "2.31.0"
    assert f.severity == "HIGH"
    assert f.cwe == "CWE-200"
