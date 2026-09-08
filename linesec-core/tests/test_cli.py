import json
import pytest
from cli.main import build_parser, cmd_scan, cmd_policy_test, cmd_verify
import schemas

def test_cli_parser():
    parser = build_parser()
    
    # Test scan args
    scan_args = parser.parse_args(["scan", "--scanner", "trivy", "--format", "json"])
    assert scan_args.command == "scan"
    assert scan_args.scanner == "trivy"
    assert scan_args.format == "json"

    # Test policy args
    policy_args = parser.parse_args(["policy", "test", "-f", "scan.json", "-e", "production"])
    assert policy_args.command == "policy"
    assert policy_args.subcommand == "test"
    assert policy_args.scan_file == "scan.json"
    assert policy_args.environment == "production"

def test_cli_policy_evaluation_pass(tmp_path):
    scan_file = tmp_path / "clean_scan.json"
    scan_file.write_text(json.dumps([
        {
            "tool_name": "bandit",
            "vulnerability_name": "B101: Test assert",
            "severity": "LOW",
            "file_path": "tests/test_auth.py",
            "line_number": 5
        }
    ]))

    parser = build_parser()
    args = parser.parse_args(["policy", "test", "-f", str(scan_file), "-e", "development"])
    exit_code = cmd_policy_test(args)
    assert exit_code == 0

def test_cli_policy_evaluation_block_critical_production(tmp_path):
    scan_file = tmp_path / "vuln_scan.json"
    scan_file.write_text(json.dumps([
        {
            "tool_name": "trivy",
            "vulnerability_name": "CVE-2023-45803",
            "severity": "CRITICAL",
            "file_path": "requirements.txt",
            "line_number": 1
        }
    ]))

    parser = build_parser()
    args = parser.parse_args(["policy", "test", "-f", str(scan_file), "-e", "production"])
    exit_code = cmd_policy_test(args)
    assert exit_code == 1 # Blocked!

def test_cli_verify_diff(tmp_path):
    base_file = tmp_path / "base.json"
    rescan_file = tmp_path / "rescan.json"

    base_file.write_text(json.dumps([
        {
            "tool_name": "bandit",
            "vulnerability_name": "B301: Pickle usage",
            "severity": "HIGH",
            "file_path": "auth.py",
            "line_number": 10
        }
    ]))

    # Clean rescan
    rescan_file.write_text(json.dumps([]))

    parser = build_parser()
    args = parser.parse_args(["verify", "-b", str(base_file), "-r", str(rescan_file)])
    exit_code = cmd_verify(args)
    assert exit_code == 0
