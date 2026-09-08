#!/usr/bin/env python3
import sys
import os
import json
import argparse
import subprocess
from typing import List, Dict, Any, Optional

# Add linesec-core root to sys.path so CLI can be run standalone
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

from adapters.bandit import BanditAdapter
from adapters.trivy import TrivyAdapter
from adapters.sarif import SARIFAdapter
from core.risk import RiskEngine
from core.context import RepositoryContext
from core.policy import PolicyEngine
from core.safety import SafetyValidator, SafetyLevel
from services.patcher import ManifestPatcher
from services.verification import SecurityDiffService
import models
import schemas

def run_local_bandit(target_dir: str) -> List[schemas.FindingCreate]:
    try:
        cmd = ["bandit", "-r", target_dir, "-f", "json"]
        result = subprocess.run(cmd, capture_output=True, text=True)
        raw_output = result.stdout or "{}"
        return BanditAdapter.parse_raw(raw_output)
    except Exception as e:
        sys.stderr.write(f"[!] Warning: Could not run local bandit binary ({e})\n")
        return []

def cmd_scan(args):
    print(f"\n[+] LineSec 2+ Scanner: Analyzing '{args.target}'...")
    findings: List[schemas.FindingCreate] = []

    if args.file:
        with open(args.file, "r", encoding="utf-8") as f:
            content = f.read()
        if args.scanner == "bandit":
            findings = BanditAdapter.parse_raw(content)
        elif args.scanner == "trivy":
            findings = TrivyAdapter.parse_raw(content)
        elif args.scanner == "sarif":
            findings = SARIFAdapter.parse_raw(content)
    else:
        findings = run_local_bandit(args.target)

    # Risk evaluation
    ctx = RepositoryContext(
        environment=args.environment,
        criticality=args.criticality,
        internet_exposed=args.internet_exposed
    )

    enriched_findings = []
    for f in findings:
        risk_res = RiskEngine.calculate_risk(
            severity=f.severity,
            epss_score=0.0,
            cisa_kev=False,
            context=ctx
        )
        f_dict = f.model_dump()
        f_dict["risk_score"] = risk_res.risk_score
        f_dict["priority"] = risk_res.priority
        enriched_findings.append(f_dict)

    if args.format == "json":
        print(json.dumps(enriched_findings, indent=2))
        return 0
    elif args.format == "sarif":
        sarif_obj = SARIFAdapter.to_sarif(findings)
        print(json.dumps(sarif_obj, indent=2))
        return 0

    # Table output
    print(f"\nFound {len(enriched_findings)} vulnerabilities:")
    print("-" * 80)
    print(f"{'PRIORITY':<10} | {'SEVERITY':<10} | {'RISK':<6} | {'FILE / PACKAGE':<30} | {'VULNERABILITY'}")
    print("-" * 80)
    for f in enriched_findings:
        loc = f.get("file_path") or f.get("package") or "N/A"
        loc_str = (loc[:27] + "...") if len(loc) > 30 else loc
        vuln = f.get("vulnerability_name") or "Unknown"
        vuln_str = (vuln[:25] + "...") if len(vuln) > 28 else vuln
        print(f"{f.get('priority', 'P2'):<10} | {f.get('severity', 'MEDIUM'):<10} | {f.get('risk_score', 50.0):<6.1f} | {loc_str:<30} | {vuln_str}")
    print("-" * 80)
    return 0

def cmd_policy_test(args):
    print(f"\n[+] LineSec 2+ Policy Gate Evaluation (Environment: {args.environment})...")
    findings = []
    if args.scan_file:
        with open(args.scan_file, "r", encoding="utf-8") as f:
            content = f.read()
        try:
            data = json.loads(content)
            if isinstance(data, list):
                findings = [schemas.FindingCreate(**item) for item in data]
            elif "results" in data:
                findings = BanditAdapter.parse_raw(content)
            elif "Results" in data:
                findings = TrivyAdapter.parse_raw(content)
        except Exception as e:
            sys.stderr.write(f"Error reading scan file: {e}\n")
            return 1

    ctx = RepositoryContext(
        environment=args.environment,
        criticality=args.criticality
    )

    enriched_findings = []
    for f in findings:
        risk_res = RiskEngine.calculate_risk(
            severity=f.severity,
            context=ctx
        )
        obj = schemas.FindingResponse(
            finding_id="cli-eval",
            vulnerability_name=f.vulnerability_name,
            severity=f.severity,
            priority=risk_res.priority,
            risk_score=risk_res.risk_score,
            file_path=f.file_path,
            cve=f.cve,
            package=f.package
        )
        enriched_findings.append(obj)

    decision = PolicyEngine.evaluate(
        findings=enriched_findings,
        context=ctx
    )


    print(f"\n>>> POLICY VERDICT: [{decision.action}] <<<")
    if decision.matched_rules:
        print("\nTriggered Rules:")
        for r in decision.matched_rules:
            print(f"  * {r}")
    if decision.reasons:
        print("\nDetailed Reasons:")
        for reason in decision.reasons:
            print(f"  - {reason}")

    if decision.action == "BLOCK":
        print("\n[!] CI/CD Gate Failed: Security policy violations detected.")
        return 1
    elif decision.action == "WARN":
        print("\n[?] CI/CD Gate Warning: Non-blocking security warnings detected.")
        return 0
    else:
        print("\n[✓] CI/CD Gate Passed.")
        return 0


def cmd_verify(args):
    print("\n[+] LineSec 2+ Security Diff & Verification Engine...")
    if not os.path.exists(args.base) or not os.path.exists(args.rescan):
        sys.stderr.write("Error: Both --base and --rescan files must exist.\n")
        return 1

    with open(args.base, "r", encoding="utf-8") as f:
        base_data = json.load(f)
    with open(args.rescan, "r", encoding="utf-8") as f:
        rescan_data = json.load(f)

    # Convert base to mock Finding models
    base_findings = []
    for item in (base_data if isinstance(base_data, list) else base_data.get("findings", [])):
        bf = schemas.FindingCreate(**item)
        base_findings.append(models.Finding(
            fingerprint=item.get("fingerprint"),
            vulnerability_name=bf.vulnerability_name,
            severity=bf.severity,
            file_path=bf.file_path,
            package=bf.package,
            cve=bf.cve,
            status="ANALYZED"
        ))

    rescan_findings = [
        schemas.FindingCreate(**item) for item in (rescan_data if isinstance(rescan_data, list) else rescan_data.get("findings", []))
    ]

    diff = SecurityDiffService.compare_finding_sets(
        base_findings=base_findings,
        rescan_findings=rescan_findings
    )

    print(f"\nVerification Verdict: [{diff['verdict']}]")
    print(f"  - Base Findings:     {diff['total_base']}")
    print(f"  - Rescan Findings:   {diff['total_rescan']}")
    print(f"  - Resolved:          {diff['resolved_count']}")
    print(f"  - Remaining/Open:    {diff['unchanged_count']}")
    print(f"  - New Introduced:    {diff['new_count']}")
    print(f"  - Regressed:         {diff['regressed_count']}\n")

    return 0 if diff["verdict"] == "PASSED" else 1

def build_parser():
    parser = argparse.ArgumentParser(prog="linesec", description="LineSec 2+ DevSecOps CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Scan
    scan_parser = subparsers.add_parser("scan", help="Scan repository or parse security scan reports")
    scan_parser.add_argument("target", nargs="?", default=".", help="Target directory to scan")
    scan_parser.add_argument("--file", "-f", help="Direct scan output file to parse")
    scan_parser.add_argument("--scanner", "-s", choices=["bandit", "trivy", "sarif", "all"], default="bandit")
    scan_parser.add_argument("--environment", "-e", choices=["production", "staging", "development"], default="development")
    scan_parser.add_argument("--criticality", "-c", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"], default="MEDIUM")
    scan_parser.add_argument("--internet-exposed", action="store_true", default=False)
    scan_parser.add_argument("--format", choices=["table", "json", "sarif"], default="table")
    scan_parser.add_argument("--offline", "--no-web", action="store_true", default=True)

    # Policy
    policy_parser = subparsers.add_parser("policy", help="Evaluate security posture against policy gates")
    policy_sub = policy_parser.add_subparsers(dest="subcommand", required=True)
    test_parser = policy_sub.add_parser("test", help="Test findings against policy")
    test_parser.add_argument("--scan-file", "-f", required=True, help="Scan JSON or findings file")
    test_parser.add_argument("--environment", "-e", choices=["production", "staging", "development"], default="production")
    test_parser.add_argument("--criticality", "-c", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"], default="HIGH")

    # Verify
    verify_parser = subparsers.add_parser("verify", help="Compare pre-fix and post-fix scans")
    verify_parser.add_argument("--base", "-b", required=True, help="Baseline scan JSON file")
    verify_parser.add_argument("--rescan", "-r", required=True, help="Rescan JSON file after fix")

    return parser

def main():
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "scan":
        sys.exit(cmd_scan(args))
    elif args.command == "policy":
        if args.subcommand == "test":
            sys.exit(cmd_policy_test(args))
    elif args.command == "verify":
        sys.exit(cmd_verify(args))

if __name__ == "__main__":
    main()
