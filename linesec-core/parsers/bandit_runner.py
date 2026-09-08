import json
import os
import subprocess
import requests

def run_bandit():
    # The script lives in linesec-core/parsers/bandit_runner.py.
    # We want to scan the parent directory (linesec-core).
    script_dir = os.path.dirname(os.path.abspath(__file__))
    target_dir = os.path.dirname(script_dir)

    print(f"Running Bandit scan against: {target_dir}")
    # Run bandit command: bandit -r <target_dir> -x <target_dir>/venv -f json
    result = subprocess.run(
        ["bandit", "-r", target_dir, "-x", f"{target_dir}/venv", "-f", "json"],
        capture_output=True,
        text=True
    )

    # Bandit exits with 1 if issues are found, and 0 if none are found.
    # Exit codes other than 0 or 1 indicate an execution failure.
    if result.returncode not in (0, 1):
        print(f"Bandit scan failed with exit code: {result.returncode}")
        print(f"Stderr: {result.stderr}")
        return

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError as e:
        print("Failed to decode Bandit JSON output.")
        print(f"Raw Output: {result.stdout}")
        return

    raw_results = data.get("results", [])
    print(f"Parsed {len(raw_results)} raw findings from Bandit.")

    normalized_findings = []
    for issue in raw_results:
        # Map to FindingCreate schema:
        # tool_name, vulnerability_name, severity, description, file_path, line_number
        finding = {
            "tool_name": "bandit",
            "vulnerability_name": issue.get("test_name", "Unknown Bandit Test"),
            "severity": issue.get("issue_severity", "UNKNOWN"),
            "description": issue.get("issue_text", ""),
            "file_path": issue.get("filename", ""),
            "line_number": int(issue.get("line_number", 0))
        }
        normalized_findings.append(finding)

    if not normalized_findings:
        print("No findings to ingest.")
        return

    # POST normalized findings to LineSec Core API
    url = "http://127.0.0.1:8000/api/ingest"
    print(f"Sending {len(normalized_findings)} findings to {url}...")
    try:
        response = requests.post(url, json=normalized_findings)
        print(f"HTTP Status Code: {response.status_code}")
        print("Server Response:")
        print(json.dumps(response.json(), indent=2))
    except requests.exceptions.RequestException as e:
        print(f"Request failed: {e}")

if __name__ == "__main__":
    run_bandit()
