import requests

payload = [
    {
        "tool_name": "git-secrets",
        "vulnerability_name": "Hardcoded AWS Access Key",
        "severity": "CRITICAL",
        "description": "A hardcoded AWS Access Key ID was found in the repository configuration.",
        "file_path": "config/aws.conf",
        "line_number": 12
    },
    {
        "tool_name": "bandit",
        "vulnerability_name": "SQL Injection",
        "severity": "HIGH",
        "description": "Possible SQL injection vector found due to string formatting in database query construction.",
        "file_path": "src/database/query.py",
        "line_number": 45
    }
]

url = "http://127.0.0.1:8000/api/ingest"

try:
    response = requests.post(url, json=payload)
    print(f"Status Code: {response.status_code}")
    print("Response JSON:")
    print(response.json())
except requests.exceptions.RequestException as e:
    print(f"An error occurred: {e}")
