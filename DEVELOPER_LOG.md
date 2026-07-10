# Developer Log: LineSec Remediation Module

## PyGithub Automation Architecture
The **LineSec Remediation** module (`linesec-remediation`) automates the creation of GitHub issues for security findings that have been analyzed by our AI module.

### Core Architecture & Workflow:
1.  **Authentication**:
    *   The module loads `GITHUB_TOKEN` and `TARGET_REPO` from `.env`.
    *   It authenticates using the PyGithub library's modern token syntax: `auth = Auth.Token(github_token)` and `g = Github(auth=auth)`.
2.  **Database Connection**:
    *   The engine connects to the local PostgreSQL database (`postgresql://localhost/linesec_core_db`) and queries the `findings` table.
    *   It filters for records where `remediation_status == 'ANALYZED'`.
3.  **Issue Creation**:
    *   For each analyzed finding, it generates an issue on the target repository using `repo.create_issue()`.
    *   **Title**: `[Security Alert] {vulnerability_name}`
    *   **Body**: A Markdown document containing structured information about the finding, including the tool that detected it, severity, file path, line number, description, AI-generated root cause, and remediation plan.
4.  **State Synchronization**:
    *   Once the issue is successfully created, the finding's `remediation_status` is updated to `'TICKET_OPENED'` in the database and the changes are committed.
