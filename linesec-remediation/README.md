# LineSec Remediation Module

LineSec Remediation is an autonomous ticketing microservice designed to close the gap between security detection and developer action. It polls the database for vulnerabilities analyzed by the AI engine and automatically generates highly descriptive developer tickets as GitHub Issues.

## Features

*   **Autonomous Operation**: Continuously monitors the security database for findings transitioned to the `ANALYZED` status by the AI layer.
*   **Structured Ticket Generation**: Creates detailed markdown issues displaying file path, line numbers, severity, vulnerability descriptions, custom root-cause analysis, and specific remediation recipes.
*   **PyGithub Integration**: Communicates directly with the GitHub API utilizing modern authorization token flows.
*   **Database Synced**: Promotes the database status of the finding to `TICKET_OPENED` once ticket generation is successfully verified.

## Project Setup

### Prerequisites
*   Python 3.10+
*   FastAPI/Postgres database running locally

### Installation
1. Navigate to the remediation directory:
   ```bash
   cd linesec-remediation
   ```
2. Activate the virtual environment:
   ```bash
   source venv/bin/activate
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

### Configuration
Create a `.env` file inside `linesec-remediation` specifying your GitHub Token and the target repository:
```env
GITHUB_TOKEN=ghp_your_secure_developer_token
TARGET_REPO=OwnerName/RepositoryName
```

### Running the Ticketing System
Run the script to process all newly analyzed findings:
```bash
python ticket_creator.py
```
Upon success, the script will print the created issue numbers and commit the updated `TICKET_OPENED` status to the database.
