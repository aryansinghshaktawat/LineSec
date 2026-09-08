# LineSec Security Dashboard

LineSec Dashboard is a Next.js and Tailwind CSS frontend that provides a single-pane-of-glass monitoring solution for application security infrastructure. It visualizes real-time security analytics and vulnerability telemetry ingested into the LineSec Core database.

## Features

*   **Single Pane of Glass**: Displays a consolidated dashboard of application security health and real-time vulnerability status.
*   **Analytics Metrics Summary Cards**:
    *   **Total Vulnerabilities**: Calculates total findings in the database.
    *   **Critical Severity Count**: Isolates and counts issues marked with `CRITICAL` severity status.
    *   **High Severity Count**: Isolates and counts issues marked with `HIGH` severity status.
    *   **Remediation Progress**: A progress percentage of total vulnerabilities moved to `TICKET_OPENED` status, displayed using a clean, modern loading bar.
*   **Telemetry Table**: List of security issues detailing detection tool, vulnerability name, severity badges, ticketing status, and code file-path mapping.
*   **Expandable Analysis Drawers**: Clicking any finding unfolds a drawer containing the vulnerability description, along with the AI-generated `root_cause` and `remediation_plan` generated dynamically by the Gemini analyzer module.
*   **Live Refresher**: Interactive reload button to sync the UI state directly with the active FastAPI server without page reloads.

## Project Setup

### Prerequisites
*   Node.js 18+
*   FastAPI backend running locally at `http://127.0.0.1:8000`

### Installation & Run
1. Navigate to the dashboard directory:
   ```bash
   cd linesec-dashboard
   ```
2. Install npm dependencies:
   ```bash
   npm install
   ```
3. Boot the development server:
   ```bash
   npm run dev
   ```
Open `http://localhost:3000` in your web browser to view the active security dashboard.
