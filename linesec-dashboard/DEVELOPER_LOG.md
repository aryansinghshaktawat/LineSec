# Developer Log: LineSec Dashboard

## Frontend State Architecture
The **LineSec Dashboard** (`linesec-dashboard`) is a modern React SPA built using **Next.js** (App Router) and **Tailwind CSS**. It communicates directly with our FastAPI backend (`http://127.0.0.1:8000/api/findings`) to render real-time security posture analytics.

### Architecture & Components:
1.  **State Management**:
    *   `findings` (Array of objects): Stores the collection of vulnerabilities retrieved from the `/api/findings` API.
    *   `loading` (Boolean): Controls the state spinner when fetching data from the database.
    *   `error` (String | Null): Captures database or HTTP communication failures (e.g. backend offline).
    *   `expandedId` (String | Null): Tracks which table row is currently expanded to show deep AI analysis details.
2.  **Hooks**:
    *   `useEffect`: Automatically fires on page mount to query findings from the API.
    *   `useState`: Manages client-side reactivity and toggling details.
3.  **Metrics Processing**:
    *   Total vulnerabilities are derived from `findings.length`.
    *   Severity counts are calculated dynamically in-memory using array filters (e.g., `severity === 'CRITICAL'`).
    *   Remediation progress calculates the percentage of findings marked with `TICKET_OPENED` status out of the total.
4.  **UI/UX Details**:
    *   **Tailwind CSS**: Custom dark mode layout using deep slate backgrounds and glassmorphic panels.
    *   **Lucide React**: Modern iconography used for cards (Activity, Shield, CheckCircle) and tables.
    *   **Expandable Rows**: Clicking any finding reveals a nested panel highlighting the AI-generated `root_cause` and `remediation_plan` fields.

---

## LineSec 2+ Enterprise Dashboard Upgrade
In LineSec 2+, the dashboard was upgraded to support full vulnerability management lifecycle visibility:
*   **Security Posture & SLA Ribbon**: Live Security Score (0-100), estimated security debt in developer hours, MTTR, and SLA breach tracking (`P0` 24h, `P1` 7d, `P2` 30d).
*   **Multi-View Navigation Tabs**:
    1.  **Vulnerabilities**: Displays canonical findings with deterministic Risk Score (0-100), Priority badge (`P0`–`P3`), CVSS/CVE details, and expandable AI root cause / guidance panels.
    2.  **Remediation Tasks & FixPlans**: Visualizes grouped dependency clusters, target upgrade bumps, safety validation levels (`SAFE`, `APPROVAL_REQUIRED`, `MANUAL`), and one-click "Open PR" / "Verify Fix" actions.
    3.  **Security Diffs & Verification**: Pre- and post-fix scan comparison showing Resolved, Remaining, New Introduced, and Regressed vulnerabilities.
    4.  **SLA Governance & Waivers**: SLA compliance timers and interactive form to grant formal Risk Acceptance waivers.

