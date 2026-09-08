# LineSec Core — Ingestion, Intelligence, Policy & Verification Engine

LineSec Core is the high-performance DevSecOps backend engine of the **LineSec 2+** platform. Built with **FastAPI**, **PostgreSQL**, and **SQLAlchemy**, it provides context-aware vulnerability ingestion, deterministic risk scoring, policy gating, AI reasoning, manifest patching, SLA governance, and post-fix verification.

---

## 🌟 Key Capabilities

### 1. Canonical Identity & Deduplication (`core/fingerprint.py`)
- Computes stable SHA-256 coordinates across `(repository, scanner, rule_id, file_path, line_number, package, ecosystem)`.
- Eliminates duplicate findings on repeated rescans while preserving first-seen and last-seen timestamps.
- Detects regressions automatically if a previously resolved vulnerability reappears.

### 2. Strict Finite State Machine (`core/lifecycle.py`)
- Enforces an 11-state deterministic lifecycle transition matrix:
  $$\text{NEW} \to \text{TRIAGED} \to \text{ANALYZED} \to \text{REMEDIATION\_PENDING} \to \text{IN\_PROGRESS} \to \text{VERIFICATION\_PENDING} \to \text{RESOLVED} \mid \text{FAILED} \mid \text{REGRESSED}$$
- Prevents invalid state jumps and supports backward-compatible legacy statuses (`TICKET_OPENED`).

### 3. Multi-Scanner Adapters & SARIF 2.1.0 (`adapters/`)
- **Bandit Adapter (`adapters/bandit.py`)**: Parses Python static analysis results into canonical SAST findings.
- **Trivy Adapter (`adapters/trivy.py`)**: Normalizes Software Composition Analysis (SCA) dependencies, packages, installed/fixed versions, container image flaws, and misconfigurations.
- **SARIF 2.1.0 Adapter (`adapters/sarif.py`)**: Full OASIS SARIF 2.1.0 import and export for GitHub Code Scanning and CI/CD pipelines.

### 4. Vulnerability Intelligence & Context Engine (`intel/`, `core/context.py`)
- **EPSS Provider (`intel/epss.py`)**: Queries FIRST.org Exploit Prediction Scoring System ($0.0 - 1.0$) with in-memory TTL caching and offline fallback.
- **CISA KEV Provider (`intel/cisa_kev.py`)**: Identifies active in-the-wild weaponized vulnerabilities from the CISA catalog.
- **Environment & Asset Exposure (`core/context.py`)**: Models environment (`production`, `staging`, `development`), asset criticality (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`), and internet exposure.

### 5. Deterministic Risk & Policy Engine (`core/risk.py`, `core/policy.py`)
- **Explainable 0–100 Risk Score**:
  $$\text{Risk} = \text{Clamp}_{0}^{100}\Big(\big(\text{BaseSeverity} + \text{Exploitability}\big) \times \text{ContextMultiplier} + \text{ExposureBonus}\Big)$$
- **Priority Bands**: Assigns actionable priority tiers: `P0` (Critical/Emergency), `P1` (High), `P2` (Medium), `P3` (Low).
- **Policy Engine**: Evaluates repository posture against declarative governance rules to output actionable CI/CD gates (`PASS`, `WARN`, `BLOCK`).

### 6. Resilient AI Analysis & Prompt-Injection Defense (`ai/`)
- **Prompt Sanitizer (`ai/sanitizer.py`)**: Sanitizes untrusted scanner outputs, strips prompt injection markers, and builds strictly structured prompts.
- **Dual-Provider Architecture**:
  - `GeminiAIProvider`: Google Gemini reasoning client configured with structured JSON schema output mode.
  - `DeterministicFallbackProvider`: Rule-based deterministic engine that produces structured remediation decisions when LLMs are offline or unconfigured.

### 7. Automated Remediation & Manifest Patcher (`core/safety.py`, `services/patcher.py`, `services/planner.py`)
- **Safety Classifier**: Evaluates semver upgrade distance, breaking change risk, and deployment risk to output `SAFE`, `APPROVAL_REQUIRED`, `MANUAL`, or `BLOCKED`.
- **Manifest Patcher**: Safely updates `requirements.txt` and `package.json` without raw shell execution.
- **FixPlan Generator**: Formulates actionable upgrade plans with concrete verification recipes.

### 8. Verification & Security Diff Engine (`services/verification.py`)
- Compares findings before and after fix, categorizing issues into `RESOLVED`, `UNCHANGED`, `NEW`, and `REGRESSED`.
- Autonomous lifecycle promotion for tasks and findings based on rescan verification.

### 9. SLA Governance & Security Debt (`core/sla.py`, `services/posture.py`)
- Strict priority-based SLAs: `P0` (24h), `P1` (7d), `P2` (30d), `P3` (90d).
- Mean Time To Remediate (MTTR) calculation and formal Risk Acceptance waiver governance.

### 10. LineSec Developer CLI (`cli/main.py`)
- Zero-dependency CLI utility for scanning, CI/CD policy gating, and verification diffing.

---

## 🚀 Setup & Execution

### Prerequisites
- Python 3.10+
- PostgreSQL 15+ (or SQLite for development/testing)

### Installation
```bash
cd linesec-core
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Running the API Server
```bash
uvicorn main:app --reload --port 8000
```
*API interactive documentation is available at `http://127.0.0.1:8000/docs`.*

---

## 📡 API Reference Overview

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/health` | API & database health status |
| `POST` | `/api/v1/ingest/batch` | Ingest batch of normalized findings with deduplication stats |
| `POST` | `/api/v1/adapters/bandit/import` | Ingest raw Bandit SAST scan JSON |
| `POST` | `/api/v1/adapters/trivy/import` | Ingest raw Trivy SCA/Container scan JSON |
| `POST` | `/api/v1/adapters/sarif/import` | Import OASIS SARIF 2.1.0 scan report |
| `GET` | `/api/v1/adapters/sarif/export` | Export repository findings as SARIF 2.1.0 |
| `POST` | `/api/v1/tasks/group` | Cluster unassigned findings into remediation tasks |
| `GET` | `/api/v1/tasks` | List all remediation tasks |
| `GET` | `/api/v1/tasks/{task_id}` | Retrieve task details with linked findings |
| `POST` | `/api/v1/tasks/{task_id}/analyze` | AI/fallback reasoning and task decision analysis |
| `POST` | `/api/v1/tasks/{task_id}/plan` | Formulate structured FixPlan & safety level |
| `POST` | `/api/v1/tasks/{task_id}/remediate` | Generate PR branch metadata & commit instructions |
| `POST` | `/api/v1/tasks/{task_id}/verify` | Autonomous post-fix verification against rescan |
| `POST` | `/api/v1/verification/diff` | Calculate security diff between baseline and rescan |
| `POST` | `/api/v1/risk/evaluate` | Deterministic risk evaluation for repository findings |
| `POST` | `/api/v1/policy/evaluate` | Evaluate repository posture against CI/CD policy gates |
| `GET` | `/api/v1/posture` | Live security score (0-100), debt hours & progress |
| `GET` | `/api/v1/posture/sla` | SLA compliance breakdown, breached tasks & MTTR |
| `POST` | `/api/v1/risk-acceptance` | Grant formal risk acceptance waiver |
| `GET` | `/api/v1/risk-acceptance` | List all risk acceptance records |
| `GET` | `/api/v1/audit` | Query immutable system audit logs |

---

## 🧪 Testing

Execute the test suite with:
```bash
./venv/bin/pytest -v
```
