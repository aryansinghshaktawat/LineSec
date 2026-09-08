# LineSec 2+ — Context-Aware DevSecOps Vulnerability Management & Automated Remediation Platform

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-009688.svg?logo=fastapi)](https://fastapi.tiangolo.com)
[![Next.js 16](https://img.shields.io/badge/Next.js-16.2-black.svg?logo=next.js)](https://nextjs.org/)
[![SARIF 2.1.0](https://img.shields.io/badge/OASIS-SARIF_2.1.0-blue.svg)](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)

**LineSec 2+** is a production-oriented, context-aware DevSecOps vulnerability management, automated remediation, and verification platform.

Unlike traditional vulnerability scanners that simply dump alerts on developers, LineSec answers the six critical questions of engineering security:
> **1. What is wrong?** (Canonical detection across SAST, SCA, Container, and SARIF 2.1.0)  
> **2. Why does it matter?** (Explainable 0–100 risk score combining Base Severity, EPSS, CISA KEV exploitation, asset exposure, and environmental context)  
> **3. What should we fix first?** (Deterministic priority bands `P0`–`P3` and strict SLA governance)  
> **4. Why?** (Deterministic policy gates evaluating `PASS` / `WARN` / `BLOCK` for CI/CD pipelines)  
> **5. How can we safely fix it?** (Automated task clustering, semantic `FixPlan` generation, AST manifest patching, and safety classification)  
> **6. Did the fix work without regressions?** (Post-fix test execution, rescan diffing, and automated lifecycle promotion)

---

## 🏗️ Monorepo Architecture

```text
                               ┌─────────────────────────────────────────┐
                               │           LineSec 2+ Platform           │
                               └────────────────────┬────────────────────┘
                                                    │
         ┌──────────────────────────────────────────┼──────────────────────────────────────────┐
         │                                          │                                          │
         ▼                                          ▼                                          ▼
┌──────────────────┐                       ┌──────────────────┐                       ┌──────────────────┐
│   linesec-core   │                       │linesec-dashboard │                       │linesec-remediat. │
├──────────────────┤                       ├──────────────────┤                       ├──────────────────┤
│• FastAPI Backend │                       │• Next.js App Rtr │                       │• GitHub PR/Issue │
│• Deduplication   │ ◄───────────────────► │• Posture Ribbon  │ ◄───────────────────► │  Automation      │
│• EPSS & CISA KEV │                       │• 4-Tab Analytics │                       │• PyGithub Sync   │
│• Risk & Policy   │                       │• FixPlan Drawer  │                       │• Lifecycle State │
│• Safety & Planner│                       │• Security Diff   │                       │  Promotion       │
│• Verification    │                       │• SLA Governance  │                       │                  │
│• Developer CLI   │                       └──────────────────┘                       └──────────────────┘
└──────────────────┘
```

---

## 🔄 End-to-End Vulnerability Lifecycle

```text
       DETECT (Bandit SAST / Trivy SCA / SARIF 2.1.0)
                           ↓
          NORMALIZE (Canonical Coordinate Identity)
                           ↓
     DEDUPLICATE (Stable SHA-256 Fingerprint Engine)
                           ↓
         GROUP (Package & File Task Clustering)
                           ↓
   ENRICH (EPSS Exploit Prediction & CISA KEV Exploitation)
                           ↓
     RISK SCORE (Deterministic 0–100 Explainable Scoring)
                           ↓
       POLICY GATE (Deterministic PASS / WARN / BLOCK)
                           ↓
     AI REASONING (Gemini Structured Mode + Deterministic Fallback)
                           ↓
      REMEDIATION PLAN (Semantic FixPlan & AST Patching)
                           ↓
     SAFETY VALIDATION (SAFE / APPROVAL_REQUIRED / MANUAL)
                           ↓
                 PR CREATION & DISPATCH
                           ↓
             POST-FIX RESCAN & SECURITY DIFF
                           ↓
     LIFECYCLE PROMOTION (RESOLVED / FAILED / REGRESSED)
                           ↓
          SLA GOVERNANCE & AUDIT TRAIL LOGGING
```

---

## ⚡ Core Modules

### 1. [`linesec-core`](./linesec-core) — Ingestion, Intelligence, Policy & Verification Engine
- **Deterministic Fingerprinting (`core/fingerprint.py`)**: Stable SHA-256 coordinates across tool, rule, file path, line number, package, and ecosystem.
- **Finite State Machine (`core/lifecycle.py`)**: Strict 11-state transition matrix (`NEW` $\to$ `TRIAGED` $\to$ `ANALYZED` $\to$ `REMEDIATION_PENDING` $\to$ `IN_PROGRESS` $\to$ `VERIFICATION_PENDING` $\to$ `RESOLVED` / `FAILED` / `REGRESSED`).
- **Unified Adapters (`adapters/`)**: Native ingestion for Bandit SAST, Trivy SCA/Container, and OASIS SARIF 2.1.0 reports.
- **Vulnerability Intelligence (`intel/`)**: Real-time EPSS percentile lookups and CISA KEV catalog check with resilient TTL caching.
- **Deterministic Risk Engine (`core/risk.py`)**: Explainable 0–100 scoring using base severity, exploitability, asset exposure, and environment multipliers.
- **Policy Engine (`core/policy.py`)**: Declarative CI/CD security gate evaluation producing `PASS`, `WARN`, or `BLOCK` actions.
- **Safety Classification (`core/safety.py`)**: Classifies remediation into `SAFE`, `APPROVAL_REQUIRED`, `MANUAL`, or `BLOCKED`.
- **Manifest Patcher (`services/patcher.py`)**: Safely updates `requirements.txt` and `package.json` with AST and regex parsing.
- **Verification & Diff Engine (`services/verification.py`)**: Compares pre-fix and post-fix scans, categorizing findings into `RESOLVED`, `UNCHANGED`, `NEW`, and `REGRESSED`.
- **SLA Manager (`core/sla.py`)**: Computes priority-based deadlines (`P0`: 24h, `P1`: 7d, `P2`: 30d, `P3`: 90d), breach warnings, MTTR, and formal Risk Acceptance waivers.
- **Developer CLI (`cli/main.py`)**: Zero-dependency CLI for offline scanning, CI/CD policy gating, and verification diffing.

### 2. [`linesec-dashboard`](./linesec-dashboard) — Enterprise Single-Pane-of-Glass
- **App Router & Tailwind CSS**: Glassmorphic dark UI with live polling and responsive navigation.
- **Posture & SLA Ribbon**: Live Security Score (0–100), security debt hours, MTTR, and SLA breach counters.
- **Vulnerabilities View**: Detailed table with deterministic priority badges (`P0`–`P3`), risk score gauges, and AI Root Cause drawers.
- **Remediation Task Manager**: Clustered CVE views, target version bumps, safety classification tags, and one-click PR actions.
- **Verification Diffs**: Visual security rescan comparisons displaying resolved vs regressed issues.
- **SLA Governance**: Interactive interface to inspect breach timers and grant formal Risk Acceptance waivers.

### 3. [`linesec-remediation`](./linesec-remediation) — Autonomous Action & PR Dispatch
- **GitHub API Integration**: Automated ticket and issue generation with PyGithub.
- **Structured Issue Formatting**: Markdown reports containing CVE metadata, stack traces, AI root-cause analysis, and verified remediation recipes.
- **Database Synchronization**: Updates finding lifecycle states to `TICKET_OPENED` / `PR_OPENED` in real time.

---

## 🚀 Quick Start

### 1. Start the Core Backend
```bash
cd linesec-core
source venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```
*API documentation available at `http://127.0.0.1:8000/docs`.*

### 2. Launch the Web Dashboard
```bash
cd linesec-dashboard
npm install
npm run dev
```
*Open `http://localhost:3000` to view the security portal.*

### 3. Run the LineSec Developer CLI
```bash
# Run local scan and print risk table
./linesec-core/cli/main.py scan .

# Run CI/CD policy gate test
./linesec-core/cli/main.py policy test -f scan_results.json -e production

# Compare pre-fix and post-fix scans
./linesec-core/cli/main.py verify -b baseline.json -r rescan.json
```

---

## 🧪 Testing & Verification

LineSec 2+ features a comprehensive test suite with **62 automated tests** covering unit logic, scanner adapters, risk calculations, policy gates, AI fallback resilience, manifest patchers, verification diffs, SLA calculations, CLI commands, and end-to-end pipelines.

```bash
cd linesec-core
./venv/bin/pytest -v
```

---

## 📜 License
LineSec is licensed under the [MIT License](LICENSE).
