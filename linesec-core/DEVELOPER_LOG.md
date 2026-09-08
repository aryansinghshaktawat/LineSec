# Developer Log: LineSec Core

## Day 1 Architecture: FastAPI + PostgreSQL
On Day 1, we set up the core foundation of **LineSec**, a modular security platform.
The architecture consists of:
*   **FastAPI**: A modern, fast (high-performance) web framework for building APIs with Python. It handles our HTTP endpoints (like `/health` and `/api/ingest`), input validation via **Pydantic** schemas, and automatic API documentation.
*   **PostgreSQL**: A powerful, open-source object-relational database system used to persist the security findings.
*   **SQLAlchemy**: The Object Relational Mapper (ORM) that acts as a translator between our Python code/objects and the database.
*   **Lifespan Events**: FastAPI automatically initializes and creates our database tables on startup.
*   **Ingest Endpoint**: Exposes a `POST /api/ingest` endpoint to receive normalized lists of vulnerabilities and save them to the PostgreSQL `findings` table.

---

## Day 2 Goal: Bandit Parser Engine
On Day 2, we introduce automated scanning capabilities:
*   **Static Application Security Testing (SAST)**: We integrate **Bandit**, a tool designed to find common security issues in Python code.
*   **Bandit Parser Engine (`bandit_runner.py`)**: A Python utility that:
    1. Runs Bandit programmatically against the codebase (`bandit -r . -f json`).
    2. Parses the JSON output in memory.
    3. Normalizes Bandit's raw findings into our LineSec-compliant `FindingCreate` schema format.
    4. Automatically transmits (ingests) these normalized findings to the local FastAPI backend using HTTP POST requests.

---

## LineSec 2+ Phase 1: Canonical Domain Foundation & Fingerprinting Engine
In LineSec 2+ Phase 1, we transformed the data and ingestion foundation into a production-grade DevSecOps platform:
*   **Deterministic Fingerprinting (`core/fingerprint.py`)**: Computes stable SHA-256 hashes across scanner, rule, file path, line number, and package coordinates. Eliminates finding duplication across rescans.
*   **Finite State Machine (`core/lifecycle.py`)**: Enforces strict lifecycle state transitions (`NEW` → `TRIAGED` → `ANALYZED` → `REMEDIATION_PENDING` → `IN_PROGRESS` → `VERIFICATION_PENDING` → `RESOLVED` / `FAILED` / `REGRESSED`). Prevents illegal state jumps.
*   **Domain Models (`models.py`)**: Added relational entities for `Repository`, `Scan`, `RemediationTask`, `TaskDecision`, `FixPlan`, `Policy`, `AuditEvent`, `RiskAcceptance`, and `VulnerabilityIntel` while preserving 100% backward compatibility for legacy queries and dashboard integrations.
*   **Ingestion Service (`services/ingestion.py`)**: Separated route handling from business logic. Ingestion deduplicates findings automatically, updates `last_seen` timestamps, detects regressions for reappearing vulnerabilities, and creates an audit trail.
*   **Extended API Endpoints (`main.py`)**:
    *   `POST /api/v1/ingest/batch`: Returns comprehensive ingestion stats (new, existing, regressed).
    *   `GET /api/v1/posture`: Computes live security score (0-100), estimated security debt hours, and remediation progress.
    *   `GET /api/v1/audit`: Returns immutable system audit logs.

---

## LineSec 2+ Phase 2: Unified Scanner Adapters & Remediation Task Grouping Engine
In LineSec 2+ Phase 2, we built the multi-scanner ingestion layer and intelligent vulnerability grouping engine:
*   **Abstract Scanner Adapter (`adapters/base.py`)**: Defines standard interface `ScannerAdapter` with `parse_raw()` returning canonical `FindingCreate` schemas.
*   **Bandit SAST Adapter (`adapters/bandit.py`)**: Parses Python static analysis results into canonical SAST findings.
*   **Trivy SCA/Container Adapter (`adapters/trivy.py`)**: Normalizes Software Composition Analysis (SCA) dependencies, packages, installed/fixed versions, container image flaws, and misconfigurations.
*   **SARIF 2.1.0 Engine (`adapters/sarif.py`)**: Provides full OASIS SARIF 2.1.0 import and export for CI/CD and GitHub Code Scanning integration.
*   **Remediation Task Grouping Engine (`services/grouping.py`)**: Intelligently clusters multiple open findings sharing a package and ecosystem (or file and scanner) into a single actionable `RemediationTask`. Automatically calculates target fixed versions and sets task priority (`P0` - `P3`).
*   **Phase 2 Endpoints (`main.py`)**:
    *   `POST /api/v1/adapters/bandit/import`: Ingest raw Bandit JSON scans.
    *   `POST /api/v1/adapters/trivy/import`: Ingest raw Trivy SCA/Container JSON scans.
    *   `POST /api/v1/adapters/sarif/import`: Import SARIF 2.1.0 reports.
    *   `GET /api/v1/adapters/sarif/export`: Export database findings as SARIF 2.1.0.
    *   `POST /api/v1/tasks/group`: Group unassigned findings into tasks.
    *   `GET /api/v1/tasks`: List all remediation tasks with linked finding counts.
    *   `GET /api/v1/tasks/{task_id}`: Retrieve detailed task specifications with linked findings.

---

## LineSec 2+ Phase 3: Vulnerability Intelligence, Context Engine & Deterministic Risk/Policy Engine
In LineSec 2+ Phase 3, we built the contextual intelligence and deterministic decision engines:
*   **Modular Intelligence Layer (`intel/`)**:
    *   `EPSSProvider`: Fetches exploit prediction scores ($0.0 - 1.0$) and percentiles from FIRST.org with local TTL caching and graceful offline fallback.
    *   `CISAKEVProvider`: Queries CISA Known Exploited Vulnerabilities catalog for active weaponization in the wild.
    *   `OSVProvider`: Retrieves package ecosystem advisories and fix data from OSV.dev.
    *   `IntelligenceManager`: Coordinates batch enrichment across providers.
*   **Context Engine (`core/context.py`)**: Models environment (`production`, `staging`, `development`), asset criticality (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`), internet exposure, and data sensitivity.
*   **Deterministic Risk Scoring Engine (`core/risk.py`)**: Computes an explainable 0–100 risk score and assigns priority bands (`P0`, `P1`, `P2`, `P3`) using a deterministic formula combining Base Severity, Exploitability (CISA KEV + EPSS), Asset Exposure, and Context Multipliers.
*   **Policy Engine (`core/policy.py`)**: Evaluates repository posture against declarative governance rules to output actionable CI/CD gates (`PASS`, `WARN`, `BLOCK`).
*   **Phase 3 Endpoints (`main.py`)**:
    *   `POST /api/v1/intel/enrich`: Enriches findings with EPSS & CISA KEV intelligence.
    *   `POST /api/v1/risk/evaluate`: Runs deterministic risk evaluation on findings.
    *   `POST /api/v1/policy/evaluate`: Runs policy gate evaluation for CI/CD pipelines.

---

## LineSec 2+ Phase 4: Resilient AI Analysis Layer & Task Decisions
In LineSec 2+ Phase 4, we engineered the AI analysis layer with prompt injection protection and deterministic fallback resilience:
*   **Prompt Sanitization Engine (`ai/sanitizer.py`)**: Sanitizes untrusted scanner outputs, filters prompt injection directives, escapes Markdown/HTML injection tags, and builds strictly structured prompts.
*   **Multi-Provider AI Hierarchy (`ai/`)**:
    *   `GeminiAIProvider`: Google Gemini reasoning client configured with structured JSON schema output mode.
    *   `DeterministicFallbackProvider`: Rule-based deterministic engine that produces structured remediation decisions when LLMs are offline, rate-limited, or unconfigured.
*   **AI Analysis Service (`ai/service.py`)**: Orchestrates the fallback pipeline, persists `TaskDecision` entities, updates finding remediation plans, and logs audit events.
*   **Phase 4 Endpoints (`main.py`)**:
    *   `POST /api/v1/tasks/{task_id}/analyze`: Analyzes a specific remediation task.
    *   `POST /api/v1/tasks/analyze-all`: Batch analyzes all pending tasks.

## LineSec 2+ Phase 5: Automated Remediation Engine & Manifest Patching
In LineSec 2+ Phase 5, we implemented automated remediation planning and safe manifest patching:
*   **Safety Classification Engine (`core/safety.py`)**: Deterministically categorizes remediation actions into `SAFE`, `APPROVAL_REQUIRED`, `MANUAL`, or `BLOCKED` using semantic version analysis, deployment risk, and environment context.
*   **Manifest Patcher (`services/patcher.py`)**: Safely updates package versions in `requirements.txt` and `package.json` with regex and AST parsing without shelling out or corrupting manifests.
*   **Remediation Planner (`services/planner.py`)**: Generates structured `FixPlan` records containing target versions, safety levels, explainable rationale, and concrete verification steps.
*   **Phase 5 Endpoints (`main.py`)**:
    *   `POST /api/v1/tasks/{task_id}/plan`: Generates or updates a deterministic `FixPlan` for a task.
    *   `POST /api/v1/tasks/{task_id}/remediate`: Generates PR metadata, safety validation, branch name, and commit/verification payload (supporting `dry_run=true/false`).

---

## LineSec 2+ Phase 6: Verification & Security Diff Engine
In LineSec 2+ Phase 6, we implemented post-fix verification and scan comparison:
*   **Security Diff Service (`services/verification.py`)**: Compares finding sets before and after remediation, categorizing results into `RESOLVED`, `UNCHANGED`, `NEW`, and `REGRESSED`.
*   **Verification Engine (`services/verification.py`)**: Evaluates rescan results against active remediation tasks, promotes tasks to `RESOLVED` or `FAILED`, updates individual finding statuses, and records immutable audit logs.
*   **Phase 6 Endpoints (`main.py`)**:
    *   `POST /api/v1/verification/diff`: Computes security diff and pass/fail gate verdict between database baseline and rescan findings.
    *   `POST /api/v1/tasks/{task_id}/verify`: Executes autonomous task verification against rescan results.

---

## LineSec 2+ Phase 7: Security Posture, Debt & SLA Management
In LineSec 2+ Phase 7, we built enterprise SLA governance and posture compliance tracking:
*   **Deterministic SLA Manager (`core/sla.py`)**: Defines priority-based remediation targets (`P0`: 24h, `P1`: 7d, `P2`: 30d, `P3`: 90d), tracks breach warnings (`APPROACHING_BREACH` at 75% elapsed), and calculates Mean Time to Remediate (MTTR).
*   **Risk Acceptance Engine (`services/posture.py`)**: Supports formal exception waivers with expiration dates and rationale, temporarily suppressing SLA breach alerts and posture scoring penalties.
*   **Phase 7 Endpoints (`main.py`)**:
    *   `GET /api/v1/posture/sla`: Computes active SLA breaches, approaching breaches, MTTR, and priority breakdown.
    *   `POST /api/v1/risk-acceptance`: Grants formal risk acceptance waivers.
    *   `GET /api/v1/risk-acceptance`: Retrieves all active and historical waivers.

---

## LineSec 2+ Phase 8: LineSec Developer CLI & CI/CD Gating
In LineSec 2+ Phase 8, we implemented the standalone developer CLI:
*   **CLI Application (`cli/main.py`)**: Zero-external-dependency CLI supporting standalone execution, local code scanning, report parsing, risk scoring, SARIF 2.1.0 and JSON exports.
*   **CI/CD Policy Gate Runner (`linesec policy test`)**: Evaluates scan reports against security policies and returns standardized exit codes (0 for PASS/WARN, 1 for BLOCK) for GitHub Actions and GitLab CI.
*   **Security Diff Engine CLI (`linesec verify`)**: Compares baseline and rescan outputs to verify vulnerability eradication and catch regressions.

---

## LineSec 2+ Phase 9: Enterprise Dashboard Upgrade
In LineSec 2+ Phase 9, we upgraded the Next.js React frontend (`linesec-dashboard`):
*   **Security Posture & SLA Ribbon**: Live Security Score (0–100), estimated security debt in developer hours, MTTR, and SLA breach tracking (`P0` 24h, `P1` 7d, `P2` 30d).
*   **Multi-View Navigation Tabs**: Vulnerabilities table, Remediation Task clusters, Verification Diff viewer, and formal Risk Acceptance governance.
*   **One-Click Workflows**: Interactive task clustering, PR dispatch, and automated rescan verification.

---

## LineSec 2+ Phase 10: Enterprise Hardening & Full Pipeline Integration
In LineSec 2+ Phase 10, we conducted rigorous end-to-end integration and security validation:
*   **Full Lifecycle Verification (`tests/test_e2e_pipeline.py`)**: Validates the end-to-end flow: Ingestion $\to$ Canonical Fingerprint Deduplication $\to$ Task Clustering $\to$ EPSS/KEV Risk Evaluation $\to$ Policy Gate Evaluation $\to$ AI/Deterministic Fallback Decision $\to$ FixPlan & Safety $\to$ Automated Remediation $\to$ Post-Fix Rescan Diff $\to$ Verification & SLA Resolution.
*   **100% Backward Compatibility**: Verified seamless coexistence with existing microservices (`bandit_runner.py`, `ticket_creator.py`, legacy dashboard routes).
*   **62/62 Test Suite Passing**: Comprehensive coverage across unit, adapter, policy, SLA, CLI, and integration layers.





