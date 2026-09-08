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




