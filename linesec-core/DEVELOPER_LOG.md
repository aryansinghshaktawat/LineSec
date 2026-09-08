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
