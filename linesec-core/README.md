# LineSec Core Ingestion Engine

LineSec Core is a high-performance DevSecOps ingestion engine built with FastAPI and PostgreSQL. It acts as the central ingestion point and data repository for the LineSec Security Platform, exposing secure endpoints to ingest, catalog, and query security vulnerabilities across multiple tools.

## Architecture & Features

*   **FastAPI Backend**: Built on modern, asynchronous Python primitives to guarantee sub-millisecond response times.
*   **PostgreSQL Persistence**: Utilizes SQLAlchemy ORM for structured relational storage, mapping scan findings dynamically.
*   **Automated Scanning Pipeline**: Designed for comprehensive **SAST/DAST aggregation**. It integrates security scanners like **Bandit** (Static Application Security Testing) to automatically scan codebases, filter out environment noise, and normalize raw security outputs.
*   **AI Reasoning Layer**: Configured to work in tandem with **google-genai** (Google Gemini) to analyze open vulnerabilities, outputting root-cause analysis and mitigation plans in structured JSON formats.
*   **CORS Enabled**: Configured to safely serve telemetry and ingestion data to frontend clients.

## Project Setup

### Prerequisites
*   Python 3.10+
*   PostgreSQL 15+

### Installation
1. Navigate to the core directory:
   ```bash
   cd linesec-core
   ```
2. Activate the virtual environment:
   ```bash
   source venv/bin/activate
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

### Running the Application
Spin up the FastAPI server via Uvicorn:
```bash
uvicorn main:app --reload
```
The server will boot on `http://127.0.0.1:8000`. You can check the health check endpoint at `/health`.

## API Endpoints

*   `GET /health`: Returns database and API availability health status.
*   `POST /api/ingest`: Accepts a normalized array of findings and persists them in the PostgreSQL database.
*   `GET /api/findings`: Retrieves all findings currently persisted in the database.
