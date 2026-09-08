# LineSec

LineSec is a cybersecurity platform composed of three integrated components
for security scanning, vulnerability visualization, and automated remediation.

## Projects

### 1. LineSec Core

Backend security analysis and vulnerability ingestion engine.

**Location:** `linesec-core/`

### 2. LineSec Dashboard

Web-based dashboard for viewing and analyzing security findings.

**Location:** `linesec-dashboard/`

### 3. LineSec Remediation

Automated remediation service that creates GitHub issues for identified
security findings.

**Location:** `linesec-remediation/`

## Architecture

```text
                    LineSec
                       |
        +--------------+--------------+
        |              |              |
        v              v              v
   Core Engine     Dashboard      Remediation
        |              |              |
        v              v              v
   Security Scan    Findings       GitHub Issues
