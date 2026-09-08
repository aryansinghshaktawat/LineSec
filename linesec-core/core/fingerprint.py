import hashlib
from typing import Optional

def generate_finding_fingerprint(
    repository: str,
    scanner: str,
    vulnerability_identifier: str,
    file_path: Optional[str] = None,
    line_number: Optional[int] = None,
    package: Optional[str] = None,
    ecosystem: Optional[str] = None
) -> str:
    """
    Generates a stable, deterministic SHA-256 fingerprint for a vulnerability finding.
    
    A finding fingerprint is scanner-independent and resistant to non-semantic variances
    (such as whitespace, relative path prefixes, or scan timestamp changes).
    """
    norm_repo = (repository or "default").strip().lower()
    norm_scanner = (scanner or "unknown").strip().lower()
    norm_vuln = (vulnerability_identifier or "unknown").strip().lower()
    norm_file = (file_path or "").strip().lower().lstrip("./").lstrip("/")
    norm_line = str(line_number if line_number is not None and line_number > 0 else 0)
    norm_pkg = (package or "").strip().lower()
    norm_eco = (ecosystem or "").strip().lower()

    # Canonical composition string
    components = [
        norm_repo,
        norm_scanner,
        norm_vuln,
        norm_file,
        norm_line,
        norm_pkg,
        norm_eco
    ]
    
    raw_key = ":".join(components)
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()
