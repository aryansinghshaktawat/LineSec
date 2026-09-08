import hashlib
from typing import Optional

def generate_finding_fingerprint(
    repository: str,
    scanner: str,
    vulnerability_identifier: str,
    file_path: Optional[str] = None,
    line_number: Optional[int] = None,
    package: Optional[str] = None,
    ecosystem: Optional[str] = None,
    scanner_type: Optional[str] = None
) -> str:
    """
    Generates a stable, deterministic SHA-256 fingerprint for a vulnerability finding.
    
    Uses finding-type-aware coordinate hashing:
    - SCA / Dependency: repository + ecosystem + package + vulnerability_identifier
    - SAST / Code: repository + scanner + vulnerability_identifier + normalized_file_path + line
    - Container: repository + package + vulnerability_identifier + file_path
    - Secret / Config: repository + scanner + vulnerability_identifier + normalized_file_path
    """
    norm_repo = (repository or "default").strip().lower()
    norm_scanner = (scanner or "unknown").strip().lower()
    norm_vuln = (vulnerability_identifier or "unknown").strip().lower()
    norm_file = (file_path or "").strip().lower().lstrip("./").lstrip("/")
    norm_pkg = (package or "").strip().lower()
    norm_eco = (ecosystem or "").strip().lower()
    norm_type = (scanner_type or "SAST").strip().upper()

    if norm_type in ("SCA", "DEPENDENCY") or (norm_pkg and norm_eco):
        # SCA coordinate
        raw_key = f"sca:{norm_repo}:{norm_eco or 'generic'}:{norm_pkg}:{norm_vuln}"
    elif norm_type in ("CONTAINER", "IMAGE"):
        # Container coordinate
        raw_key = f"container:{norm_repo}:{norm_file}:{norm_pkg}:{norm_vuln}"
    elif norm_type in ("SECRET", "CONFIG"):
        # Secret coordinate (line shifts don't change identity)
        raw_key = f"secret:{norm_repo}:{norm_scanner}:{norm_vuln}:{norm_file}"
    else:
        # SAST / Code coordinate
        norm_line = str(line_number if line_number is not None and line_number > 0 else 0)
        raw_key = f"sast:{norm_repo}:{norm_scanner}:{norm_vuln}:{norm_file}:{norm_line}:{norm_pkg}:{norm_eco}"

    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()

generate_canonical_fingerprint = generate_finding_fingerprint
