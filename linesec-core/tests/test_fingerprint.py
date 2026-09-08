import pytest
from core.fingerprint import generate_finding_fingerprint

def test_fingerprint_determinism():
    """Verify identical parameters produce identical SHA-256 fingerprints."""
    fp1 = generate_finding_fingerprint(
        repository="linesec-core",
        scanner="bandit",
        vulnerability_identifier="B104_hardcoded_bind_all_interfaces",
        file_path="app/main.py",
        line_number=45,
        package="fastapi",
        ecosystem="pip"
    )
    fp2 = generate_finding_fingerprint(
        repository="linesec-core",
        scanner="bandit",
        vulnerability_identifier="B104_hardcoded_bind_all_interfaces",
        file_path="app/main.py",
        line_number=45,
        package="fastapi",
        ecosystem="pip"
    )
    assert fp1 == fp2
    assert len(fp1) == 64  # SHA-256 length

def test_fingerprint_path_normalization():
    """Verify relative paths with ./ or leading slashes are normalized identically."""
    fp1 = generate_finding_fingerprint(
        repository="repo",
        scanner="bandit",
        vulnerability_identifier="B101",
        file_path="./src/utils.py",
        line_number=10
    )
    fp2 = generate_finding_fingerprint(
        repository="repo",
        scanner="bandit",
        vulnerability_identifier="B101",
        file_path="/src/utils.py",
        line_number=10
    )
    fp3 = generate_finding_fingerprint(
        repository="repo",
        scanner="bandit",
        vulnerability_identifier="B101",
        file_path="src/utils.py",
        line_number=10
    )
    assert fp1 == fp2 == fp3

def test_fingerprint_uniqueness():
    """Verify distinct findings yield different fingerprints."""
    fp1 = generate_finding_fingerprint("repo", "bandit", "B101", "src/a.py", 10)
    fp2 = generate_finding_fingerprint("repo", "bandit", "B102", "src/a.py", 10)
    fp3 = generate_finding_fingerprint("repo", "bandit", "B101", "src/b.py", 10)
    assert fp1 != fp2
    assert fp1 != fp3
