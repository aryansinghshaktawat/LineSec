import pytest
from core.lifecycle import (
    FindingStatus,
    validate_finding_transition,
    InvalidStateTransitionError
)

def test_valid_lifecycle_transitions():
    """Verify normal progression transitions succeed."""
    assert validate_finding_transition("NEW", "TRIAGED") is True
    assert validate_finding_transition("TRIAGED", "ANALYZED") is True
    assert validate_finding_transition("ANALYZED", "REMEDIATION_PENDING") is True
    assert validate_finding_transition("REMEDIATION_PENDING", "IN_PROGRESS") is True
    assert validate_finding_transition("IN_PROGRESS", "VERIFICATION_PENDING") is True
    assert validate_finding_transition("VERIFICATION_PENDING", "RESOLVED") is True
    assert validate_finding_transition("RESOLVED", "REGRESSED") is True

def test_legacy_status_normalization():
    """Verify legacy 'OPEN' status maps cleanly to 'NEW'."""
    assert validate_finding_transition("OPEN", "ANALYZED") is True
    assert validate_finding_transition("ANALYZED", "TICKET_OPENED") is True

def test_illegal_lifecycle_transitions():
    """Verify invalid arbitrary state jumps raise InvalidStateTransitionError."""
    with pytest.raises(InvalidStateTransitionError):
        # Cannot jump straight from NEW to RESOLVED without verification
        validate_finding_transition("NEW", "RESOLVED")

    with pytest.raises(InvalidStateTransitionError):
        # Cannot jump from RESOLVED back to IN_PROGRESS directly without regression
        validate_finding_transition("RESOLVED", "IN_PROGRESS")
