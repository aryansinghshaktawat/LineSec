from enum import Enum
from typing import Set, Dict

class FindingStatus(str, Enum):
    NEW = "NEW"
    TRIAGED = "TRIAGED"
    ANALYZED = "ANALYZED"
    REMEDIATION_PENDING = "REMEDIATION_PENDING"
    IN_PROGRESS = "IN_PROGRESS"
    VERIFICATION_PENDING = "VERIFICATION_PENDING"
    RESOLVED = "RESOLVED"
    FAILED = "FAILED"
    REGRESSED = "REGRESSED"
    RISK_ACCEPTED = "RISK_ACCEPTED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    TICKET_OPENED = "TICKET_OPENED"  # Backward compatibility state

class TaskStatus(str, Enum):
    PENDING = "PENDING"
    ANALYZED = "ANALYZED"
    APPROVED = "APPROVED"
    IN_PROGRESS = "IN_PROGRESS"
    PR_OPENED = "PR_OPENED"
    VERIFIED = "VERIFIED"
    FAILED = "FAILED"
    RESOLVED = "RESOLVED"

# Finite State Machine: allowed source -> set of valid target states
ALLOWED_FINDING_TRANSITIONS: Dict[FindingStatus, Set[FindingStatus]] = {
    FindingStatus.NEW: {
        FindingStatus.TRIAGED,
        FindingStatus.ANALYZED,
        FindingStatus.FALSE_POSITIVE,
        FindingStatus.RISK_ACCEPTED,
        FindingStatus.TICKET_OPENED
    },
    FindingStatus.TRIAGED: {
        FindingStatus.ANALYZED,
        FindingStatus.REMEDIATION_PENDING,
        FindingStatus.FALSE_POSITIVE,
        FindingStatus.RISK_ACCEPTED,
        FindingStatus.TICKET_OPENED,
        FindingStatus.RESOLVED
    },
    FindingStatus.ANALYZED: {
        FindingStatus.REMEDIATION_PENDING,
        FindingStatus.IN_PROGRESS,
        FindingStatus.TICKET_OPENED,
        FindingStatus.RISK_ACCEPTED,
        FindingStatus.FALSE_POSITIVE,
        FindingStatus.RESOLVED
    },
    FindingStatus.TICKET_OPENED: {
        FindingStatus.REMEDIATION_PENDING,
        FindingStatus.IN_PROGRESS,
        FindingStatus.VERIFICATION_PENDING,
        FindingStatus.RESOLVED,
        FindingStatus.FAILED,
        FindingStatus.REGRESSED,
        FindingStatus.RISK_ACCEPTED
    },
    FindingStatus.REMEDIATION_PENDING: {
        FindingStatus.IN_PROGRESS,
        FindingStatus.TICKET_OPENED,
        FindingStatus.RISK_ACCEPTED,
        FindingStatus.FALSE_POSITIVE,
        FindingStatus.RESOLVED
    },
    FindingStatus.IN_PROGRESS: {
        FindingStatus.VERIFICATION_PENDING,
        FindingStatus.FAILED,
        FindingStatus.RESOLVED
    },
    FindingStatus.VERIFICATION_PENDING: {
        FindingStatus.RESOLVED,
        FindingStatus.FAILED,
        FindingStatus.REGRESSED
    },
    FindingStatus.RESOLVED: {
        FindingStatus.REGRESSED
    },
    FindingStatus.FAILED: {
        FindingStatus.REMEDIATION_PENDING,
        FindingStatus.ANALYZED,
        FindingStatus.IN_PROGRESS
    },
    FindingStatus.REGRESSED: {
        FindingStatus.TRIAGED,
        FindingStatus.ANALYZED,
        FindingStatus.REMEDIATION_PENDING,
        FindingStatus.TICKET_OPENED
    },
    FindingStatus.RISK_ACCEPTED: {
        FindingStatus.TRIAGED,
        FindingStatus.ANALYZED,
        FindingStatus.NEW
    },
    FindingStatus.FALSE_POSITIVE: {
        FindingStatus.TRIAGED,
        FindingStatus.NEW
    }
}

class InvalidStateTransitionError(ValueError):
    """Raised when an illegal lifecycle transition is attempted."""
    pass

def validate_finding_transition(current_status: str, target_status: str) -> bool:
    """
    Validates if transitioning from current_status to target_status is permitted.
    Normalizes input strings into FindingStatus enum values.
    """
    # Normalize legacy or lowercase statuses
    normalized_curr = current_status.upper()
    if normalized_curr == "OPEN":
        normalized_curr = "NEW"
    
    normalized_tgt = target_status.upper()
    if normalized_tgt == "OPEN":
        normalized_tgt = "NEW"

    try:
        curr_enum = FindingStatus(normalized_curr)
        tgt_enum = FindingStatus(normalized_tgt)
    except ValueError as e:
        raise InvalidStateTransitionError(f"Invalid status value: {e}")

    # No-op transition is allowed
    if curr_enum == tgt_enum:
        return True

    allowed_targets = ALLOWED_FINDING_TRANSITIONS.get(curr_enum, set())
    if tgt_enum not in allowed_targets:
        raise InvalidStateTransitionError(
            f"Illegal state transition from '{curr_enum.value}' to '{tgt_enum.value}'. "
            f"Allowed transitions: {[s.value for s in allowed_targets]}"
        )
    return True
