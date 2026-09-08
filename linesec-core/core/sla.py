from datetime import datetime, timezone
from typing import Optional, Dict, Any, List, Tuple

def utc_now():
    return datetime.now(timezone.utc)

SLA_HOURS_BY_PRIORITY = {
    "P0": 24.0,     # Critical: 24 hours
    "P1": 168.0,    # High: 7 days (168h)
    "P2": 720.0,    # Medium: 30 days (720h)
    "P3": 2160.0    # Low: 90 days (2160h)
}

class SLAManager:
    """
    Deterministic SLA tracking and MTTR computation engine for vulnerability lifecycles.
    """

    @staticmethod
    def get_target_hours(priority: str) -> float:
        return SLA_HOURS_BY_PRIORITY.get(priority.upper(), 720.0)

    @classmethod
    def calculate_sla_status(
        cls,
        priority: str,
        created_at: datetime,
        resolved_at: Optional[datetime] = None,
        now: Optional[datetime] = None
    ) -> Dict[str, Any]:
        target_hours = cls.get_target_hours(priority)
        current_ts = now or utc_now()

        # Handle timezone naive vs aware
        if created_at.tzinfo is None:
            created_at = created_at.replace(tzinfo=timezone.utc)
        if resolved_at and resolved_at.tzinfo is None:
            resolved_at = resolved_at.replace(tzinfo=timezone.utc)

        end_time = resolved_at or current_ts
        elapsed_hours = max(0.0, (end_time - created_at).total_seconds() / 3600.0)
        remaining_hours = max(0.0, target_hours - elapsed_hours)
        is_breached = elapsed_hours > target_hours

        if resolved_at:
            status = "RESOLVED_ON_TIME" if not is_breached else "RESOLVED_BREACHED"
        else:
            if is_breached:
                status = "BREACHED"
            elif elapsed_hours >= (0.75 * target_hours):
                status = "APPROACHING_BREACH"
            else:
                status = "ON_TRACK"

        return {
            "priority": priority.upper(),
            "target_hours": target_hours,
            "elapsed_hours": round(elapsed_hours, 2),
            "remaining_hours": round(remaining_hours, 2),
            "status": status,
            "is_breached": is_breached
        }

    @staticmethod
    def calculate_mttr(resolved_durations_hours: List[float]) -> float:
        """Computes Mean Time To Remediate (MTTR) in hours."""
        if not resolved_durations_hours:
            return 0.0
        return round(sum(resolved_durations_hours) / len(resolved_durations_hours), 2)
