from datetime import datetime, timezone, timedelta
import pytest
from core.sla import SLAManager

def test_sla_manager_target_hours():
    assert SLAManager.get_target_hours("P0") == 24.0
    assert SLAManager.get_target_hours("P1") == 168.0
    assert SLAManager.get_target_hours("P2") == 720.0
    assert SLAManager.get_target_hours("P3") == 2160.0

def test_sla_status_on_track():
    now = datetime(2026, 9, 8, 12, 0, 0, tzinfo=timezone.utc)
    created_at = now - timedelta(hours=5) # 5 hours ago for P0 (24h target)
    res = SLAManager.calculate_sla_status(priority="P0", created_at=created_at, now=now)
    assert res["status"] == "ON_TRACK"
    assert res["is_breached"] is False
    assert res["elapsed_hours"] == 5.0
    assert res["remaining_hours"] == 19.0

def test_sla_status_approaching_breach():
    now = datetime(2026, 9, 8, 12, 0, 0, tzinfo=timezone.utc)
    created_at = now - timedelta(hours=20) # 20 hours for P0 (target 24h, >75% is >18h)
    res = SLAManager.calculate_sla_status(priority="P0", created_at=created_at, now=now)
    assert res["status"] == "APPROACHING_BREACH"
    assert res["is_breached"] is False

def test_sla_status_breached():
    now = datetime(2026, 9, 8, 12, 0, 0, tzinfo=timezone.utc)
    created_at = now - timedelta(hours=30) # 30 hours for P0 (target 24h)
    res = SLAManager.calculate_sla_status(priority="P0", created_at=created_at, now=now)
    assert res["status"] == "BREACHED"
    assert res["is_breached"] is True
    assert res["remaining_hours"] == 0.0

def test_sla_resolved_metrics():
    now = datetime(2026, 9, 8, 12, 0, 0, tzinfo=timezone.utc)
    created_at = now - timedelta(hours=10)
    resolved_at = now - timedelta(hours=2) # Took 8 hours
    res = SLAManager.calculate_sla_status(priority="P0", created_at=created_at, resolved_at=resolved_at, now=now)
    assert res["status"] == "RESOLVED_ON_TIME"
    assert res["is_breached"] is False
    assert res["elapsed_hours"] == 8.0

def test_mttr_calculation():
    durations = [4.0, 8.0, 12.0]
    mttr = SLAManager.calculate_mttr(durations)
    assert mttr == 8.0
