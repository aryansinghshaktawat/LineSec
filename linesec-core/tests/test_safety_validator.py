import pytest
from core.safety import SafetyValidator, SafetyLevel

def test_safety_validator_minor_patch_upgrade():
    # Minor/patch version upgrade in development/staging is SAFE
    level = SafetyValidator.classify_safety(
        action="upgrade",
        current_version="1.2.0",
        target_version="1.2.1",
        priority="P2",
        deployment_risk="LOW",
        environment="development"
    )
    assert level == SafetyLevel.SAFE

def test_safety_validator_major_upgrade_requires_approval():
    # Major version upgrade (e.g. 1.2.0 to 2.0.0) must require APPROVAL_REQUIRED
    level = SafetyValidator.classify_safety(
        action="upgrade",
        current_version="1.2.0",
        target_version="2.0.0",
        priority="P2",
        deployment_risk="LOW",
        environment="development"
    )
    assert level == SafetyLevel.APPROVAL_REQUIRED

def test_safety_validator_high_deployment_risk_requires_approval():
    # Minor upgrade with HIGH deployment risk must require APPROVAL_REQUIRED
    level = SafetyValidator.classify_safety(
        action="upgrade",
        current_version="1.2.0",
        target_version="1.2.1",
        priority="P2",
        deployment_risk="HIGH",
        environment="development"
    )
    assert level == SafetyLevel.APPROVAL_REQUIRED

def test_safety_validator_production_p0_requires_approval():
    # Production P0 with MEDIUM or HIGH deployment risk requires APPROVAL_REQUIRED
    level = SafetyValidator.classify_safety(
        action="upgrade",
        current_version="1.2.0",
        target_version="1.2.1",
        priority="P0",
        deployment_risk="MEDIUM",
        environment="production"
    )
    assert level == SafetyLevel.APPROVAL_REQUIRED

def test_safety_validator_manual_action():
    # Non-upgrade actions (refactoring, removal) are MANUAL
    level = SafetyValidator.classify_safety(
        action="refactor",
        current_version="1.0.0",
        target_version="1.1.0"
    )
    assert level == SafetyLevel.MANUAL

def test_safety_validator_unpinned_target_requires_approval():
    # If target version is latest-secure or missing, require approval
    level = SafetyValidator.classify_safety(
        action="upgrade",
        current_version="1.0.0",
        target_version="latest-secure"
    )
    assert level == SafetyLevel.APPROVAL_REQUIRED
