from dataclasses import replace
from datetime import datetime, timezone
import pytest
from services.incident_models import IncidentError, IncidentCorrelation, build_incident

AT = datetime(2026, 10, 12, 8, 0, tzinfo=timezone.utc)


def correlation(correlation_id=1, correlation_type="SSH_AUTH_ACTIVITY_PATTERN"):
    if correlation_type == "SSH_AUTH_ACTIVITY_PATTERN":
        return IncidentCorrelation(correlation_id, correlation_type, "PATTERN", "MEDIUM", "HIGH", AT, AT,
            "Authentication pattern review.", "correlation.ssh_auth_activity", "1",
            (("THREAT", 1), ("THREAT", 2)), source_ip="192.168.1.20")
    return IncidentCorrelation(correlation_id, "WEB_CREDENTIAL_ACTIVITY_CHAIN", "CHAIN_REVIEW", "MEDIUM", "MEDIUM",
        AT, AT, "Web credential activity review.", "correlation.web_credential_activity", "1",
        (("THREAT", 3), ("WEB_DETECTION", 4)), sensor_id=7, hostname="example.test")


def test_authentication_review_is_bounded_and_non_confirming():
    candidate = build_incident((correlation(),), AT)
    assert candidate.incident_type.value == "AUTHENTICATION_REVIEW"
    assert candidate.status.value == "OPEN"
    assert candidate.priority.value == "MEDIUM"
    assert "does not establish" in candidate.reason.lower()
    assert "successful access" in candidate.reason.lower()


def test_web_review_does_not_confirm_phishing_or_malware():
    candidate = build_incident((correlation(2, "WEB_CREDENTIAL_ACTIVITY_CHAIN"),), AT)
    assert candidate.incident_type.value == "WEB_ACTIVITY_REVIEW"
    assert "does not confirm phishing" in candidate.reason.lower()
    assert "malware" in candidate.reason.lower()


def test_mixed_review_is_explicit_not_causal():
    candidate = build_incident((correlation(2, "WEB_CREDENTIAL_ACTIVITY_CHAIN"), correlation(1)), AT)
    assert candidate.incident_type.value == "MULTI_SIGNAL_REVIEW"
    assert "does not establish causality" in candidate.reason.lower()


def test_stable_key_is_order_independent():
    left, right = correlation(1), correlation(2, "WEB_CREDENTIAL_ACTIVITY_CHAIN")
    assert build_incident((left, right), AT).stable_key == build_incident((right, left), AT).stable_key


def test_invalid_or_duplicate_correlation_rejected():
    item = correlation()
    with pytest.raises(IncidentError):
        build_incident((item, item), AT)
    with pytest.raises(IncidentError):
        replace(item, severity="HIGH")
