from datetime import datetime

import pytest

from services.finding_models import (
    FindingConfidence,
    FindingModelError,
    FindingRecord,
    FindingSeverity,
    FindingStatus,
    FindingType,
)


def make_finding(**overrides):
    values = {
        "finding_type": FindingType.PLAINTEXT_SERVICE,
        "device_id": 1,
        "network_id": 1,
        "severity": FindingSeverity.HIGH,
        "confidence": FindingConfidence.HIGH,
        "status": FindingStatus.OPEN,
        "title": "Plaintext service",
        "reason": "Explicit plaintext service evidence was observed.",
        "recommendation": "Review and replace the service with an encrypted alternative.",
        "evidence_type": "SERVICE_OBSERVATION",
        "source": "risk-engine",
        "rule_id": "risk.plaintext.telnet",
        "rule_version": "1",
        "stable_key": "device:1:plaintext:port:4:risk.plaintext.telnet:1",
        "first_seen": datetime(2026, 10, 11, 12, 0, 0),
        "last_seen": datetime(2026, 10, 11, 12, 0, 0),
    }
    values.update(overrides)
    return FindingRecord(**values)


def test_finding_model_normalizes_constrained_values():
    finding = make_finding(
        finding_type="plaintext_service",
        severity="high",
        confidence="high",
        status="open",
    )

    assert finding.finding_type is FindingType.PLAINTEXT_SERVICE
    assert finding.severity is FindingSeverity.HIGH
    assert finding.confidence is FindingConfidence.HIGH
    assert finding.status is FindingStatus.OPEN


@pytest.mark.parametrize(
    "field_values",
    [
        {"finding_type": "UNKNOWN"},
        {"severity": "CRITICAL"},
        {"confidence": "UNKNOWN"},
        {"status": "INVALID"},
        {"stable_key": ""},
        {"rule_id": ""},
    ],
)
def test_finding_model_rejects_invalid_values(field_values):
    with pytest.raises(FindingModelError):
        make_finding(**field_values)


def test_finding_model_accepts_optional_references_and_metadata():
    finding = make_finding(
        port_id=4,
        service_id=5,
        change_id=6,
        metadata={"explicit": True},
    )

    assert finding.port_id == 4
    assert finding.service_id == 5
    assert finding.change_id == 6