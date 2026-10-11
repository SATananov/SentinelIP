from datetime import datetime

import pytest

from services.change_models import (
    ChangeConfidence,
    ChangeModelError,
    ChangeRecord,
    ChangeType,
)


def make_change(**overrides):
    values = {
        "change_type": ChangeType.NEW_DEVICE,
        "device_id": 1,
        "network_id": 2,
        "observed_at": datetime(2026, 10, 11, 12, 0, 0),
        "source": "device-inventory",
        "confidence": ChangeConfidence.HIGH,
        "evidence_type": "DEVICE_OBSERVATION",
        "message": "A device was observed for the first time.",
    }
    values.update(overrides)
    return ChangeRecord(**values)


def test_change_model_normalizes_constrained_values():
    change = make_change(
        change_type="IP_CHANGED",
        confidence="high",
        previous_value={"ip": "192.168.1.20"},
        current_value={"ip": "192.168.1.21"},
    )

    assert change.change_type is ChangeType.IP_CHANGED
    assert change.confidence is ChangeConfidence.HIGH
    assert change.previous_value["ip"] == "192.168.1.20"


@pytest.mark.parametrize(
    "field_values",
    [
        {"change_type": "UNKNOWN"},
        {"confidence": "CRITICAL"},
        {"source": ""},
        {"evidence_type": ""},
        {"message": ""},
        {"device_id": 0},
    ],
)
def test_change_model_rejects_invalid_values(field_values):
    with pytest.raises(ChangeModelError):
        make_change(**field_values)


def test_change_model_accepts_optional_references_and_metadata():
    change = make_change(
        port_id=4,
        service_id=5,
        correlation_key="device:1:port:4",
        metadata_json={"reason": "state transition"},
    )

    assert change.port_id == 4
    assert change.service_id == 5
    assert change.metadata_json["reason"] == "state transition"