from dataclasses import FrozenInstanceError, replace
import pytest
from services.web_detection_models import WebDetectionError
from services.web_detection_rules import evaluate_rules
from test_web_detection_rules import AT, evidence


def detection():
    return evaluate_rules(evidence(has_password_form=True), (), AT)[0]


def test_immutable_model_and_stable_identity():
    first = detection()
    with pytest.raises(FrozenInstanceError):
        first.hostname = "other.test"
    with pytest.raises(FrozenInstanceError):
        first.evidence[0].hostname = "other.test"
    assert first.stable_key == replace(first, reason="Review explanation.").stable_key
    assert first.stable_key != replace(first, rule_version="2").stable_key


@pytest.mark.parametrize("changes", [{"state": "PHISHING_CONFIRMED"}, {"severity": "HIGH"},
    {"confidence": "HIGH"}, {"primary_observation_id": 99}, {"evidence": []}, {"sensor_id": 2},
    {"hostname": "other.test"}, {"rule_id": ""}, {"first_seen": "invalid"}])
def test_invalid_detection(changes):
    with pytest.raises(ValueError):
        replace(detection(), **changes)


@pytest.mark.parametrize("changes", [{"observation_id": 0}, {"sensor_id": True}, {"source": "dns"},
    {"has_password_form": "false"}, {"hostname": "https://example.test"}, {"tab_id": 1},
    {"observed_at": AT.replace(tzinfo=None)}])
def test_invalid_evidence(changes):
    with pytest.raises(ValueError):
        evidence(**changes)
