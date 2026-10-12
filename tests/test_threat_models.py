from dataclasses import FrozenInstanceError, replace
import pytest
from services.threat_models import ThreatState
from services.threat_rules import evaluate_ssh
from test_threat_rules import AT, ssh


def candidate():
    rows = tuple(ssh(i+1, i) for i in range(5))
    return evaluate_ssh(rows[-1], rows, AT)


def test_immutable_identity_and_unavailable_confirmation():
    record = candidate()
    with pytest.raises(FrozenInstanceError):
        record.reason = "changed"
    with pytest.raises(ValueError):
        ThreatState("CONFIRMED")
    assert replace(record, reason="Review.").stable_key == record.stable_key
    assert replace(record, rule_version="2").stable_key != record.stable_key


@pytest.mark.parametrize("changes", [{"state": "CONFIRMED"}, {"severity": "CRITICAL"}, {"evidence": []},
    {"primary_evidence_id": 999}, {"anchor_id": 999}, {"rule_id": ""}, {"last_seen": "bad"},
    {"threat_type": "MALWARE"}])
def test_invalid_threat(changes):
    with pytest.raises(ValueError):
        replace(candidate(), **changes)


@pytest.mark.parametrize("changes", [{"evidence_id": True}, {"event_count": 0}, {"source_ip": "example.test"},
    {"event_type": "PROCESS_EXECUTION"}, {"timestamp": "bad"}, {"username": {"password": "value"}}])
def test_invalid_ssh_evidence(changes):
    with pytest.raises(ValueError):
        ssh(**changes)


def test_web_evidence_deep_immutability_and_snapshot_projection():
    from test_threat_rules import web_pair
    anchor, _ = web_pair()
    with pytest.raises(FrozenInstanceError):
        anchor.observations[0].hostname = "other.test"
    assert not {"url", "path", "metadata_json", "credentials"} & anchor.snapshot().keys()
    with pytest.raises(ValueError):
        replace(anchor, observations=list(anchor.observations))
    with pytest.raises(ValueError):
        replace(anchor, primary_observation_id=999)
