from dataclasses import FrozenInstanceError, replace
import pytest
from services.correlation_rules import correlate_ssh
from test_correlation_rules import ssh_entity, AT


def record():
    return correlate_ssh(ssh_entity(), ssh_entity(2, "SSH_BRUTE_FORCE_THREAT"), AT)


def test_frozen_order_independent_key():
    candidate = record()
    with pytest.raises(FrozenInstanceError):
        candidate.entities[0].reason = "changed"
    assert replace(candidate, entities=tuple(reversed(candidate.entities))).stable_key == candidate.stable_key
    assert replace(candidate, rule_version="2").stable_key != candidate.stable_key


@pytest.mark.parametrize("changes", [{"state": "CONFIRMED_INCIDENT"}, {"severity": "HIGH"}, {"entities": []},
    {"entities": (ssh_entity(),)}, {"primary_entity_id": 99}, {"rule_version": ""}, {"last_seen": "bad"}])
def test_invalid_model(changes):
    with pytest.raises(ValueError):
        replace(record(), **changes)


@pytest.mark.parametrize("changes", [{"entity_id": True}, {"source_ip": "example.test"},
    {"entity_timestamp": "bad"}, {"observation_ids": [1]}, {"sensor_id": 0}])
def test_invalid_entity(changes):
    with pytest.raises(ValueError):
        ssh_entity(**changes)
