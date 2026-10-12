from dataclasses import replace
from datetime import datetime, timedelta, timezone
import pytest
from services.correlation_models import CorrelationEntity
from services.correlation_rules import correlate_ssh, correlate_web

AT = datetime(2026, 1, 1, tzinfo=timezone.utc)


def ssh_entity(number=1, kind="SUSPICIOUS_AUTH_ACTIVITY", **changes):
    values = dict(entity_type="THREAT", entity_id=number, signal_type=kind, state="SUSPECTED", severity="MEDIUM",
                  confidence="HIGH" if kind == "SSH_BRUTE_FORCE_THREAT" else "MEDIUM", entity_timestamp=AT,
                  first_seen=AT, rule_id="threat.ssh", rule_version="1", reason="Authentication review.",
                  source_evidence_type="SSH_EVENT", source_evidence_id=number, source_ip="192.0.2.10")
    values.update(changes)
    return CorrelationEntity(**values)


def web_entities():
    threat = CorrelationEntity("THREAT", 1, "WEB_CREDENTIAL_FLOW_THREAT", "SUSPECTED", "MEDIUM", "MEDIUM",
        AT, AT, "threat.web_credential_flow", "1", "Review credential flow.", "WEB_DETECTION", 5,
        sensor_id=1, hostname="login.example.test", browser_session_id="session", tab_id="tab",
        primary_observation_id=2, observation_ids=(1, 2))
    web = replace(threat, entity_type="WEB_DETECTION", entity_id=5, signal_type="CROSS_DOMAIN_LOGIN_REDIRECT",
                  state="REVIEW", source_evidence_type="WEB_OBSERVATION", source_evidence_id=2)
    download = replace(web, entity_id=6, signal_type="SUSPICIOUS_DOWNLOAD_FLOW", primary_observation_id=3,
                       source_evidence_id=3, observation_ids=(2, 3), entity_timestamp=AT+timedelta(seconds=20))
    return threat, web, download


def test_ssh_pair_and_order_independent_identity():
    left, right = ssh_entity(), ssh_entity(2, "SSH_BRUTE_FORCE_THREAT")
    first = correlate_ssh(left, right, AT)
    assert first == correlate_ssh(right, left, AT)
    assert (first.state, first.severity, first.confidence) == ("PATTERN", "MEDIUM", "HIGH")
    assert correlate_ssh(left, ssh_entity(3), AT) is None


@pytest.mark.parametrize("changes", [{"source_ip": "192.0.2.11"}, {"device_id": 1}, {"sensor_id": 1},
    {"entity_timestamp": AT+timedelta(seconds=301)}, {"entity_timestamp": AT.replace(tzinfo=None)}, {"confidence": "LOW"}])
def test_ssh_boundaries(changes):
    assert correlate_ssh(ssh_entity(), ssh_entity(2, "SSH_BRUTE_FORCE_THREAT", **changes), AT) is None


def test_inclusive_ssh_window():
    assert correlate_ssh(ssh_entity(), ssh_entity(2, "SSH_BRUTE_FORCE_THREAT", entity_timestamp=AT+timedelta(minutes=5)), AT)


def test_web_requires_anchor_and_can_include_linked_download():
    threat, web, download = web_entities()
    assert correlate_web(threat, (), AT) is None
    assert correlate_web(threat, (download,), AT) is None
    first = correlate_web(threat, (web, download), AT)
    assert first == correlate_web(threat, (download, web), AT)
    assert (first.state, first.severity, first.confidence) == ("CHAIN_REVIEW", "MEDIUM", "MEDIUM")
    assert len(first.entities) == 3


@pytest.mark.parametrize("changes", [{"browser_session_id": "other"}, {"tab_id": "other"}, {"tab_id": None},
    {"sensor_id": 2}, {"device_id": 2}, {"entity_timestamp": AT+timedelta(seconds=301)}])
def test_web_boundaries(changes):
    threat, web, _ = web_entities()
    assert correlate_web(threat, (replace(web, **changes),), AT) is None


def test_session_only_and_missing_session():
    threat, web, _ = web_entities()
    assert correlate_web(replace(threat, tab_id=None), (replace(web, tab_id=None),), AT)
    assert correlate_web(replace(threat, browser_session_id=None), (replace(web, browser_session_id=None),), AT) is None


def test_exact_device_is_required_but_not_sufficient_without_links():
    threat, web, _ = web_entities()
    assert correlate_web(replace(threat, device_id=4), (replace(web, device_id=4),), AT)
    assert correlate_web(replace(threat, device_id=4), (web,), AT) is None
    assert correlate_web(threat, (replace(web, entity_id=99),), AT) is None


def test_download_outside_window_is_not_added():
    threat, web, download = web_entities()
    result = correlate_web(threat, (web, replace(download, entity_timestamp=AT+timedelta(seconds=301))), AT)
    assert len(result.entities) == 2
