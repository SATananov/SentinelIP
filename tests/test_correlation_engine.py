from datetime import timedelta
import pytest
from database.correlations import list_correlations
from database.db import get_connection
from services.correlation_engine import CorrelationEngine
from services.correlation_models import CorrelationError
from services.threat_engine import ThreatEngine
from services.web_detection_engine import WebDetectionEngine
from test_correlation_rules import AT
from test_threat_engine import persist_ssh, web_scenario


def ssh_pair(path, *, other_source="192.0.2.10", delay=0, naive=False):
    start = AT.replace(tzinfo=None) if naive else AT
    preauth = persist_ssh(path, 3, kind="SSH_PREAUTH", start=start)
    failed = persist_ssh(path, 5, source=other_source, start=start+timedelta(seconds=delay))
    suspicious, = ThreatEngine(path).evaluate_ssh_event(preauth[-1], evaluated_at=AT)
    brute, = ThreatEngine(path).evaluate_ssh_event(failed[-1], evaluated_at=AT+timedelta(days=5))
    return suspicious, brute


def web_chain(path, download=False):
    observations, cross = web_scenario(path)
    if download:
        WebDetectionEngine(path).evaluate_observation(observations[3], evaluated_at=AT)
    threat, = ThreatEngine(path).evaluate_web_detection(cross["id"], evaluated_at=AT)
    return observations, cross, threat


def test_ssh_evaluation_uses_observed_times_and_deduplicates_both_directions(tmp_path):
    path = tmp_path / "test.db"
    suspicious, brute = ssh_pair(path)
    engine = CorrelationEngine(path)
    first, = engine.evaluate_threat(suspicious["id"], evaluated_at=AT)
    second, = engine.evaluate_threat(brute["id"], evaluated_at=AT+timedelta(minutes=1))
    assert first["id"] == second["id"] and first["first_seen"] == second["first_seen"]
    assert first["last_seen"] < second["last_seen"]
    assert (first["state"], first["severity"], first["confidence"]) == ("PATTERN", "MEDIUM", "HIGH")
    assert {e["entity_id"] for e in first["entities"]} == {suspicious["id"], brute["id"]}
    assert len(list_correlations(path)) == 1


@pytest.mark.parametrize("source,delay,expected", [("192.0.2.11", 0, False), ("192.0.2.10", 298, True), ("192.0.2.10", 299, False)])
def test_persisted_ssh_source_and_window(source, delay, expected, tmp_path):
    path = tmp_path / "test.db"
    suspicious, _ = ssh_pair(path, other_source=source, delay=delay)
    assert bool(CorrelationEngine(path).evaluate_threat(suspicious["id"])) == expected


def test_single_threat_is_not_a_pattern(tmp_path):
    path = tmp_path / "test.db"
    ids = persist_ssh(path, 3)
    threat, = ThreatEngine(path).evaluate_ssh_event(ids[-1])
    assert CorrelationEngine(path).evaluate_threat(threat["id"]) == []


def test_legacy_naive_clock_is_preserved(tmp_path):
    path = tmp_path / "test.db"
    suspicious, _ = ssh_pair(path, naive=True)
    record, = CorrelationEngine(path).evaluate_threat(suspicious["id"])
    assert all("+00:00" not in e["entity_timestamp"] for e in record["entities"])


def test_web_chain_follows_existing_links(tmp_path):
    path = tmp_path / "test.db"
    _, cross, threat = web_chain(path, download=True)
    engine = CorrelationEngine(path)
    first, = engine.evaluate_threat(threat["id"], evaluated_at=AT)
    second, = engine.evaluate_web_detection(cross["id"], evaluated_at=AT)
    assert first == second and len(first["entities"]) == 3
    assert (first["state"], first["severity"], first["confidence"]) == ("CHAIN_REVIEW", "MEDIUM", "MEDIUM")
    assert {e["entity_type"] for e in first["entities"]} == {"THREAT", "WEB_DETECTION"}


def test_unlinked_download_does_not_enter_existing_chain(tmp_path):
    path = tmp_path / "test.db"
    observations, _, threat = web_chain(path)
    download, = WebDetectionEngine(path).evaluate_observation(observations[3], evaluated_at=AT)
    engine = CorrelationEngine(path)
    assert engine.evaluate_web_detection(download["id"]) == []
    result, = engine.evaluate_threat(threat["id"])
    assert len(result["entities"]) == 2


def test_added_participant_creates_distinct_history_without_overwriting(tmp_path):
    path = tmp_path / "test.db"
    observations, cross, threat = web_chain(path)
    engine = CorrelationEngine(path)
    original, = engine.evaluate_threat(threat["id"])
    WebDetectionEngine(path).evaluate_observation(observations[3], evaluated_at=AT)
    ThreatEngine(path).evaluate_web_detection(cross["id"])
    updated, = engine.evaluate_threat(threat["id"])
    assert original["stable_key"] != updated["stable_key"]
    assert len(list_correlations(path)) == 2


def test_missing_session_does_not_create_chain(tmp_path):
    from dataclasses import replace
    from database.telemetry import create_web_observation, provision_sensor
    from services.telemetry_models import WebObservation
    path = tmp_path / "test.db"
    sensor, _ = provision_sensor("no-session", "Browser", "BROWSER", None, "DOMAIN_ONLY", 30, path)
    row = create_web_observation(WebObservation("one", str(sensor["id"]), AT, "REDIRECT", "https://login.example.test",
        "DOMAIN_ONLY", redirect_from_domain="example.test", redirect_to_domain="login.example.test",
        has_password_form=True, received_at=AT, retention_until=AT+timedelta(days=30)), path)
    review, = WebDetectionEngine(path).evaluate_observation(row["id"])
    threat, = ThreatEngine(path).evaluate_web_detection(review["id"])
    assert CorrelationEngine(path).evaluate_threat(threat["id"]) == []


def test_bound_overflow_aborts_without_writes(tmp_path, monkeypatch):
    import services.correlation_engine as module
    path = tmp_path / "test.db"
    _, _, threat = web_chain(path, download=True)
    monkeypatch.setattr(module, "MAX_RELATED_ENTITIES", 1)
    with pytest.raises(CorrelationError, match="limit"):
        CorrelationEngine(path).evaluate_threat(threat["id"])
    assert list_correlations(path) == []


def test_deferred_types_and_bad_identity(tmp_path):
    engine = CorrelationEngine(tmp_path / "test.db")
    for kind in ("FINDING", "CHANGE", "CVE_MATCH", "SSH_EVENT"):
        assert engine.evaluate_entity(kind, 1) == []
    for identity in (True, 0, "1", 999):
        with pytest.raises(ValueError):
            engine.evaluate_threat(identity)
    with pytest.raises(ValueError):
        engine.evaluate_entity("INCIDENT", 1)
