from datetime import timedelta
import pytest
from database.db import get_connection, initialize_database, save_event
from database.threats import list_threats
from services.threat_engine import ThreatEngine
from services.threat_models import ThreatError
from test_threat_rules import AT


def persist_ssh(path, count=5, *, source="192.0.2.10", kind="LOGIN_FAILED", start=AT, username="ordinary"):
    initialize_database(path)
    ids = []
    for index in range(count):
        save_event((start+timedelta(seconds=index)).isoformat(), source, username, kind, "INFO",
                   "RAW_MESSAGE_SHOULD_NOT_BE_COPIED", index+1, path)
        with get_connection(path) as connection:
            ids.append(connection.execute("SELECT MAX(id) FROM events").fetchone()[0])
    return ids


def test_persisted_ssh_replay_and_success_preserve_history(tmp_path):
    path = tmp_path / "test.db"
    ids = persist_ssh(path)
    engine = ThreatEngine(path)
    assert engine.evaluate_ssh_event(ids[0]) == []
    first, = engine.evaluate_ssh_event(ids[-1], evaluated_at=AT)
    again, = engine.evaluate_ssh_event(ids[-1], evaluated_at=AT+timedelta(minutes=1))
    assert first["id"] == again["id"] and first["first_seen"] == again["first_seen"]
    assert first["last_seen"] < again["last_seen"]
    success = persist_ssh(path, 1, kind="LOGIN_SUCCESS", start=AT+timedelta(seconds=10))[0]
    assert engine.evaluate_ssh_event(success) == []
    assert len(list_threats(path)) == 1
    assert first["source_ip"] == "192.0.2.10" and first["device_id"] is None
    assert len(first["evidence"]) == 5
    assert "RAW_MESSAGE" not in str(first)


def test_sources_not_joined_and_running_count_not_summed(tmp_path):
    path = tmp_path / "test.db"
    persist_ssh(path, 4)
    other = persist_ssh(path, 1, source="192.0.2.11")[0]
    with get_connection(path) as connection:
        connection.execute("UPDATE events SET event_count=999 WHERE id=?", (other,))
    assert ThreatEngine(path).evaluate_ssh_event(other) == []


def test_legacy_naive_clock_supported(tmp_path):
    path = tmp_path / "test.db"
    ids = persist_ssh(path, start=AT.replace(tzinfo=None))
    result, = ThreatEngine(path).evaluate_ssh_event(ids[-1])
    assert result["threat_type"] == "SSH_BRUTE_FORCE_THREAT"
    assert result["evidence"][0]["snapshot"]["timestamp"] == "2026-01-01T00:00:00"


def test_invalid_identity_and_unknown_event(tmp_path):
    engine = ThreatEngine(tmp_path / "test.db")
    for identity in (0, True, "1", 999):
        with pytest.raises(ValueError):
            engine.evaluate_ssh_event(identity)
    with pytest.raises(ValueError):
        engine.evaluate_evidence("DNS_OBSERVATION", 1)


def test_bounded_evaluation_fails_without_partial_writes(tmp_path, monkeypatch):
    import services.threat_engine as module
    path = tmp_path / "test.db"
    ids = persist_ssh(path)
    monkeypatch.setattr(module, "MAX_RELATED_EVIDENCE", 4)
    with pytest.raises(ThreatError, match="limit"):
        ThreatEngine(path).evaluate_ssh_event(ids[-1])
    assert list_threats(path) == []


def web_scenario(path):
    from test_web_detection_integration import scenario
    from services.web_detection_engine import WebDetectionEngine
    ids = scenario(path)
    cross, = WebDetectionEngine(path).evaluate_observation(ids[2], evaluated_at=AT)
    return ids, cross


def test_web_strengthening_appends_to_same_threat(tmp_path):
    from services.web_detection_engine import WebDetectionEngine
    path = tmp_path / "test.db"
    ids, cross = web_scenario(path)
    engine = ThreatEngine(path)
    first, = engine.evaluate_web_detection(cross["id"], evaluated_at=AT)
    assert first["state"] == "SUSPECTED" and len(first["evidence"]) == 1
    download, = WebDetectionEngine(path).evaluate_observation(ids[3], evaluated_at=AT)
    second, = engine.evaluate_web_detection(download["id"], evaluated_at=AT+timedelta(minutes=1))
    assert first["id"] == second["id"] and first["first_seen"] == second["first_seen"]
    assert len(second["evidence"]) == 2
    assert second["confidence"] == "MEDIUM" and second["severity"] == "MEDIUM"
    assert len(list_threats(path)) == 1
    # Re-evaluation bookkeeping on source web reviews must not invalidate snapshots.
    WebDetectionEngine(path).evaluate_observation(ids[2], evaluated_at=AT+timedelta(minutes=2))
    assert engine.evaluate_web_detection(cross["id"])[0]["id"] == first["id"]


def test_web_evaluation_order_independent(tmp_path):
    from services.web_detection_engine import WebDetectionEngine
    path = tmp_path / "test.db"
    ids, cross = web_scenario(path)
    download, = WebDetectionEngine(path).evaluate_observation(ids[3], evaluated_at=AT)
    engine = ThreatEngine(path)
    first, = engine.evaluate_web_detection(download["id"], evaluated_at=AT)
    second, = engine.evaluate_web_detection(cross["id"], evaluated_at=AT)
    assert first == second and len(first["evidence"]) == 2


def test_download_without_cross_and_login_review_do_not_become_threats(tmp_path):
    from services.web_detection_engine import WebDetectionEngine
    from test_web_detection_integration import scenario
    path = tmp_path / "test.db"
    ids = scenario(path, session="different")
    login, = WebDetectionEngine(path).evaluate_observation(ids[2], evaluated_at=AT)
    download, = WebDetectionEngine(path).evaluate_observation(ids[3], evaluated_at=AT)
    assert ThreatEngine(path).evaluate_web_detection(login["id"]) == []
    assert ThreatEngine(path).evaluate_web_detection(download["id"]) == []


def test_assessment_categories_are_explicitly_deferred(tmp_path):
    engine = ThreatEngine(tmp_path / "test.db")
    for kind in ("FINDING", "CVE_MATCH", "CHANGE"):
        assert engine.evaluate_evidence(kind, 1) == []


def test_real_assessment_records_do_not_become_threats(tmp_path):
    from test_cve_correlation import setup_context, evidence
    from services.cve_correlation import CveCorrelationService
    from services.cve_models import CveRecord
    from database.findings import list_findings
    from services.risk_engine import RiskEngine
    path = tmp_path / "test.db"
    network, device, port, service = setup_context(path)
    RiskEngine(path).evaluate_device(device, network["id"])
    matches = CveCorrelationService(path).correlate(
        evidence(service["id"], device["id"], port["id"], "9.6"),
        [CveRecord("CVE-2099-0001", "local-test", "OpenSSH", ">=9.0,<9.7")],
    )
    engine = ThreatEngine(path)
    for finding in list_findings(path):
        assert engine.evaluate_evidence("FINDING", finding["id"]) == []
    for match in matches:
        assert engine.evaluate_evidence("CVE_MATCH", match["id"]) == []
    assert list_threats(path) == []


def test_deferred_download_can_be_evaluated_after_cross_review_is_persisted(tmp_path):
    from test_web_detection_integration import scenario
    from services.web_detection_engine import WebDetectionEngine
    path = tmp_path / "test.db"
    ids = scenario(path)
    download, = WebDetectionEngine(path).evaluate_observation(ids[3], evaluated_at=AT)
    assert ThreatEngine(path).evaluate_web_detection(download["id"]) == []
    cross, = WebDetectionEngine(path).evaluate_observation(ids[2], evaluated_at=AT)
    result, = ThreatEngine(path).evaluate_web_detection(download["id"])
    assert len(result["evidence"]) == 2 and result["primary_evidence_id"] == cross["id"]
