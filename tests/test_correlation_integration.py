import socket
from datetime import timedelta
from database.correlations import list_correlations
from services.correlation_engine import CorrelationEngine
from services.threat_engine import ThreatEngine
from services.web_detection_engine import WebDetectionEngine
from test_correlation_engine import ssh_pair, web_chain
from test_correlation_rules import AT


def test_mocked_ssh_and_web_correlations_are_local_and_auditable(tmp_path, monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("External access is forbidden.")
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    path = tmp_path / "test.db"
    suspicious, brute = ssh_pair(path)
    engine = CorrelationEngine(path)
    ssh, = engine.evaluate_threat(suspicious["id"], evaluated_at=AT)
    assert ssh["correlation_type"] == "SSH_AUTH_ACTIVITY_PATTERN"
    assert (ssh["state"], ssh["severity"], ssh["confidence"]) == ("PATTERN", "MEDIUM", "HIGH")
    observations, cross, threat = web_chain(path, download=True)
    web, = engine.evaluate_web_detection(cross["id"], evaluated_at=AT)
    assert web["correlation_type"] == "WEB_CREDENTIAL_ACTIVITY_CHAIN"
    assert (web["state"], web["severity"], web["confidence"]) == ("CHAIN_REVIEW", "MEDIUM", "MEDIUM")
    assert len(web["entities"]) == 3
    # Mutable evaluation bookkeeping on source entities must not change snapshots.
    WebDetectionEngine(path).evaluate_observation(observations[2], evaluated_at=AT+timedelta(days=1))
    ThreatEngine(path).evaluate_web_detection(cross["id"], evaluated_at=AT+timedelta(days=1))
    assert engine.evaluate_threat(threat["id"], evaluated_at=AT)[0] == web
    for record in list_correlations(path):
        assert record["state"] not in {"INCIDENT", "CONFIRMED_PHISHING", "MALWARE", "COMPROMISED_DEVICE"}
        assert "host compromised" not in record["reason"].lower()
        assert "attacker identified" not in record["reason"].lower()
        for entity in record["entities"]:
            assert not {"url", "path", "raw_line", "message", "cookies", "credentials", "page_text", "metadata_json"} & entity["snapshot"].keys()
            assert entity["snapshot"]["entity_timestamp"] == entity["entity_timestamp"]
    assert len(list_correlations(path)) == 2
