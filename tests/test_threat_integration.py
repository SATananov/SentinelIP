import socket

from database.threats import list_threats
from services.threat_engine import ThreatEngine
from services.web_detection_engine import WebDetectionEngine
from test_threat_engine import persist_ssh, web_scenario
from test_threat_rules import AT


def test_mocked_ssh_and_web_integrations_are_offline_and_auditable(tmp_path, monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("Active network access is forbidden.")
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    path = tmp_path / "test.db"
    ids = persist_ssh(path)
    engine = ThreatEngine(path)
    ssh, = engine.evaluate_ssh_event(ids[-1], evaluated_at=AT)
    assert ssh["threat_type"] == "SSH_BRUTE_FORCE_THREAT"
    assert (ssh["state"], ssh["severity"], ssh["confidence"]) == ("SUSPECTED", "MEDIUM", "HIGH")
    assert "repeated failed ssh authentication" in ssh["reason"].lower()
    assert {item["evidence_id"] for item in ssh["evidence"]} == set(ids)
    web_ids, cross = web_scenario(path)
    web, = engine.evaluate_web_detection(cross["id"], evaluated_at=AT)
    download, = WebDetectionEngine(path).evaluate_observation(web_ids[3], evaluated_at=AT)
    strengthened, = engine.evaluate_web_detection(download["id"], evaluated_at=AT)
    assert strengthened["id"] == web["id"] and len(strengthened["evidence"]) == 2
    assert (web["state"], web["severity"], web["confidence"]) == ("SUSPECTED", "MEDIUM", "MEDIUM")
    for threat in list_threats(path):
        assert threat["threat_type"] not in {"MALWARE", "CONFIRMED_PHISHING", "COMPROMISED_DEVICE"}
        for item in threat["evidence"]:
            assert not {"message", "raw_line", "path", "url", "credentials", "metadata_json"} & item["snapshot"].keys()
        assert "compromised" not in threat["reason"].lower()
        assert "gained access" not in threat["reason"].lower()
    assert len(list_threats(path)) == 2
