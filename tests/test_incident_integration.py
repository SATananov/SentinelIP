import socket
from database.incidents import list_incidents
from services.correlation_engine import CorrelationEngine
from services.incident_engine import IncidentEngine
from test_correlation_engine import ssh_pair, web_chain
from test_correlation_rules import AT


def test_incident_review_is_explicit_local_and_auditable(tmp_path, monkeypatch):
    def forbidden(*args, **kwargs): raise AssertionError("External access is forbidden.")
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    path = tmp_path / "test.db"
    suspicious, _ = ssh_pair(path)
    ssh = CorrelationEngine(path).evaluate_threat(suspicious["id"], evaluated_at=AT)[0]
    _, cross, _ = web_chain(path, download=True)
    web = CorrelationEngine(path).evaluate_web_detection(cross["id"], evaluated_at=AT)[0]
    assert list_incidents(path) == []
    incident = IncidentEngine(path).open_review([ssh["id"], web["id"]], opened_at=AT)
    assert (incident["incident_type"], incident["status"], incident["priority"]) == ("MULTI_SIGNAL_REVIEW", "OPEN", "MEDIUM")
    assert "does not establish causality" in incident["reason"].lower()
    for item in incident["correlations"]:
        assert not {"url", "path", "raw_line", "message", "cookies", "credentials", "page_text", "metadata_json"} & item["snapshot"].keys()
    assert len(list_incidents(path)) == 1
