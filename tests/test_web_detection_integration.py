from datetime import datetime, timezone

from database.telemetry import provision_sensor, list_web_observations
from services.telemetry_ingestion import ingest_web


AT = datetime(2026, 1, 1, tzinfo=timezone.utc)


def test_ingestion_preserves_explicit_browser_context(tmp_path):
    path = tmp_path / "web.db"
    sensor, token = provision_sensor("web", "Web", "BROWSER", None, "DOMAIN_ONLY", 30, path)
    payload = dict(external_event_id="context", observed_at=AT, event_type="FORM_SIGNAL",
                   url="https://login.example.test/private?secret=ignored", has_password_form=True,
                   browser_session_id="session", tab_id="tab")
    first = ingest_web(sensor["id"], token, payload, path)
    second = ingest_web(sensor["id"], token, payload, path)
    row, = list_web_observations(sensor["id"], path)
    assert first["id"] == second["id"] and second["idempotent"]
    assert row["browser_session_id"] == "session" and row["tab_id"] == "tab"
    assert row["path"] is None


def scenario(path, *, session="session", tab="tab", download_delay=40):
    from datetime import timedelta
    sensor, token = provision_sensor("scenario", "Web", "BROWSER", None, "DOMAIN_ONLY", 30, path)
    payloads = [
        dict(event_type="NAVIGATION", url="https://example.test", observed_at=AT),
        dict(event_type="REDIRECT", url="https://login.example.test", observed_at=AT + timedelta(seconds=10),
             redirect_from_domain="Example.TEST.", redirect_to_domain="Login.Example.TEST."),
        dict(event_type="FORM_SIGNAL", url="https://login.example.test", observed_at=AT + timedelta(seconds=20),
             has_password_form=True),
        dict(event_type="DOWNLOAD_SIGNAL", url="https://download.example.test", observed_at=AT + timedelta(seconds=download_delay),
             download_detected=True),
    ]
    ids = []
    for index, payload in enumerate(payloads):
        context = dict(browser_session_id="session", tab_id="tab")
        if index >= 2:
            context = dict(browser_session_id=session, tab_id=tab)
        ids.append(ingest_web(sensor["id"], token, {**payload, **context, "external_event_id": str(index)}, path)["id"])
    return ids


def test_full_persisted_scenario_is_review_only_and_offline(tmp_path, monkeypatch):
    import socket
    import json
    from datetime import timedelta
    from database.web_detections import list_web_detections
    from database.findings import list_findings
    from services.web_detection_engine import WebDetectionEngine
    from database import telemetry

    def forbidden(*args, **kwargs):
        raise AssertionError("External access or DNS evidence is forbidden.")

    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(telemetry, "list_dns_observations", forbidden)
    path = tmp_path / "web.db"
    ids = scenario(path)
    assert list_web_detections(db_path=path) == []  # No ingestion hook.
    engine = WebDetectionEngine(path)
    assert engine.evaluate_observation(ids[0]) == []
    assert engine.evaluate_observation(ids[1]) == []
    cross, = engine.evaluate_observation(ids[2], evaluated_at=AT)
    download, = engine.evaluate_observation(ids[3], evaluated_at=AT)
    assert cross["detection_type"] == "CROSS_DOMAIN_LOGIN_REDIRECT"
    assert {e["observation_id"] for e in cross["evidence"]} == {ids[1], ids[2]}
    assert download["detection_type"] == "SUSPICIOUS_DOWNLOAD_FLOW"
    for row in (cross, download):
        assert (row["state"], row["severity"], row["confidence"]) == ("REVIEW", "MEDIUM", "MEDIUM")
        assert row["rule_version"] == "1" and row["rule_id"]
        assert row["detection_type"] not in {"PHISHING_CONFIRMED", "MALWARE", "COMPROMISED_DEVICE"}
        for item in row["evidence"]:
            assert not {"path", "url", "metadata", "metadata_json", "page_text", "credentials", "password_value"} & item.keys()
            assert item["source"] == "browser"
    later, = engine.evaluate_observation(ids[2], evaluated_at=AT + timedelta(minutes=1))
    assert later["first_seen"] == cross["first_seen"] and later["last_seen"] > cross["last_seen"]
    assert len(list_web_detections(db_path=path)) == 2
    assert list_findings(path) == []


def test_persisted_cross_tab_and_session_boundaries(tmp_path):
    from services.web_detection_engine import WebDetectionEngine
    for index, (session, tab) in enumerate([("other", "tab"), ("session", "other"), (None, "tab"), ("session", None)]):
        path = tmp_path / f"web-{index}.db"
        ids = scenario(path, session=session, tab=tab)
        review, = WebDetectionEngine(path).evaluate_observation(ids[2])
        assert review["detection_type"] == "LOGIN_DOMAIN_REVIEW"


def test_persisted_download_outside_window(tmp_path):
    from services.web_detection_engine import WebDetectionEngine
    path = tmp_path / "web.db"
    ids = scenario(path, download_delay=321)
    assert WebDetectionEngine(path).evaluate_observation(ids[3]) == []
