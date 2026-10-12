from datetime import timedelta
import pytest
from database.db import get_connection
from database.web_detections import list_web_detections
from services.web_detection_engine import WebDetectionEngine
from services.web_detection_models import WebDetectionError
from test_database_web_detections import stored_evidence
from test_web_detection_rules import AT


def test_explicit_engine_evaluation_and_replay(tmp_path):
    path = tmp_path / "web.db"
    evidence = stored_evidence(path)
    assert list_web_detections(db_path=path) == []
    engine = WebDetectionEngine(path)
    first, = engine.evaluate_observation(evidence.observation_id, evaluated_at=AT)
    second, = engine.evaluate_observation(evidence.observation_id, evaluated_at=AT + timedelta(minutes=1))
    assert first["id"] == second["id"] and first["first_seen"] == second["first_seen"]
    assert second["last_seen"] > first["last_seen"]
    assert second["detection_type"] == "LOGIN_DOMAIN_REVIEW"


def test_unknown_observation_and_invalid_id(tmp_path):
    engine = WebDetectionEngine(tmp_path / "web.db")
    for identifier in (999, 0, True, "1"):
        with pytest.raises(WebDetectionError):
            engine.evaluate_observation(identifier)


def test_context_limit_fails_explicitly_without_partial_writes(tmp_path, monkeypatch):
    import services.web_detection_engine as module
    path = tmp_path / "web.db"
    primary = stored_evidence(path)
    with get_connection(path) as connection:
        for number in (2, 3):
            connection.execute("""INSERT INTO web_observations(sensor_id, external_event_id, observed_at, received_at,
                event_type, hostname, has_login_form, has_password_form, download_detected, source, retention_until,
                browser_session_id, tab_id) VALUES (?, ?, ?, ?, 'NAVIGATION', 'example.test', 0, 0, 0,
                'browser', ?, 'session', 'tab')""", (primary.sensor_id, str(number), AT.isoformat(), AT.isoformat(), AT.isoformat()))
    monkeypatch.setattr(module, "MAX_CONTEXT_OBSERVATIONS", 1)
    with pytest.raises(WebDetectionError, match="limit"):
        module.WebDetectionEngine(path).evaluate_observation(primary.observation_id)
    assert list_web_detections(db_path=path) == []
