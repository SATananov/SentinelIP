from datetime import timedelta
import pytest
from database.db import get_connection
from services.correlation_engine import CorrelationEngine
from services.incident_engine import IncidentEngine
from services.incident_models import IncidentError
from test_correlation_engine import ssh_pair, web_chain
from test_correlation_rules import AT


def ssh_correlation(path):
    suspicious, _ = ssh_pair(path)
    return CorrelationEngine(path).evaluate_threat(suspicious["id"], evaluated_at=AT)[0]


def web_correlation(path):
    _, cross, _ = web_chain(path, download=True)
    return CorrelationEngine(path).evaluate_web_detection(cross["id"], evaluated_at=AT)[0]


def test_explicit_ssh_review_creation(tmp_path):
    path = tmp_path / "test.db"
    incident = IncidentEngine(path).open_review([ssh_correlation(path)["id"]], opened_at=AT)
    assert (incident["incident_type"], incident["status"], incident["priority"]) == ("AUTHENTICATION_REVIEW", "OPEN", "MEDIUM")


def test_explicit_web_review_creation(tmp_path):
    path = tmp_path / "test.db"
    incident = IncidentEngine(path).open_review([web_correlation(path)["id"]], opened_at=AT)
    assert incident["incident_type"] == "WEB_ACTIVITY_REVIEW"
    assert "does not confirm phishing" in incident["reason"].lower()


def test_mixed_review_requires_explicit_ids(tmp_path):
    path = tmp_path / "test.db"
    incident = IncidentEngine(path).open_review([ssh_correlation(path)["id"], web_correlation(path)["id"]], opened_at=AT)
    assert incident["incident_type"] == "MULTI_SIGNAL_REVIEW"
    assert len(incident["correlations"]) == 2


def test_repeated_open_is_idempotent(tmp_path):
    path = tmp_path / "test.db"
    correlation = ssh_correlation(path)
    engine = IncidentEngine(path)
    first = engine.open_review([correlation["id"]], opened_at=AT)
    second = engine.open_review([correlation["id"]], opened_at=AT + timedelta(minutes=10))
    assert first == second


def test_missing_duplicate_and_excessive_ids_rejected(tmp_path):
    path = tmp_path / "test.db"
    correlation = ssh_correlation(path)
    engine = IncidentEngine(path)
    with pytest.raises(IncidentError): engine.open_review([])
    with pytest.raises(IncidentError): engine.open_review([correlation["id"], correlation["id"]])
    with pytest.raises(IncidentError): engine.open_review([999999])
    with pytest.raises(IncidentError): engine.open_review(range(1, 27))


def test_open_review_does_not_mutate_correlation(tmp_path):
    path = tmp_path / "test.db"
    correlation = ssh_correlation(path)
    IncidentEngine(path).open_review([correlation["id"]], opened_at=AT)
    with get_connection(path) as connection:
        row = connection.execute("SELECT state, severity, confidence FROM correlations WHERE id=?", (correlation["id"],)).fetchone()
    assert row == ("PATTERN", "MEDIUM", "HIGH")
