import sqlite3
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import pytest
from database.db import get_connection, initialize_database
from database.incidents import get_incident, list_incidents, upsert_incident
from services.correlation_engine import CorrelationEngine
from services.incident_evidence import load_correlation_projection
from services.incident_models import IncidentError, build_incident
from test_correlation_engine import ssh_pair
from test_correlation_rules import AT


def stored_candidate(path):
    suspicious, _ = ssh_pair(path)
    correlation = CorrelationEngine(path).evaluate_threat(suspicious["id"], evaluated_at=AT)[0]
    with get_connection(path) as connection:
        connection.row_factory = sqlite3.Row
        projection = load_correlation_projection(connection, correlation["id"])
    return build_incident((projection,), AT)


def test_migration_25_is_additive_and_idempotent(tmp_path):
    path = tmp_path / "test.db"
    initialize_database(path); initialize_database(path)
    with get_connection(path) as connection:
        assert connection.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0] == 25
        assert connection.execute("SELECT name FROM sqlite_master WHERE name='incidents'").fetchone()
        assert connection.execute("SELECT name FROM sqlite_master WHERE name='incident_correlations'").fetchone()
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []


def test_incident_persistence_is_idempotent(tmp_path):
    path = tmp_path / "test.db"; candidate = stored_candidate(path)
    assert upsert_incident(candidate, path) == upsert_incident(candidate, path)
    assert len(list_incidents(path)) == 1


def test_concurrent_equivalent_open_has_one_record(tmp_path):
    path = tmp_path / "test.db"; candidate = stored_candidate(path)
    with ThreadPoolExecutor(max_workers=2) as pool:
        rows = list(pool.map(lambda _: upsert_incident(candidate, path), range(4)))
    assert len({row["id"] for row in rows}) == 1


def test_forged_incident_semantics_cannot_persist(tmp_path):
    path = tmp_path / "test.db"; candidate = stored_candidate(path)
    with pytest.raises(IncidentError):
        upsert_incident(replace(candidate, reason="Host compromised."), path)
    assert list_incidents(path) == []


def test_deleted_source_preserves_incident_snapshot(tmp_path):
    path = tmp_path / "test.db"; original = upsert_incident(stored_candidate(path), path)
    with get_connection(path) as connection:
        connection.execute("DELETE FROM correlation_entities")
        connection.execute("DELETE FROM correlations")
    current = get_incident(original["id"], path)
    assert current["correlations"][0]["correlation_id"] is None
    assert current["correlations"][0]["source_correlation_id"] == original["correlations"][0]["source_correlation_id"]
    assert current["correlations"][0]["snapshot"] == original["correlations"][0]["snapshot"]


def test_database_constraints_forbid_confirmed_status(tmp_path):
    path = tmp_path / "test.db"; upsert_incident(stored_candidate(path), path)
    with pytest.raises(sqlite3.IntegrityError), get_connection(path) as connection:
        connection.execute("UPDATE incidents SET status='CONFIRMED'")
    with pytest.raises(sqlite3.IntegrityError), get_connection(path) as connection:
        connection.execute("UPDATE incidents SET priority='CRITICAL'")
