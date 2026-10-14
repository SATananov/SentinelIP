import sqlite3
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import timedelta
import pytest
from database.db import get_connection, initialize_database
from database.correlations import get_correlation, list_correlations, upsert_correlation
from services.correlation_evidence import load_entity
from services.correlation_models import CorrelationError
from services.correlation_rules import correlate_ssh
from services.correlation_engine import CorrelationEngine
from test_correlation_engine import ssh_pair, web_chain
from test_correlation_rules import AT


def stored_candidate(path):
    a, b = ssh_pair(path)
    with get_connection(path) as connection:
        connection.row_factory = sqlite3.Row
        return correlate_ssh(load_entity(connection, "THREAT", a["id"]), load_entity(connection, "THREAT", b["id"]), AT)


def test_upgrade_from_23_is_additive_and_idempotent(tmp_path, monkeypatch):
    import database.migrations as migrations
    path = tmp_path / "test.db"
    all_migrations = migrations.MIGRATIONS
    monkeypatch.setattr(migrations, "MIGRATIONS", all_migrations[:23])
    a, b = ssh_pair(path)
    monkeypatch.setattr(migrations, "MIGRATIONS", all_migrations)
    initialize_database(path)
    initialize_database(path)
    with get_connection(path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM schema_migrations").fetchone()[0] == 43
        assert connection.execute("SELECT COUNT(*) FROM threat_detections").fetchone()[0] == 2
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
        assert connection.execute("SELECT name FROM sqlite_master WHERE name='idx_correlations_source'").fetchone()
    assert CorrelationEngine(path).evaluate_threat(a["id"])


def test_concurrent_equivalent_insertion_and_monotonic_time(tmp_path):
    path = tmp_path / "test.db"
    candidate = stored_candidate(path)
    with ThreadPoolExecutor(max_workers=2) as pool:
        rows = list(pool.map(lambda _: upsert_correlation(candidate, path), range(4)))
    assert len({row["id"] for row in rows}) == 1
    later = upsert_correlation(replace(candidate, last_seen=AT+timedelta(minutes=1)), path)
    replay = upsert_correlation(candidate, path)
    assert replay["first_seen"] == rows[0]["first_seen"] and replay["last_seen"] == later["last_seen"]
    assert len(replay["entities"]) == 2 and len(list_correlations(path)) == 1


def test_forged_projection_or_rule_cannot_persist(tmp_path):
    path = tmp_path / "test.db"
    candidate = stored_candidate(path)
    forged = replace(candidate, entities=(replace(candidate.entities[0], reason="Different."), candidate.entities[1]))
    with pytest.raises(CorrelationError):
        upsert_correlation(forged, path)
    with pytest.raises(CorrelationError):
        upsert_correlation(replace(candidate, reason="Unsupported conclusion."), path)
    assert list_correlations(path) == []


def test_source_change_cannot_overwrite_historical_snapshot(tmp_path):
    path = tmp_path / "test.db"
    candidate = stored_candidate(path)
    original = upsert_correlation(candidate, path)
    with get_connection(path) as connection:
        connection.execute("UPDATE threat_detections SET reason='Updated assessment.' WHERE id=?", (candidate.primary_entity_id,))
    with pytest.raises(CorrelationError, match="Historical"):
        CorrelationEngine(path).evaluate_threat(candidate.primary_entity_id, evaluated_at=AT+timedelta(minutes=1))
    assert get_correlation(original["id"], path) == original


def test_deleted_source_preserves_snapshot_and_original_identity(tmp_path):
    path = tmp_path / "test.db"
    candidate = stored_candidate(path)
    original = upsert_correlation(candidate, path)
    with get_connection(path) as connection:
        connection.execute("DELETE FROM threat_evidence")
        connection.execute("DELETE FROM threat_detections")
    current = get_correlation(original["id"], path)
    assert all(e["threat_id"] is None for e in current["entities"])
    assert [e["snapshot"] for e in current["entities"]] == [e["snapshot"] for e in original["entities"]]
    with get_connection(path) as connection:
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []


def test_constraints_forbid_confirmation_and_wrong_live_link(tmp_path):
    path = tmp_path / "test.db"
    upsert_correlation(stored_candidate(path), path)
    with pytest.raises(sqlite3.IntegrityError), get_connection(path) as connection:
        connection.execute("UPDATE correlations SET state='CONFIRMED_INCIDENT'")
    with pytest.raises(sqlite3.IntegrityError), get_connection(path) as connection:
        connection.execute("UPDATE correlation_entities SET threat_id=999")


def test_unlinked_web_candidate_is_rejected(tmp_path):
    from services.correlation_rules import correlate_web
    path = tmp_path / "test.db"
    _, cross, threat = web_chain(path)
    with get_connection(path) as connection:
        connection.row_factory = sqlite3.Row
        candidate = correlate_web(load_entity(connection, "THREAT", threat["id"]),
                                  (load_entity(connection, "WEB_DETECTION", cross["id"]),), AT)
        connection.execute("UPDATE threat_evidence SET web_detection_id=NULL WHERE threat_id=?", (threat["id"],))
    with pytest.raises(CorrelationError, match="links"):
        upsert_correlation(candidate, path)
    assert list_correlations(path) == []
