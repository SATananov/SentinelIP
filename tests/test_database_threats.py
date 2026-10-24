import sqlite3
from dataclasses import replace
from datetime import timedelta
from concurrent.futures import ThreadPoolExecutor

import pytest
from database.db import get_connection, initialize_database
from database.threats import upsert_threat, get_threat, list_threats
from services.threat_evidence import SSH_COLUMNS, ssh_from_row
from services.threat_models import ThreatError
from services.threat_rules import evaluate_ssh
from test_threat_engine import persist_ssh
from test_threat_rules import AT


def stored_candidate(path):
    persist_ssh(path)
    with get_connection(path) as connection:
        connection.row_factory = sqlite3.Row
        rows = tuple(ssh_from_row(row) for row in connection.execute(f"SELECT {SSH_COLUMNS} FROM events ORDER BY id"))
    return evaluate_ssh(rows[-1], rows, AT)


def test_migration_additive_idempotent_and_indexed(tmp_path):
    from database.migrations import MIGRATIONS, apply_migrations
    path = tmp_path / "test.db"
    # Preserve a real pre-threat schema and row across migration 23.
    with get_connection(path) as connection:
        connection.execute("CREATE TABLE events(id INTEGER PRIMARY KEY, timestamp TEXT, source_ip TEXT, username TEXT, event_type TEXT, severity TEXT, message TEXT, event_count INTEGER)")
        connection.execute("CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)")
        for version, statements in MIGRATIONS[:22]:
            for statement in ((statements,) if isinstance(statements, str) else statements):
                connection.execute(statement)
            connection.execute("INSERT INTO schema_migrations VALUES (?, 'old')", (version,))
        connection.execute("INSERT INTO events VALUES(1, '2026-01-01T00:00:00', '192.0.2.1', NULL, 'LOGIN_FAILED', 'INFO', 'original', 1)")
    initialize_database(path)
    initialize_database(path)
    with get_connection(path) as connection:
        assert connection.execute("SELECT message FROM events WHERE id=1").fetchone()[0] == "original"
        assert connection.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0] == 46
        assert connection.execute("SELECT name FROM sqlite_master WHERE name='idx_events_threat_window'").fetchone()
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []


def test_upsert_concurrent_and_monotonic(tmp_path):
    path = tmp_path / "test.db"
    candidate = stored_candidate(path)
    with ThreadPoolExecutor(max_workers=2) as pool:
        rows = list(pool.map(lambda _: upsert_threat(candidate, path), range(4)))
    assert len({row["id"] for row in rows}) == 1
    later = upsert_threat(replace(candidate, last_seen=AT+timedelta(minutes=1)), path)
    older = upsert_threat(candidate, path)
    assert older["first_seen"] == rows[0]["first_seen"]
    assert older["last_seen"] == later["last_seen"]
    assert len(older["evidence"]) == 5 and len(list_threats(path)) == 1


def test_invalid_source_snapshot_rolls_back(tmp_path):
    path = tmp_path / "test.db"
    candidate = stored_candidate(path)
    fake = replace(candidate, evidence=(*candidate.evidence[:-1], replace(candidate.evidence[-1], username="changed")))
    with pytest.raises(ThreatError):
        upsert_threat(fake, path)
    assert list_threats(path) == []


def test_changed_historical_evidence_does_not_overwrite_or_touch(tmp_path):
    path = tmp_path / "test.db"
    candidate = stored_candidate(path)
    first = upsert_threat(candidate, path)
    with get_connection(path) as connection:
        connection.execute("UPDATE events SET username='changed' WHERE id=?", (candidate.primary_evidence_id,))
    modified = replace(candidate, evidence=(*candidate.evidence[:-1], replace(candidate.evidence[-1], username="changed")),
                       last_seen=AT+timedelta(minutes=1))
    with pytest.raises(ThreatError, match="historical"):
        upsert_threat(modified, path)
    assert get_threat(first["id"], path) == first


def test_deleted_event_leaves_audit_snapshot(tmp_path):
    path = tmp_path / "test.db"
    candidate = stored_candidate(path)
    first = upsert_threat(candidate, path)
    with get_connection(path) as connection:
        connection.execute("DELETE FROM events")
    row = get_threat(first["id"], path)
    assert all(item["ssh_event_id"] is None for item in row["evidence"])
    assert [item["snapshot"] for item in row["evidence"]] == [item["snapshot"] for item in first["evidence"]]


def test_confirmation_and_wrong_references_rejected(tmp_path):
    path = tmp_path / "test.db"
    first = upsert_threat(stored_candidate(path), path)
    with pytest.raises(sqlite3.IntegrityError), get_connection(path) as connection:
        connection.execute("UPDATE threat_detections SET state='CONFIRMED'")
    with pytest.raises(sqlite3.IntegrityError), get_connection(path) as connection:
        connection.execute("UPDATE threat_evidence SET ssh_event_id=999")
