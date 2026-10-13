import sqlite3
from dataclasses import replace
from datetime import timedelta

import pytest
from database.db import get_connection, initialize_database
from database.migrations import apply_migrations, MIGRATIONS
from database.telemetry import create_web_observation, provision_sensor
from database.web_detections import get_web_detection, list_web_detections, upsert_detections
from services.telemetry_models import WebObservation
from services.web_detection_models import WebEvidence, WebDetectionError
from services.web_detection_rules import evaluate_rules
from test_web_detection_rules import AT


def stored_evidence(path, **overrides):
    sensor, _ = provision_sensor("web", "Web", "BROWSER", None, "DOMAIN_ONLY", 30, path)
    values = dict(external_event_id="first", sensor_id=str(sensor["id"]), observed_at=AT,
                  event_type="FORM_SIGNAL", url="https://login.example.test/private?secret=ignored",
                  privacy_mode="DOMAIN_ONLY", has_password_form=True, browser_session_id="session", tab_id="tab",
                  received_at=AT, retention_until=AT + timedelta(days=30))
    values.update(overrides)
    return WebEvidence.from_row(create_web_observation(WebObservation(**values), path))


def candidate(path):
    return evaluate_rules(stored_evidence(path), (), AT)[0]


def test_migration_upgrade_idempotent_and_preserves_old_rows(tmp_path):
    path = tmp_path / "upgrade.db"
    with sqlite3.connect(path) as connection:
        # Build the exact pre-phase schema and record applied versions.
        connection.execute("CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)")
        for version, statements in MIGRATIONS[:20]:
            for statement in ((statements,) if isinstance(statements, str) else statements):
                connection.execute(statement)
            connection.execute("INSERT INTO schema_migrations VALUES (?, 'old')", (version,))
        connection.execute("""INSERT INTO web_observations(sensor_id, external_event_id, observed_at, received_at,
            event_type, hostname, has_login_form, has_password_form, download_detected, source, retention_until)
            VALUES (1, 'old', '2026-01-01', '2026-01-01', 'NAVIGATION', 'example.test', 0, 0, 0, 'browser', '2026-02-01')""")
    initialize_database(path)
    initialize_database(path)
    with get_connection(path) as connection:
        assert connection.execute("SELECT browser_session_id, tab_id FROM web_observations").fetchone() == (None, None)
        assert connection.execute("SELECT COUNT(*) FROM schema_migrations").fetchone()[0] == 32
        assert connection.execute("SELECT name FROM sqlite_master WHERE name='idx_web_detections_sensor_time'").fetchone()


def test_upsert_deduplicates_and_preserves_history(tmp_path):
    path = tmp_path / "web.db"
    review = candidate(path)
    first, = upsert_detections((review,), path)
    later = replace(review, first_seen=AT + timedelta(minutes=1), last_seen=AT + timedelta(minutes=1))
    second, = upsert_detections((later,), path)
    assert first["id"] == second["id"]
    assert second["first_seen"] == first["first_seen"]
    assert second["last_seen"] == later.last_seen.isoformat()
    assert second["evidence"] == first["evidence"]
    assert get_web_detection(first["id"], path) == second
    assert len(list_web_detections(db_path=path)) == 1
    assert list_web_detections(999, path) == []
    older, = upsert_detections((review,), path)
    assert older["last_seen"] == second["last_seen"]
    with get_connection(path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM web_detection_observations").fetchone()[0] == 1


def test_evidence_mismatch_rolls_back_entire_batch(tmp_path):
    path = tmp_path / "web.db"
    review = candidate(path)
    forged = replace(review, evidence=(replace(review.evidence[0], has_login_form=True),), rule_version="2")
    with pytest.raises(WebDetectionError):
        upsert_detections((review, forged), path)
    assert list_web_detections(db_path=path) == []


def test_observation_deletion_preserves_detection_snapshot(tmp_path):
    path = tmp_path / "web.db"
    review = candidate(path)
    first, = upsert_detections((review,), path)
    with get_connection(path) as connection:
        connection.execute("DELETE FROM web_observations WHERE id = ?", (review.primary_observation_id,))
    current = get_web_detection(first["id"], path)
    assert current["primary_observation_id"] is None
    assert current["evidence"] == first["evidence"]
    with get_connection(path) as connection:
        assert connection.execute("SELECT observation_id FROM web_detection_observations").fetchone() == (None,)
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []


def test_schema_restricts_states_and_references(tmp_path):
    path = tmp_path / "web.db"
    review = candidate(path)
    first, = upsert_detections((review,), path)
    with pytest.raises(sqlite3.IntegrityError), get_connection(path) as connection:
        connection.execute("UPDATE web_detections SET state='CONFIRMED_PHISHING' WHERE id=?", (first["id"],))
    with pytest.raises(sqlite3.IntegrityError), get_connection(path) as connection:
        connection.execute("UPDATE web_detections SET primary_observation_id=999 WHERE id=?", (first["id"],))


def test_migration_failure_rolls_back_its_statements(tmp_path, monkeypatch):
    import database.migrations as migrations
    path = tmp_path / "web.db"
    initialize_database(path)
    failing_version = max(version for version, _ in migrations.MIGRATIONS) + 1
    monkeypatch.setattr(migrations, "MIGRATIONS", (*migrations.MIGRATIONS, (failing_version, (
        "ALTER TABLE web_detections ADD COLUMN rollback_probe TEXT", "INVALID SQL"))))
    with pytest.raises(sqlite3.OperationalError), get_connection(path) as connection:
        apply_migrations(connection)
    with get_connection(path) as connection:
        assert "rollback_probe" not in {r[1] for r in connection.execute("PRAGMA table_info(web_detections)")}
        assert connection.execute(
            "SELECT COUNT(*) FROM schema_migrations WHERE version = ?", (failing_version,)
        ).fetchone()[0] == 0


def test_concurrent_equivalent_evaluation_has_one_record(tmp_path):
    from concurrent.futures import ThreadPoolExecutor
    path = tmp_path / "web.db"
    review = candidate(path)
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: upsert_detections((review,), path), range(4)))
    assert len({result[0]["id"] for result in results}) == 1
    assert len(list_web_detections(db_path=path)) == 1
