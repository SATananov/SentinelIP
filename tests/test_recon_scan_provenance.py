import sqlite3
import pytest

from database.db import get_connection, initialize_database
from database import migrations
from database.scopes import create_scope
from services.scan_provenance import fail_tcp_service_run, start_tcp_service_run


def test_migration_48_preserves_existing_schema_and_records_failed_scope_run(tmp_path):
    path = tmp_path / "isolated.db"
    initialize_database(path)
    scope_id = create_scope(
        scope_type="PUBLIC_IPV4",
        canonical_target="8.8.8.8",
        authorized=True,
        enabled=True,
        authorization_confirmed_at="2026-01-01T00:00:00+00:00",
        authorization_confirmation_version="test-v1",
        authorization_source="test",
        db_path=path,
    )
    run_id = start_tcp_service_run(scope_id["id"], "8.8.8.8", db_path=path)
    with pytest.raises(ValueError, match="outside the authorized scope"):
        start_tcp_service_run(scope_id["id"], "1.1.1.1", db_path=path)
    fail_tcp_service_run(run_id, "8.8.8.8", "timeout", db_path=path)
    with get_connection(path) as connection:
        version = connection.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0]
        run = connection.execute("SELECT status, error_category FROM recon_scan_runs WHERE id=?", (run_id,)).fetchone()
        target = connection.execute("SELECT outcome FROM recon_scan_targets WHERE run_id=?", (run_id,)).fetchone()
        assert connection.execute("SELECT 1 FROM cve_intelligence LIMIT 1").fetchone() is None
        assert "scan_run_id" in {row[1] for row in connection.execute("PRAGMA table_info(port_observations)")}
        assert run == ("FAILED", "timeout")
        assert target == ("FAILED",)
        assert version == 49
        assert scope_id["id"] > 0


def test_migration_49_is_idempotent(tmp_path):
    path = tmp_path / "migrations.db"
    initialize_database(path)
    initialize_database(path)
    with get_connection(path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM schema_migrations WHERE version=48").fetchone()[0] == 1
        assert connection.execute("SELECT COUNT(*) FROM schema_migrations WHERE version=49").fetchone()[0] == 1
        assert connection.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0] == 49


def test_migration_47_database_upgrades_additively_to_48(tmp_path, monkeypatch):
    path = tmp_path / "from-47.db"
    all_migrations = migrations.MIGRATIONS
    with monkeypatch.context() as version_47:
        version_47.setattr(migrations, "MIGRATIONS", tuple(item for item in all_migrations if item[0] <= 47))
        initialize_database(path)
    assert migrations.MIGRATIONS is all_migrations
    with get_connection(path) as connection:
        assert connection.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0] == 47
        assert connection.execute("SELECT name FROM sqlite_master WHERE name='recon_scan_runs'").fetchone() is None
        assert "scan_run_id" not in {row[1] for row in connection.execute("PRAGMA table_info(port_observations)")}
        connection.execute(
            """INSERT INTO events
               (timestamp, source_ip, username, event_type, severity, message, event_count)
               VALUES ('2026-01-01T00:00:00+00:00', '192.0.2.10', NULL, 'TEST', 'INFO', 'preserved', 1)"""
        )
    with monkeypatch.context() as version_48:
        version_48.setattr(migrations, "MIGRATIONS", tuple(item for item in all_migrations if item[0] <= 48))
        initialize_database(path)
    assert migrations.MIGRATIONS is all_migrations
    with get_connection(path) as connection:
        assert connection.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0] == 48
        assert connection.execute("SELECT COUNT(*) FROM schema_migrations WHERE version=48").fetchone()[0] == 1
        assert connection.execute("SELECT message FROM events").fetchone()[0] == "preserved"
        assert {"recon_scan_runs", "recon_scan_targets"} <= {
            row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
        assert {"scan_run_id"} <= {
            row[1] for row in connection.execute("PRAGMA table_info(port_observations)")
        }
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []


def test_migration_48_database_upgrades_additively_to_49(tmp_path, monkeypatch):
    path = tmp_path / "from-48.db"
    all_migrations = migrations.MIGRATIONS
    with monkeypatch.context() as version_48:
        version_48.setattr(migrations, "MIGRATIONS", tuple(item for item in all_migrations if item[0] <= 48))
        initialize_database(path)
    assert migrations.MIGRATIONS is all_migrations
    with get_connection(path) as connection:
        assert connection.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0] == 48
        assert connection.execute("SELECT name FROM sqlite_master WHERE name='recon_scan_targets'").fetchone()
        assert "scan_run_id" in {row[1] for row in connection.execute("PRAGMA table_info(port_observations)")}
        assert connection.execute("SELECT name FROM sqlite_master WHERE name='http_endpoint_observations'").fetchone() is None
        connection.execute(
            """INSERT INTO events
               (timestamp, source_ip, username, event_type, severity, message, event_count)
               VALUES ('2026-01-01T00:00:00+00:00', '192.0.2.11', NULL, 'TEST', 'INFO', 'preserved', 1)"""
        )
    initialize_database(path)
    initialize_database(path)
    with get_connection(path) as connection:
        assert connection.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0] == 49
        assert connection.execute("SELECT COUNT(*) FROM schema_migrations WHERE version=49").fetchone()[0] == 1
        assert connection.execute("SELECT message FROM events").fetchone()[0] == "preserved"
        assert connection.execute("SELECT name FROM sqlite_master WHERE name='http_endpoint_observations'").fetchone()
        assert connection.execute("SELECT name FROM sqlite_master WHERE name='http_tls_observations'").fetchone()
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
