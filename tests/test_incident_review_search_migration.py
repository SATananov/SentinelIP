from database.db import get_connection, initialize_database
from database import migrations as migration_module
from database.incident_reviews import search_reviews
from database.migrations import MIGRATIONS


def test_fresh_initialization_reaches_45_once_and_is_idempotent(tmp_path):
    path = tmp_path / "incident-review-search-fresh.db"
    initialize_database(path)
    initialize_database(path)
    with get_connection(path) as connection:
        versions = [row[0] for row in connection.execute(
            "SELECT version FROM schema_migrations ORDER BY version")]
        objects = {row[0] for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type IN ('table','trigger')")}
    assert versions == list(range(1, 46))
    assert "incident_reviews" in objects
    assert "incident_reviews_fts" in objects
    assert {
        "incident_reviews_fts_insert", "incident_reviews_fts_update", "incident_reviews_fts_delete",
    } <= objects


def test_migration_45_rebuilds_historical_reviews_and_installs_sync_triggers(tmp_path, monkeypatch):
    path = tmp_path / "incident-review-search-upgrade.db"
    all_migrations = MIGRATIONS
    monkeypatch.setattr(migration_module, "MIGRATIONS", all_migrations[:44])
    initialize_database(path)
    with get_connection(path) as connection:
        historical_id = connection.execute(
            """INSERT INTO incident_reviews (
                incident_key,title,summary,state,priority,confidence,created_at,updated_at,
                disposition,final_summary
            ) VALUES (?,?,?,?,?,?,?,?,?,?)""",
            ("IR-historical-search", "Historical Firewall Authentication", "", "OPEN", "HIGH",
             "MEDIUM", "2026-09-01T00:00:00+00:00", "2026-09-01T00:00:00+00:00",
             "UNREVIEWED", None),
        ).lastrowid
        assert connection.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0] == 44

    monkeypatch.setattr(migration_module, "MIGRATIONS", all_migrations)
    initialize_database(path)
    initialize_database(path)

    assert [row["id"] for row in search_reviews(title="fire auth", db_path=path)["items"]] == [historical_id]
    with get_connection(path) as connection:
        assert connection.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0] == 45
        assert connection.execute("SELECT COUNT(*) FROM schema_migrations WHERE version=45").fetchone()[0] == 1
        objects = {row[0] for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type IN ('table','trigger')")}
        assert "incident_reviews_fts" in objects
        assert {
            "incident_reviews_fts_insert", "incident_reviews_fts_update", "incident_reviews_fts_delete",
        } <= objects
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
        columns = {row[1] for row in connection.execute("PRAGMA table_info(incident_reviews)")}
        assert "title" in columns and "search_text" not in columns


def test_migration_45_rebuilds_multiple_historical_titles_without_changing_rows(tmp_path, monkeypatch):
    path = tmp_path / "incident-review-search-history.db"
    all_migrations = MIGRATIONS
    monkeypatch.setattr(migration_module, "MIGRATIONS", all_migrations[:44])
    initialize_database(path)
    historical = [
        ("IR-latin-history", "Firewall Authentication History", "OPEN", "HIGH", "UNREVIEWED", None),
        ("IR-cyrillic-history", "Проверка Сетевого Экрана", "CLOSED", "MEDIUM", "BENIGN", "2026-09-03T00:00:00+00:00"),
    ]
    with get_connection(path) as connection:
        ids = []
        for key, title, state, priority, disposition, closed_at in historical:
            ids.append(connection.execute(
                """INSERT INTO incident_reviews (
                    incident_key,title,state,priority,confidence,created_at,updated_at,closed_at,disposition
                ) VALUES (?,?,?,?,?,?,?,?,?)""",
                (key, title, state, priority, "MEDIUM", "2026-09-01T00:00:00+00:00",
                 "2026-09-03T00:00:00+00:00", closed_at, disposition),
            ).lastrowid)
        before = connection.execute(
            "SELECT id,incident_key,title,state,priority,closed_at,disposition FROM incident_reviews ORDER BY id"
        ).fetchall()

    monkeypatch.setattr(migration_module, "MIGRATIONS", all_migrations)
    initialize_database(path)
    with get_connection(path) as connection:
        after = connection.execute(
            "SELECT id,incident_key,title,state,priority,closed_at,disposition FROM incident_reviews ORDER BY id"
        ).fetchall()
        indexed = connection.execute(
            "SELECT rowid,title FROM incident_reviews_fts ORDER BY rowid"
        ).fetchall()
    assert after == before
    assert indexed == [(ids[0], historical[0][1]), (ids[1], historical[1][1])]
    assert [row["id"] for row in search_reviews(title="fire auth", db_path=path)["items"]] == [ids[0]]
    assert [row["id"] for row in search_reviews(title="пров сет", db_path=path)["items"]] == [ids[1]]
    with get_connection(path) as connection:
        connection.execute("INSERT INTO incident_reviews_fts(incident_reviews_fts) VALUES ('rebuild')")
        connection.execute("INSERT INTO incident_reviews_fts(incident_reviews_fts,rank) VALUES ('integrity-check',1)")
        assert connection.execute(
            "SELECT id,incident_key,title FROM incident_reviews ORDER BY id"
        ).fetchall() == [(row[0], row[1], row[2]) for row in after]
    assert [row["id"] for row in search_reviews(title="fire auth", db_path=path)["items"]] == [ids[0]]

