from database.db import get_connection, initialize_database
from database.scopes import (
    create_hostname_scope,
    get_scope,
    list_hostname_addresses,
    reauthorize_hostname_scope,
)
from services.scope_authorization import HOSTNAME_CONFIRMATION_VERSION


def test_hostname_migration_is_idempotent_and_address_history_is_preserved(tmp_path):
    path = tmp_path / "hostname-migration.db"
    initialize_database(path)
    initialize_database(path)
    scope = create_hostname_scope(
        canonical_hostname="example.com",
        approved_addresses=["8.8.8.8", "8.8.4.4"],
        authorization_confirmed_at="2026-10-12T10:00:00",
        authorization_confirmation_version=HOSTNAME_CONFIRMATION_VERSION,
        authorization_source="test-confirmation",
        resolution_version="test-a-v1",
        db_path=path,
    )
    assert scope["approved_addresses"] == ["8.8.4.4", "8.8.8.8"]
    with get_connection(path) as connection:
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
        assert connection.execute(
            "SELECT COUNT(*) FROM scope_hostname_addresses WHERE scope_id = ?",
            (scope["id"],),
        ).fetchone()[0] == 2
        assert connection.execute(
            "SELECT MAX(version) FROM schema_migrations"
        ).fetchone()[0] == 46

    updated = reauthorize_hostname_scope(
        scope["id"],
        approved_addresses=["1.1.1.1"],
        authorization_confirmed_at="2026-10-12T10:05:00",
        authorization_confirmation_version=HOSTNAME_CONFIRMATION_VERSION,
        authorization_source="test-renewal",
        resolution_version="test-a-v1",
        db_path=path,
    )
    assert updated["approved_addresses"] == ["1.1.1.1"]
    assert get_scope(scope["id"], path) == updated
    assert list_hostname_addresses(scope["id"], path) == ["1.1.1.1"]
    with get_connection(path) as connection:
        old_addresses = connection.execute(
            "SELECT ipv4_address, approved FROM scope_hostname_addresses WHERE scope_id = ? ORDER BY ipv4_address",
            (scope["id"],),
        ).fetchall()
        assert old_addresses == [("1.1.1.1", 1), ("8.8.4.4", 0), ("8.8.8.8", 0)]
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
