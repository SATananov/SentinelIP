import sqlite3

from database.db import get_connection, initialize_database
from database.migrations import MIGRATIONS, apply_migrations
from database.networks import create_network
from database.scopes import (
    create_scope,
    get_scope,
    get_scope_for_network,
    list_scopes,
    link_network_scope,
    update_scope_enabled,
)
from services.scope_models import ScopeType


def test_migration_backfills_legacy_networks_and_preserves_inventory(tmp_path):
    path = tmp_path / "legacy-scopes.db"
    with sqlite3.connect(path) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute(
            "CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)"
        )
        connection.execute(
            """CREATE TABLE events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                username TEXT,
                event_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                message TEXT NOT NULL,
                event_count INTEGER NOT NULL
            )"""
        )
        for version, _ in MIGRATIONS[:25]:
            connection.execute(
                "INSERT INTO schema_migrations VALUES (?, 'legacy')", (version,)
            )
        for _, statements in MIGRATIONS[:25]:
            statements = (statements,) if isinstance(statements, str) else statements
            for statement in statements:
                connection.execute(statement)
        connection.execute(
            """INSERT INTO networks
               (id, cidr, name, description, authorized, enabled, created_at, updated_at)
               VALUES (41, '192.168.4.0/24', 'Legacy LAN', 'kept', 1, 1,
                       '2026-01-02T03:04:05', '2026-01-02T03:04:05')"""
        )
        connection.execute(
            """INSERT INTO devices
               (id, stable_key, network_id, first_seen, last_seen, last_ip_address,
                status, identity_confidence, created_at, updated_at)
               VALUES (51, 'network:41:ip:192.168.4.8', 41, '2026-01-02',
                       '2026-01-02', '192.168.4.8', 'ONLINE', 'LOW',
                       '2026-01-02', '2026-01-02')"""
        )
        connection.commit()

    initialize_database(path)
    initialize_database(path)
    scope = get_scope_for_network(41, path)

    assert scope["scope_type"] == "PRIVATE_NETWORK"
    assert scope["canonical_target"] == "192.168.4.0/24"
    assert scope["authorized"] is True
    assert scope["enabled"] is True
    assert scope["authorization_confirmed_at"] == "2026-01-02T03:04:05"
    assert scope["authorization_confirmation_version"] == "legacy_network_authorization_v1"
    assert scope["authorization_source"] == "legacy_network_record_migration_26"
    with get_connection(path) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM network_scope_links WHERE network_id=41"
        ).fetchone()[0] == 1
        assert connection.execute(
            "SELECT network_id FROM devices WHERE id=51"
        ).fetchone()[0] == 41
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []


def test_network_creation_atomically_creates_confirmed_scope(tmp_path):
    path = tmp_path / "new-scope.db"
    network = create_network(
        "192.168.8.4/24", "LAN", "memo", True, True, db_path=path
    )

    scope = get_scope_for_network(network["id"], path)
    assert scope["scope_type"] == "PRIVATE_NETWORK"
    assert scope["canonical_target"] == network["cidr"] == "192.168.8.0/24"
    assert scope["authorized"] is True
    assert scope["enabled"] is True
    assert scope["authorization_confirmed_at"] == network["created_at"]
    assert scope["authorization_confirmation_version"] == "private_network_create_v1"
    assert scope["authorization_source"] == "existing_network_authorization_flag"


def test_scope_crud_and_confirmation_metadata(tmp_path):
    path = tmp_path / "scope-crud.db"
    scope = create_scope(
        scope_type=ScopeType.HOSTNAME,
        canonical_target="example.test",
        name="Future inert scope",
        authorized=True,
        enabled=False,
        authorization_confirmed_at="2026-10-12T10:00:00",
        authorization_confirmation_version="test-confirmation-v1",
        authorization_source="test-fixture",
        db_path=path,
    )

    assert get_scope(scope["id"], path) == scope
    assert list_scopes(db_path=path) == [scope]
    assert list_scopes(ScopeType.HOSTNAME, path) == [scope]
    assert update_scope_enabled(scope["id"], True, path)["enabled"] is True
    assert update_scope_enabled(scope["id"], False, path)["enabled"] is False


def test_network_scope_link_is_unique_and_type_checked(tmp_path):
    path = tmp_path / "scope-link.db"
    network = create_network("10.9.0.0/24", "LAN", "", True, True, path)
    linked = get_scope_for_network(network["id"], path)

    with sqlite3.connect(path) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        try:
            connection.execute(
                "INSERT INTO network_scope_links(network_id, scope_id) VALUES (?, ?)",
                (network["id"], linked["id"]),
            )
            connection.commit()
            assert False, "duplicate network association should violate uniqueness"
        except sqlite3.IntegrityError:
            connection.rollback()

    other = create_network("10.10.0.0/24", "Other", "", True, True, path)
    try:
        link_network_scope(network["id"], get_scope_for_network(other["id"], path)["id"], path)
        assert False, "mismatched network scope should be rejected"
    except ValueError:
        pass
