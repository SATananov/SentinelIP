import sqlite3
from datetime import datetime

from database.db import DB_PATH, get_connection, initialize_database
from services.scope_models import ScopeError, ScopeType
from services.public_target_policy import normalize_public_ipv4
from services.target_policy import normalize_cidr


def _timestamp() -> str:
    return datetime.now().isoformat(timespec="seconds")


def _as_scope(row):
    if row is None:
        return None
    result = dict(row)
    result["authorized"] = bool(result["authorized"])
    result["enabled"] = bool(result["enabled"])
    return result


def _normalize_scope_type(scope_type: str | ScopeType) -> str:
    try:
        return ScopeType(scope_type).value
    except (TypeError, ValueError) as exc:
        raise ScopeError("Scope type is unsupported.") from exc


def _normalize_target(scope_type: str, canonical_target: str) -> str:
    if not isinstance(canonical_target, str) or not canonical_target.strip():
        raise ScopeError("Scope target must be a non-empty string.")
    target = canonical_target.strip()
    if scope_type == ScopeType.PRIVATE_NETWORK.value:
        return normalize_cidr(target)
    if scope_type == ScopeType.PUBLIC_IPV4.value:
        return normalize_public_ipv4(target)
    return target


def _insert_scope(
    connection,
    *,
    scope_type,
    canonical_target,
    name,
    description,
    authorized,
    enabled,
    authorization_confirmed_at,
    authorization_confirmation_version,
    authorization_source,
    created_at,
    updated_at,
) -> int:
    normalized_type = _normalize_scope_type(scope_type)
    normalized_target = _normalize_target(normalized_type, canonical_target)
    if type(authorized) is not bool or type(enabled) is not bool:
        raise ScopeError("Scope authorization and enabled state must be boolean.")
    if authorized and not all(
        isinstance(value, str) and value.strip()
        for value in (
            authorization_confirmed_at,
            authorization_confirmation_version,
            authorization_source,
        )
    ):
        raise ScopeError(
            "Authorized scopes require persisted confirmation metadata."
        )

    cursor = connection.execute(
        """
        INSERT INTO authorized_scopes (
            scope_type, canonical_target, name, description, authorized, enabled,
            authorization_confirmed_at, authorization_confirmation_version,
            authorization_source, created_at, updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            normalized_type,
            normalized_target,
            name,
            description,
            int(authorized),
            int(enabled),
            authorization_confirmed_at,
            authorization_confirmation_version,
            authorization_source,
            created_at,
            updated_at,
        ),
    )
    return cursor.lastrowid


def create_private_scope_for_network(connection, network: dict) -> int:
    """Create a confirmed scope alongside a newly inserted legacy network."""
    if not isinstance(network, dict):
        raise ScopeError("A persisted network record is required.")
    created_at = network.get("created_at")
    updated_at = network.get("updated_at")
    scope_id = _insert_scope(
        connection,
        scope_type=ScopeType.PRIVATE_NETWORK,
        canonical_target=network.get("cidr"),
        name=network.get("name", ""),
        description=network.get("description", ""),
        authorized=network.get("authorized") == 1,
        enabled=network.get("enabled") == 1,
        authorization_confirmed_at=created_at,
        authorization_confirmation_version="private_network_create_v1",
        authorization_source="existing_network_authorization_flag",
        created_at=created_at,
        updated_at=updated_at,
    )
    connection.execute(
        "INSERT INTO network_scope_links (network_id, scope_id) VALUES (?, ?)",
        (network["id"], scope_id),
    )
    return scope_id


def create_scope(
    *,
    scope_type: str | ScopeType,
    canonical_target: str,
    name: str = "",
    description: str = "",
    authorized: bool,
    enabled: bool,
    authorization_confirmed_at: str | None = None,
    authorization_confirmation_version: str | None = None,
    authorization_source: str | None = None,
    db_path=DB_PATH,
):
    normalized_type = _normalize_scope_type(scope_type)
    target = _normalize_target(normalized_type, canonical_target)
    if not isinstance(name, str) or not isinstance(description, str):
        raise ScopeError("Scope name and description must be strings.")
    timestamp = _timestamp()
    initialize_database(db_path)

    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row
        scope_id = _insert_scope(
            connection,
            scope_type=normalized_type,
            canonical_target=target,
            name=name,
            description=description,
            authorized=authorized,
            enabled=enabled,
            authorization_confirmed_at=authorization_confirmed_at,
            authorization_confirmation_version=authorization_confirmation_version,
            authorization_source=authorization_source,
            created_at=timestamp,
            updated_at=timestamp,
        )
        row = connection.execute(
            """
            SELECT authorized_scopes.*, network_scope_links.network_id
            FROM authorized_scopes
            LEFT JOIN network_scope_links
              ON network_scope_links.scope_id = authorized_scopes.id
            WHERE authorized_scopes.id = ?
            """,
            (scope_id,),
        ).fetchone()
    return _as_scope(row)


def get_scope(scope_id: int, db_path=DB_PATH):
    initialize_database(db_path)
    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row
        row = connection.execute(
            """
            SELECT authorized_scopes.*, network_scope_links.network_id
            FROM authorized_scopes
            LEFT JOIN network_scope_links
              ON network_scope_links.scope_id = authorized_scopes.id
            WHERE authorized_scopes.id = ?
            """,
            (scope_id,),
        ).fetchone()
    return _as_scope(row)


def list_scopes(scope_type: str | ScopeType | None = None, db_path=DB_PATH):
    initialize_database(db_path)
    parameters = ()
    where_clause = ""
    if scope_type is not None:
        where_clause = "WHERE authorized_scopes.scope_type = ?"
        parameters = (_normalize_scope_type(scope_type),)

    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            f"""
            SELECT authorized_scopes.*, network_scope_links.network_id
            FROM authorized_scopes
            LEFT JOIN network_scope_links
              ON network_scope_links.scope_id = authorized_scopes.id
            {where_clause}
            ORDER BY authorized_scopes.id ASC
            """,
            parameters,
        ).fetchall()
    return [_as_scope(row) for row in rows]


def get_scope_for_network(network_id: int, db_path=DB_PATH):
    initialize_database(db_path)
    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row
        row = connection.execute(
            """
            SELECT authorized_scopes.*, network_scope_links.network_id
            FROM network_scope_links
            JOIN authorized_scopes
              ON authorized_scopes.id = network_scope_links.scope_id
            WHERE network_scope_links.network_id = ?
            """,
            (network_id,),
        ).fetchone()
    return _as_scope(row)


def link_network_scope(network_id: int, scope_id: int, db_path=DB_PATH) -> None:
    """Link a private scope to its matching legacy network exactly once."""
    initialize_database(db_path)
    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row
        row = connection.execute(
            """
            SELECT networks.cidr, authorized_scopes.scope_type,
                   authorized_scopes.canonical_target
            FROM networks
            JOIN authorized_scopes ON authorized_scopes.id = ?
            WHERE networks.id = ?
            """,
            (scope_id, network_id),
        ).fetchone()
        if row is None:
            raise ScopeError("Network and scope records must exist.")
        if (
            row["scope_type"] != ScopeType.PRIVATE_NETWORK.value
            or normalize_cidr(row["cidr"]) != row["canonical_target"]
        ):
            raise ScopeError("Scope target does not match the private network.")
        connection.execute(
            "INSERT INTO network_scope_links (network_id, scope_id) VALUES (?, ?)",
            (network_id, scope_id),
        )


def update_scope_enabled(scope_id: int, enabled: bool, db_path=DB_PATH):
    if type(enabled) is not bool:
        raise ScopeError("Scope enabled state must be boolean.")
    initialize_database(db_path)
    timestamp = _timestamp()
    with get_connection(db_path) as connection:
        connection.execute(
            """
            UPDATE authorized_scopes
            SET enabled = ?, updated_at = ?
            WHERE id = ?
            """,
            (int(enabled), timestamp, scope_id),
        )
    return get_scope(scope_id, db_path)
