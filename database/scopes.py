import sqlite3
from datetime import datetime

from database.db import DB_PATH, get_connection, initialize_database
from database.management_audit import record_event
from services.scope_models import ScopeError, ScopeType
from services.public_target_policy import normalize_public_ipv4
from services.hostname_policy import normalize_hostname
from services.public_cidr_policy import normalize_public_cidr, public_cidr_addresses
from services.target_policy import normalize_cidr


def _timestamp() -> str:
    return datetime.now().isoformat(timespec="seconds")


def _as_scope(row):
    if row is None:
        return None
    result = dict(row)
    result["authorized"] = bool(result["authorized"])
    result["enabled"] = bool(result["enabled"])
    result["approved_addresses"] = []
    result["address_count"] = None
    if result["scope_type"] == "PUBLIC_CIDR":
        try:
            result["address_count"] = len(public_cidr_addresses(result["canonical_target"]))
        except ValueError:
            result["address_count"] = None
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
    if scope_type == ScopeType.PUBLIC_CIDR.value:
        return normalize_public_cidr(target)
    if scope_type == ScopeType.HOSTNAME.value:
        return normalize_hostname(target)
    return target


def _hostname_addresses(connection, scope_id: int) -> list[str]:
    rows = connection.execute(
        """SELECT ipv4_address FROM scope_hostname_addresses
           WHERE scope_id = ? AND approved = 1 ORDER BY ipv4_address ASC""",
        (scope_id,),
    ).fetchall()
    return [row[0] for row in rows]


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
    scope_id = cursor.lastrowid
    if normalized_type == ScopeType.PUBLIC_CIDR.value:
        connection.executemany(
            "INSERT INTO scope_cidr_addresses (scope_id, canonical_cidr, ipv4_address) VALUES (?, ?, ?)",
            [(scope_id, normalized_target, address) for address in public_cidr_addresses(normalized_target)],
        )
    return scope_id


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
    actor_type="API_CLIENT",
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
        if normalized_type != ScopeType.PRIVATE_NETWORK.value and authorized:
            record_event(connection, event_type="SCOPE_AUTHORIZED", entity_type="SCOPE",
                         entity_id=scope_id, scope_id=scope_id, scope_type=normalized_type,
                         actor_type=actor_type,
                         new_state="AUTHORIZED")
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
        result = _as_scope(row)
        if result is not None and result["scope_type"] == ScopeType.HOSTNAME.value:
            result["approved_addresses"] = _hostname_addresses(connection, scope_id)
    return result


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
        result = _as_scope(row)
        if result is not None and result["scope_type"] == ScopeType.HOSTNAME.value:
            result["approved_addresses"] = _hostname_addresses(connection, scope_id)
    return result


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
        results = [_as_scope(row) for row in rows]
        hostname_scope_ids = [
            row["id"] for row in results
            if row["scope_type"] == ScopeType.HOSTNAME.value
        ]
        if hostname_scope_ids:
            placeholders = ",".join("?" for _ in hostname_scope_ids)
            address_rows = connection.execute(
                f"""SELECT scope_id, ipv4_address FROM scope_hostname_addresses
                    WHERE approved = 1 AND scope_id IN ({placeholders})
                    ORDER BY scope_id, ipv4_address""",
                hostname_scope_ids,
            ).fetchall()
            addresses_by_scope = {}
            for address_row in address_rows:
                addresses_by_scope.setdefault(address_row["scope_id"], []).append(
                    address_row["ipv4_address"]
                )
            for result in results:
                if result["scope_type"] == ScopeType.HOSTNAME.value:
                    result["approved_addresses"] = addresses_by_scope.get(result["id"], [])
    return results


def list_hostname_addresses(scope_id: int, db_path=DB_PATH) -> list[str]:
    initialize_database(db_path)
    with get_connection(db_path) as connection:
        return _hostname_addresses(connection, scope_id)


def create_hostname_scope(
    *,
    canonical_hostname: str,
    approved_addresses: list[str],
    name: str = "",
    description: str = "",
    authorization_confirmed_at: str,
    authorization_confirmation_version: str,
    authorization_source: str,
    resolution_version: str,
    db_path=DB_PATH,
    actor_type="API_CLIENT",
):
    hostname = normalize_hostname(canonical_hostname)
    addresses = _normalize_hostname_addresses(approved_addresses)
    timestamp = _timestamp()
    initialize_database(db_path)
    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row
        scope_id = _insert_scope(
            connection,
            scope_type=ScopeType.HOSTNAME,
            canonical_target=hostname,
            name=name,
            description=description,
            authorized=True,
            enabled=True,
            authorization_confirmed_at=authorization_confirmed_at,
            authorization_confirmation_version=authorization_confirmation_version,
            authorization_source=authorization_source,
            created_at=timestamp,
            updated_at=timestamp,
        )
        _write_hostname_addresses(connection, scope_id, addresses, timestamp, resolution_version)
        connection.execute(
            """UPDATE authorized_scopes SET resolution_verified_at = ?,
               resolution_version = ?, resolution_status = 'CURRENT' WHERE id = ?""",
            (timestamp, resolution_version, scope_id),
        )
        record_event(connection, event_type="SCOPE_AUTHORIZED", entity_type="SCOPE",
                     entity_id=scope_id, scope_id=scope_id, scope_type="HOSTNAME",
                     actor_type=actor_type,
                     new_state="AUTHORIZED")
        row = connection.execute(
            """SELECT authorized_scopes.*, NULL AS network_id
               FROM authorized_scopes WHERE id = ?""",
            (scope_id,),
        ).fetchone()
        result = _as_scope(row)
        result["approved_addresses"] = _hostname_addresses(connection, scope_id)
    return result


def reauthorize_hostname_scope(
    scope_id: int,
    *,
    approved_addresses: list[str],
    authorization_confirmed_at: str,
    authorization_confirmation_version: str,
    authorization_source: str,
    resolution_version: str,
    db_path=DB_PATH,
    actor_type="API_CLIENT",
):
    addresses = _normalize_hostname_addresses(approved_addresses)
    timestamp = _timestamp()
    initialize_database(db_path)
    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row
        connection.execute("BEGIN IMMEDIATE")
        scope = connection.execute(
            "SELECT * FROM authorized_scopes WHERE id = ?", (scope_id,)
        ).fetchone()
        if scope is None or scope["scope_type"] != ScopeType.HOSTNAME.value:
            raise ScopeError("A persisted hostname scope is required.")
        record_event(connection, event_type="SCOPE_REAUTHORIZED", entity_type="SCOPE",
                     entity_id=scope_id, scope_id=scope_id, scope_type=scope["scope_type"],
                     actor_type=actor_type)
        connection.execute(
            """UPDATE authorized_scopes SET authorized = 1,
               authorization_confirmed_at = ?, authorization_confirmation_version = ?,
               authorization_source = ?, resolution_verified_at = ?, resolution_version = ?,
               resolution_status = 'CURRENT', updated_at = ? WHERE id = ?""",
            (
                authorization_confirmed_at,
                authorization_confirmation_version,
                authorization_source,
                timestamp,
                resolution_version,
                timestamp,
                scope_id,
            ),
        )
        connection.execute(
            "UPDATE scope_hostname_addresses SET approved = 0 WHERE scope_id = ?",
            (scope_id,),
        )
        _write_hostname_addresses(connection, scope_id, addresses, timestamp, resolution_version)
        row = connection.execute(
            """SELECT authorized_scopes.*, NULL AS network_id
               FROM authorized_scopes WHERE id = ?""",
            (scope_id,),
        ).fetchone()
        result = _as_scope(row)
        result["approved_addresses"] = _hostname_addresses(connection, scope_id)
    return result


def mark_hostname_resolution_stale(scope_id: int, db_path=DB_PATH) -> None:
    initialize_database(db_path)
    with get_connection(db_path) as connection:
        connection.execute(
            """UPDATE authorized_scopes SET resolution_status = 'REAUTH_REQUIRED',
               updated_at = ? WHERE id = ? AND scope_type = 'HOSTNAME'""",
            (_timestamp(), scope_id),
        )


def _normalize_hostname_addresses(addresses: list[str]) -> tuple[str, ...]:
    if not isinstance(addresses, list) or not addresses:
        raise ScopeError("At least one approved public IPv4 address is required.")
    normalized = tuple(normalize_public_ipv4(address) for address in addresses)
    if len(normalized) != len(set(normalized)):
        raise ScopeError("Approved IPv4 addresses must be unique.")
    return tuple(sorted(normalized))


def _write_hostname_addresses(connection, scope_id, addresses, timestamp, version):
    connection.executemany(
        """INSERT INTO scope_hostname_addresses (
            scope_id, ipv4_address, approved, approved_at, verified_at, resolution_version
        ) VALUES (?, ?, 1, ?, ?, ?)
        ON CONFLICT(scope_id, ipv4_address) DO UPDATE SET
            approved = 1, approved_at = excluded.approved_at,
            verified_at = excluded.verified_at,
            resolution_version = excluded.resolution_version""",
        [
            (scope_id, address, timestamp, timestamp, version)
            for address in addresses
        ],
    )


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


def require_cidr_membership(scope, db_path=DB_PATH) -> tuple[str, ...]:
    """Fail closed if persisted membership and the validated scope disagree."""
    from services.scope_authorization import require_public_cidr_scope, ScopeAuthorizationError
    target = require_public_cidr_scope(scope)
    expected = public_cidr_addresses(target)
    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row
        row = connection.execute("SELECT * FROM authorized_scopes WHERE id = ?", (scope["id"],)).fetchone()
        stored = _as_scope(row)
        if require_public_cidr_scope(stored) != target:
            raise ScopeAuthorizationError("The persisted scope target changed.")
        actual = connection.execute(
            "SELECT canonical_cidr, ipv4_address FROM scope_cidr_addresses WHERE scope_id = ?",
            (scope["id"],),
        ).fetchall()
    if {tuple(row) for row in actual} != {(target, address) for address in expected}:
        raise ScopeAuthorizationError("Persisted public CIDR membership does not match the authorized range.")
    return expected
