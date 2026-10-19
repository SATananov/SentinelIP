import sqlite3
from datetime import datetime

from database.db import DB_PATH, get_connection, initialize_database
from database.management_audit import record_event
from database.scopes import create_private_scope_for_network
from services.target_policy import normalize_cidr


_UNSET = object()


def _timestamp() -> str:
    return datetime.now().isoformat(timespec="seconds")


def _as_network(row):
    if row is None:
        return None

    result = dict(row)
    result["authorized"] = bool(result["authorized"])
    result["enabled"] = bool(result["enabled"])
    return result


def create_network(
    cidr: str,
    name: str,
    description: str,
    authorized: bool,
    enabled: bool,
    db_path=DB_PATH,
    actor_type="API_CLIENT",
):
    normalized_cidr = normalize_cidr(cidr)
    if not authorized:
        raise ValueError("Network authorization must be explicit.")

    initialize_database(db_path)
    timestamp = _timestamp()

    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row
        connection.execute("BEGIN IMMEDIATE")
        cursor = connection.execute(
            """
            INSERT INTO networks (
                cidr,
                name,
                description,
                authorized,
                enabled,
                created_at,
                updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                normalized_cidr,
                name,
                description,
                int(authorized),
                int(enabled),
                timestamp,
                timestamp,
            ),
        )
        row = connection.execute(
            "SELECT * FROM networks WHERE id = ?",
            (cursor.lastrowid,),
        ).fetchone()
        scope_id = create_private_scope_for_network(connection, dict(row))
        record_event(connection, event_type="NETWORK_CREATED", entity_type="NETWORK",
                     entity_id=row['id'], scope_id=scope_id, scope_type="PRIVATE_NETWORK",
                     actor_type=actor_type,
                     new_state="AUTHORIZED_ENABLED" if enabled else "AUTHORIZED_DISABLED")

    return _as_network(row)


def list_networks(db_path=DB_PATH):
    initialize_database(db_path)

    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            "SELECT * FROM networks ORDER BY id ASC"
        ).fetchall()

    return [_as_network(row) for row in rows]


def get_network(network_id: int, db_path=DB_PATH):
    initialize_database(db_path)

    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row
        row = connection.execute(
            "SELECT * FROM networks WHERE id = ?",
            (network_id,),
        ).fetchone()

    return _as_network(row)


def update_network(
    network_id: int,
    *,
    name=_UNSET,
    description=_UNSET,
    authorized=_UNSET,
    enabled=_UNSET,
    db_path=DB_PATH,
    actor_type="API_CLIENT",
):
    if authorized is False:
        raise ValueError("Network authorization must remain explicit.")

    updates = []
    parameters = []

    for field, value in (
        ("name", name),
        ("description", description),
        ("authorized", authorized),
        ("enabled", enabled),
    ):
        if value is not _UNSET:
            updates.append(f"{field} = ?")
            parameters.append(int(value) if isinstance(value, bool) else value)

    initialize_database(db_path)

    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row
        connection.execute("BEGIN IMMEDIATE")
        prior = connection.execute("SELECT * FROM networks WHERE id=?", (network_id,)).fetchone()
        if prior is None:
            return None
        if updates:
            timestamp = _timestamp()
            updates.append("updated_at = ?")
            parameters.extend((timestamp, network_id))
            connection.execute(
                f"UPDATE networks SET {', '.join(updates)} WHERE id = ?",
                parameters,
            )
            scope_updates = []
            scope_parameters = []
            for field, value in (("name", name), ("description", description)):
                if value is not _UNSET:
                    scope_updates.append(f"{field} = ?")
                    scope_parameters.append(value)
            if scope_updates:
                scope_updates.append("updated_at = ?")
                scope_parameters.append(timestamp)
                connection.execute(
                    f"""
                    UPDATE authorized_scopes
                    SET {', '.join(scope_updates)}
                    WHERE id = (
                        SELECT scope_id FROM network_scope_links
                        WHERE network_id = ?
                    )
                    """,
                    (*scope_parameters, network_id),
                )
            if enabled is not _UNSET and bool(prior['enabled']) != bool(enabled):
                record_event(connection, event_type="NETWORK_ENABLED" if enabled else "NETWORK_DISABLED",
                             entity_type="NETWORK", entity_id=network_id, actor_type=actor_type,
                             previous_state="ENABLED" if prior['enabled'] else "DISABLED",
                             new_state="ENABLED" if enabled else "DISABLED")

        connection.row_factory = sqlite3.Row
        row = connection.execute(
            "SELECT * FROM networks WHERE id = ?",
            (network_id,),
        ).fetchone()

    return _as_network(row)


def delete_network(network_id: int, db_path=DB_PATH, actor_type="API_CLIENT") -> bool:
    initialize_database(db_path)

    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row
        connection.execute("BEGIN IMMEDIATE")
        network = connection.execute("SELECT * FROM networks WHERE id=?", (network_id,)).fetchone()
        if network is None:
            return False
        scope_row = connection.execute(
            "SELECT scope_id FROM network_scope_links WHERE network_id = ?",
            (network_id,),
        ).fetchone()
        record_event(connection, event_type="NETWORK_DELETED", entity_type="NETWORK",
                     entity_id=network_id, scope_id=scope_row[0] if scope_row is not None else None,
                     actor_type=actor_type, previous_state="ENABLED" if network['enabled'] else "DISABLED")
        cursor = connection.execute(
            "DELETE FROM networks WHERE id = ?",
            (network_id,),
        )
        if cursor.rowcount and scope_row is not None:
            connection.execute(
                "DELETE FROM authorized_scopes WHERE id = ?",
                (scope_row[0],),
            )

    return cursor.rowcount > 0
