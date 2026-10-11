import sqlite3
from datetime import datetime

from database.db import DB_PATH, get_connection, initialize_database
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
):
    normalized_cidr = normalize_cidr(cidr)
    if not authorized:
        raise ValueError("Network authorization must be explicit.")

    initialize_database(db_path)
    timestamp = _timestamp()

    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row
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
        if updates:
            timestamp = _timestamp()
            updates.append("updated_at = ?")
            parameters.extend((timestamp, network_id))
            connection.execute(
                f"UPDATE networks SET {', '.join(updates)} WHERE id = ?",
                parameters,
            )

        connection.row_factory = sqlite3.Row
        row = connection.execute(
            "SELECT * FROM networks WHERE id = ?",
            (network_id,),
        ).fetchone()

    return _as_network(row)


def delete_network(network_id: int, db_path=DB_PATH) -> bool:
    initialize_database(db_path)

    with get_connection(db_path) as connection:
        cursor = connection.execute(
            "DELETE FROM networks WHERE id = ?",
            (network_id,),
        )

    return cursor.rowcount > 0