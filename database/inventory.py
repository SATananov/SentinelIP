import sqlite3
from datetime import datetime

from database.db import DB_PATH, get_connection, initialize_database


def _as_device(row):
    return dict(row) if row is not None else None


def _as_observation(row):
    return dict(row) if row is not None else None


def create_device(
    stable_key: str,
    network_id: int,
    mac_address: str | None,
    hostname: str | None,
    vendor: str | None,
    first_seen: str,
    last_seen: str,
    last_ip_address: str,
    status: str,
    identity_confidence: str,
    db_path=DB_PATH,
):
    initialize_database(db_path)

    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row
        connection.execute(
            """
            INSERT INTO devices (
                stable_key,
                network_id,
                mac_address,
                hostname,
                vendor,
                first_seen,
                last_seen,
                last_ip_address,
                status,
                identity_confidence,
                created_at,
                updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                stable_key,
                network_id,
                mac_address,
                hostname,
                vendor,
                first_seen,
                last_seen,
                last_ip_address,
                status,
                identity_confidence,
                first_seen,
                last_seen,
            ),
        )
        row = connection.execute(
            "SELECT * FROM devices WHERE stable_key = ?",
            (stable_key,),
        ).fetchone()

    return _as_device(row)


def get_device(device_id: int, db_path=DB_PATH):
    initialize_database(db_path)

    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row
        row = connection.execute(
            "SELECT * FROM devices WHERE id = ?",
            (device_id,),
        ).fetchone()

    return _as_device(row)


def find_device_by_stable_key(stable_key: str, db_path=DB_PATH):
    initialize_database(db_path)

    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row
        row = connection.execute(
            "SELECT * FROM devices WHERE stable_key = ?",
            (stable_key,),
        ).fetchone()

    return _as_device(row)


def list_devices(network_id: int | None = None, db_path=DB_PATH):
    initialize_database(db_path)
    parameters = []
    where_clause = ""

    if network_id is not None:
        where_clause = "WHERE network_id = ?"
        parameters.append(network_id)

    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            f"""
            SELECT *
            FROM devices
            {where_clause}
            ORDER BY id ASC
            """,
            parameters,
        ).fetchall()

    return [_as_device(row) for row in rows]


def update_device_state(
    device_id: int,
    *,
    last_seen: str,
    last_ip_address: str,
    status: str,
    mac_address: str | None,
    hostname: str | None,
    vendor: str | None,
    db_path=DB_PATH,
):
    initialize_database(db_path)

    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row
        connection.execute(
            """
            UPDATE devices
            SET
                mac_address = COALESCE(?, mac_address),
                hostname = COALESCE(?, hostname),
                vendor = COALESCE(?, vendor),
                last_seen = ?,
                last_ip_address = ?,
                status = ?,
                updated_at = ?
            WHERE id = ?
            """,
            (
                mac_address,
                hostname,
                vendor,
                last_seen,
                last_ip_address,
                status,
                last_seen,
                device_id,
            ),
        )
        row = connection.execute(
            "SELECT * FROM devices WHERE id = ?",
            (device_id,),
        ).fetchone()

    return _as_device(row)


def save_observation(
    device_id: int,
    network_id: int,
    ip_address: str,
    mac_address: str | None,
    hostname: str | None,
    vendor: str | None,
    status: str,
    observed_at: str,
    source: str,
    db_path=DB_PATH,
):
    initialize_database(db_path)

    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row
        cursor = connection.execute(
            """
            INSERT INTO device_observations (
                device_id,
                network_id,
                ip_address,
                mac_address,
                hostname,
                vendor,
                status,
                observed_at,
                source
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                device_id,
                network_id,
                ip_address,
                mac_address,
                hostname,
                vendor,
                status,
                observed_at,
                source,
            ),
        )
        row = connection.execute(
            "SELECT * FROM device_observations WHERE id = ?",
            (cursor.lastrowid,),
        ).fetchone()

    return _as_observation(row)


def list_observations(device_id: int, db_path=DB_PATH):
    initialize_database(db_path)

    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            """
            SELECT *
            FROM device_observations
            WHERE device_id = ?
            ORDER BY observed_at ASC, id ASC
            """,
            (device_id,),
        ).fetchall()

    return [_as_observation(row) for row in rows]


def mark_devices_offline(
    network_id: int,
    observed_device_ids: set[int],
    observed_at: str,
    db_path=DB_PATH,
):
    initialize_database(db_path)
    parameters = [observed_at, network_id]
    exclusion = ""

    if observed_device_ids:
        placeholders = ", ".join("?" for _ in observed_device_ids)
        exclusion = f"AND id NOT IN ({placeholders})"
        parameters.extend(sorted(observed_device_ids))

    with get_connection(db_path) as connection:
        connection.execute(
            f"""
            UPDATE devices
            SET status = 'OFFLINE', updated_at = ?
            WHERE network_id = ?
              {exclusion}
              AND status != 'OFFLINE'
            """,
            parameters,
        )


def timestamp_text(value: datetime) -> str:
    return value.isoformat(timespec="seconds")