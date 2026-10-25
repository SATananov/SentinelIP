import json
import sqlite3

from database.db import DB_PATH, connection_context, get_connection, initialize_database
from services.change_models import ChangeRecord, serialize_change_value


def _as_change(row):
    if row is None:
        return None

    result = dict(row)
    result["metadata"] = None

    if result.get("metadata_json") is not None:
        result["metadata"] = json.loads(result["metadata_json"])

    return result


def create_change(
    change: ChangeRecord,
    db_path=DB_PATH,
    conn: sqlite3.Connection | None = None,
):
    if not isinstance(change, ChangeRecord):
        raise TypeError("change must be a ChangeRecord.")

    created_at = change.observed_at.isoformat(timespec="seconds")
    metadata_json = serialize_change_value(change.metadata_json)

    with connection_context(db_path, conn=conn) as connection:
        if conn is None:
            connection.row_factory = sqlite3.Row
        cursor = connection.execute(
            """
            INSERT INTO changes (
                change_type,
                device_id,
                network_id,
                port_id,
                service_id,
                observed_at,
                source,
                confidence,
                previous_value,
                current_value,
                evidence_type,
                message,
                correlation_key,
                metadata_json,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                change.change_type.value,
                change.device_id,
                change.network_id,
                change.port_id,
                change.service_id,
                created_at,
                change.source,
                change.confidence.value,
                serialize_change_value(change.previous_value),
                serialize_change_value(change.current_value),
                change.evidence_type,
                change.message,
                change.correlation_key,
                metadata_json,
                created_at,
            ),
        )
        row = connection.execute(
            "SELECT * FROM changes WHERE id = ?",
            (cursor.lastrowid,),
        ).fetchone()

    return _as_change(row)


def get_change(change_id: int, db_path=DB_PATH):
    initialize_database(db_path)

    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row
        row = connection.execute(
            "SELECT * FROM changes WHERE id = ?",
            (change_id,),
        ).fetchone()

    return _as_change(row)


def list_changes(limit: int | None = None, db_path=DB_PATH):
    initialize_database(db_path)
    parameters = []
    limit_clause = ""

    if limit is not None:
        limit_clause = "LIMIT ?"
        parameters.append(limit)

    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            f"""
            SELECT * FROM changes
            ORDER BY observed_at ASC, id ASC
            {limit_clause}
            """,
            parameters,
        ).fetchall()

    return [_as_change(row) for row in rows]


def list_device_changes(device_id: int, db_path=DB_PATH):
    return _list_filtered("device_id", device_id, db_path)


def list_network_changes(network_id: int, db_path=DB_PATH):
    return _list_filtered("network_id", network_id, db_path)


def list_changes_by_type(change_type: str, db_path=DB_PATH):
    return _list_filtered("change_type", change_type, db_path)


def _list_filtered(field: str, value, db_path):
    if field not in {
        "device_id",
        "network_id",
        "change_type",
    }:
        raise ValueError("Unsupported change filter.")

    initialize_database(db_path)

    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            f"""
            SELECT * FROM changes
            WHERE {field} = ?
            ORDER BY observed_at ASC, id ASC
            """,
            (value,),
        ).fetchall()

    return [_as_change(row) for row in rows]
