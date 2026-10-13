"""Persistence and bounded read queries for normalized perimeter evidence."""
import json
import sqlite3
from datetime import datetime, timezone

from database.db import DB_PATH, get_connection, initialize_database
from services.perimeter_models import PerimeterEvent


def _row(row):
    if row is None:
        return None
    result = dict(row)
    result["metadata"] = json.loads(result.pop("metadata_json")) if result.get("metadata_json") else None
    return result


def persist_perimeter_event(event: PerimeterEvent, db_path=DB_PATH):
    if not isinstance(event, PerimeterEvent):
        raise TypeError("PerimeterEvent is required.")
    initialize_database(db_path)
    metadata_json = (
        json.dumps(event.metadata, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        if event.metadata is not None else None
    )
    received_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    values = (
        event.external_event_id, event.site_id, event.sensor_id, event.source_type.value,
        event.source_key, event.event_type.value, event.direction.value, event.action.value,
        event.protocol.value, event.source_ip, event.destination_ip, event.source_port,
        event.destination_port, event.interface, event.source_reference, event.raw_event_hash,
        metadata_json, event.observed_at.isoformat(), received_at,
    )
    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row
        connection.execute("BEGIN IMMEDIATE")
        existing = connection.execute(
            """SELECT * FROM perimeter_events
               WHERE site_id=? AND source_key=? AND external_event_id=?""",
            (event.site_id, event.source_key, event.external_event_id),
        ).fetchone()
        if existing is not None:
            comparable = dict(existing)
            candidate_columns = (
                "external_event_id", "site_id", "sensor_id", "source_type", "source_key", "event_type",
                "direction", "action", "protocol", "source_ip", "destination_ip", "source_port",
                "destination_port", "interface", "source_reference", "raw_event_hash", "metadata_json", "observed_at",
            )
            candidate = dict(zip(candidate_columns, values[:-1]))
            if any(comparable[column] != candidate[column] for column in candidate_columns):
                raise sqlite3.IntegrityError("Perimeter event identity conflicts with existing evidence.")
            result = _row(existing)
            result["idempotent"] = True
            return result

        cursor = connection.execute(
            """INSERT INTO perimeter_events(
                external_event_id, site_id, sensor_id, source_type, source_key, event_type,
                direction, action, protocol, source_ip, destination_ip, source_port,
                destination_port, interface, source_reference, raw_event_hash, metadata_json,
                observed_at, received_at
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            values,
        )
        row = connection.execute("SELECT * FROM perimeter_events WHERE id=?", (cursor.lastrowid,)).fetchone()
        result = _row(row)
        result["idempotent"] = False
        return result


def get_perimeter_event(event_id: int, db_path=DB_PATH):
    initialize_database(db_path)
    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row
        return _row(connection.execute("SELECT * FROM perimeter_events WHERE id=?", (event_id,)).fetchone())


def query_perimeter_events(*, limit=20, offset=0, site_id=None, sensor_id=None, source_type=None,
                           direction=None, action=None, protocol=None, source_ip=None,
                           destination_ip=None, destination_port=None, db_path=DB_PATH):
    initialize_database(db_path)
    clauses, params = [], []
    for column, value in (
        ("site_id", site_id), ("sensor_id", sensor_id), ("source_type", source_type),
        ("direction", direction), ("action", action), ("protocol", protocol),
        ("source_ip", source_ip), ("destination_ip", destination_ip),
        ("destination_port", destination_port),
    ):
        if value is not None:
            clauses.append(f"{column} = ?")
            params.append(value)
    where = " WHERE " + " AND ".join(clauses) if clauses else ""
    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row
        total = connection.execute(f"SELECT COUNT(*) FROM perimeter_events{where}", tuple(params)).fetchone()[0]
        rows = connection.execute(
            f"""SELECT * FROM perimeter_events{where}
                ORDER BY observed_at DESC, id DESC LIMIT ? OFFSET ?""",
            (*params, limit, offset),
        ).fetchall()
        return {"total": total, "items": [_row(row) for row in rows]}
