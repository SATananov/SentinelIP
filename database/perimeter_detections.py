"""Persistence and bounded read queries for deterministic perimeter detections."""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone

from database.db import DB_PATH, get_connection, initialize_database
from services.perimeter_detection_models import PerimeterDetection


def _decode(row, connection=None):
    if row is None:
        return None
    result = dict(row)
    raw_ids = result.pop("event_ids_json")
    result["event_ids"] = json.loads(raw_ids)
    return result


def persist_perimeter_detection(candidate: PerimeterDetection, db_path=DB_PATH):
    if not isinstance(candidate, PerimeterDetection):
        raise TypeError("PerimeterDetection is required.")
    initialize_database(db_path)
    created_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    event_ids_json = json.dumps(candidate.event_ids, separators=(",", ":"))
    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row
        for event_id in candidate.event_ids:
            event = connection.execute("SELECT * FROM perimeter_events WHERE id=?", (event_id,)).fetchone()
            if event is None or event["site_id"] != candidate.site_id:
                raise sqlite3.IntegrityError("Perimeter detection evidence is missing or site-mismatched.")
        existing = connection.execute(
            "SELECT * FROM perimeter_detections WHERE stable_key=?", (candidate.stable_key,)
        ).fetchone()
        values = (
            candidate.stable_key, candidate.detection_type.value, candidate.state.value,
            candidate.confidence.value, candidate.site_id, candidate.sensor_id,
            candidate.primary_event_id, event_ids_json, candidate.source_ip,
            candidate.destination_ip, candidate.source_port, candidate.destination_port,
            candidate.protocol.value, candidate.action.value, candidate.event_count,
            candidate.unique_source_count, candidate.first_seen.isoformat(), candidate.last_seen.isoformat(),
            candidate.rule_id, candidate.rule_version, candidate.reason,
        )
        columns = (
            "stable_key", "detection_type", "state", "confidence", "site_id", "sensor_id",
            "primary_event_id", "event_ids_json", "source_ip", "destination_ip", "source_port",
            "destination_port", "protocol", "action", "event_count", "unique_source_count",
            "first_seen", "last_seen", "rule_id", "rule_version", "reason",
        )
        if existing is not None:
            if any(existing[column] != value for column, value in zip(columns, values)):
                raise sqlite3.IntegrityError("Perimeter detection identity conflicts with existing evidence.")
            result = _decode(existing)
            result["idempotent"] = True
            return result
        cursor = connection.execute(
            f"INSERT INTO perimeter_detections({','.join(columns)},created_at) VALUES ({','.join('?' for _ in columns)},?)",
            (*values, created_at),
        )
        row = connection.execute("SELECT * FROM perimeter_detections WHERE id=?", (cursor.lastrowid,)).fetchone()
        result = _decode(row)
        result["idempotent"] = False
        return result


def get_perimeter_detection(detection_id: int, db_path=DB_PATH):
    initialize_database(db_path)
    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row
        return _decode(connection.execute("SELECT * FROM perimeter_detections WHERE id=?", (detection_id,)).fetchone())


def query_perimeter_detections(*, limit=20, offset=0, site_id=None, detection_type=None,
                               action=None, protocol=None, source_ip=None, destination_ip=None,
                               destination_port=None, db_path=DB_PATH):
    initialize_database(db_path)
    clauses, params = [], []
    for column, value in (
        ("site_id", site_id), ("detection_type", detection_type), ("action", action),
        ("protocol", protocol), ("source_ip", source_ip), ("destination_ip", destination_ip),
        ("destination_port", destination_port),
    ):
        if value is not None:
            clauses.append(f"{column}=?")
            params.append(value)
    where = " WHERE " + " AND ".join(clauses) if clauses else ""
    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row
        total = connection.execute(f"SELECT COUNT(*) FROM perimeter_detections{where}", tuple(params)).fetchone()[0]
        rows = connection.execute(
            f"SELECT * FROM perimeter_detections{where} ORDER BY last_seen DESC,id DESC LIMIT ? OFFSET ?",
            (*params, limit, offset),
        ).fetchall()
        return {"total": total, "items": [_decode(row) for row in rows]}
