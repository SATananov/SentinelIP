"""Persistence and bounded reads for deterministic perimeter policy correlations."""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone

from database.db import DB_PATH, get_connection, initialize_database
from services.perimeter_policy_models import PerimeterPolicyCorrelation


def _decode(row):
    if row is None:
        return None
    result = dict(row)
    for column in ("event_ids_json", "allowed_event_ids_json", "blocked_event_ids_json"):
        result[column.removesuffix("_json")] = json.loads(result.pop(column))
    return result


def persist_perimeter_policy_correlation(candidate: PerimeterPolicyCorrelation, db_path=DB_PATH):
    if not isinstance(candidate, PerimeterPolicyCorrelation):
        raise TypeError("PerimeterPolicyCorrelation is required.")
    initialize_database(db_path)
    created_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    event_ids_json = json.dumps(candidate.event_ids, separators=(",", ":"))
    allowed_ids_json = json.dumps(candidate.allowed_event_ids, separators=(",", ":"))
    blocked_ids_json = json.dumps(candidate.blocked_event_ids, separators=(",", ":"))
    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row
        for event_id in candidate.event_ids:
            event = connection.execute("SELECT site_id FROM perimeter_events WHERE id=?", (event_id,)).fetchone()
            if event is None or event["site_id"] != candidate.site_id:
                raise sqlite3.IntegrityError("Perimeter correlation evidence is missing or site-mismatched.")
        existing = connection.execute(
            "SELECT * FROM perimeter_policy_correlations WHERE stable_key=?", (candidate.stable_key,)
        ).fetchone()
        values = (
            candidate.stable_key, candidate.correlation_type.value, candidate.state.value,
            candidate.confidence.value, candidate.site_id, candidate.sensor_id,
            candidate.primary_event_id, event_ids_json, allowed_ids_json, blocked_ids_json,
            candidate.source_type.value, candidate.source_key, candidate.source_ip, candidate.destination_ip, candidate.destination_port,
            candidate.protocol.value, candidate.primary_action.value, candidate.event_count,
            candidate.allow_count, candidate.blocked_count, candidate.first_seen.isoformat(),
            candidate.last_seen.isoformat(), candidate.rule_id, candidate.rule_version, candidate.reason,
        )
        columns = (
            "stable_key", "correlation_type", "state", "confidence", "site_id", "sensor_id",
            "primary_event_id", "event_ids_json", "allowed_event_ids_json", "blocked_event_ids_json",
            "source_type", "source_key", "source_ip", "destination_ip", "destination_port", "protocol", "primary_action",
            "event_count", "allow_count", "blocked_count", "first_seen", "last_seen",
            "rule_id", "rule_version", "reason",
        )
        if existing is not None:
            if any(existing[column] != value for column, value in zip(columns, values)):
                raise sqlite3.IntegrityError("Perimeter policy correlation identity conflicts with existing evidence.")
            result = _decode(existing)
            result["idempotent"] = True
            return result
        cursor = connection.execute(
            f"INSERT INTO perimeter_policy_correlations({','.join(columns)},created_at) VALUES ({','.join('?' for _ in columns)},?)",
            (*values, created_at),
        )
        row = connection.execute(
            "SELECT * FROM perimeter_policy_correlations WHERE id=?", (cursor.lastrowid,)
        ).fetchone()
        result = _decode(row)
        result["idempotent"] = False
        return result


def get_perimeter_policy_correlation(correlation_id: int, db_path=DB_PATH):
    initialize_database(db_path)
    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row
        return _decode(connection.execute(
            "SELECT * FROM perimeter_policy_correlations WHERE id=?", (correlation_id,)
        ).fetchone())


def query_perimeter_policy_correlations(*, limit=20, offset=0, site_id=None, correlation_type=None,
                                        protocol=None, source_type=None, source_key=None, source_ip=None, destination_ip=None,
                                        destination_port=None, primary_action=None, db_path=DB_PATH):
    initialize_database(db_path)
    clauses, params = [], []
    for column, value in (
        ("site_id", site_id), ("correlation_type", correlation_type), ("protocol", protocol),
        ("source_type", source_type), ("source_key", source_key), ("source_ip", source_ip), ("destination_ip", destination_ip),
        ("destination_port", destination_port), ("primary_action", primary_action),
    ):
        if value is not None:
            clauses.append(f"{column}=?")
            params.append(value)
    where = " WHERE " + " AND ".join(clauses) if clauses else ""
    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row
        total = connection.execute(
            f"SELECT COUNT(*) FROM perimeter_policy_correlations{where}", tuple(params)
        ).fetchone()[0]
        rows = connection.execute(
            f"SELECT * FROM perimeter_policy_correlations{where} ORDER BY last_seen DESC,id DESC LIMIT ? OFFSET ?",
            (*params, limit, offset),
        ).fetchall()
        return {"total": total, "items": [_decode(row) for row in rows]}
