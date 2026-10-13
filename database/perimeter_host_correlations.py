"""Persistence and bounded reads for perimeter-to-host inventory correlations."""
from __future__ import annotations

import sqlite3
from datetime import datetime, timezone

from database.db import DB_PATH, get_connection, initialize_database
from services.perimeter_host_models import PerimeterHostCorrelation


def _row(row):
    return dict(row) if row is not None else None


def persist_perimeter_host_correlation(candidate: PerimeterHostCorrelation, db_path=DB_PATH):
    if not isinstance(candidate, PerimeterHostCorrelation):
        raise TypeError("PerimeterHostCorrelation is required.")
    initialize_database(db_path)
    created_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    columns = (
        "stable_key", "correlation_type", "state", "confidence", "site_id", "sensor_id", "event_id",
        "scope_id", "network_id", "device_id", "destination_ip", "destination_port", "protocol", "action",
        "observed_at", "device_last_seen", "device_status", "identity_confidence", "rule_id", "rule_version", "reason",
    )
    values = (
        candidate.stable_key, candidate.correlation_type.value, candidate.state.value, candidate.confidence.value,
        candidate.site_id, candidate.sensor_id, candidate.event_id, candidate.scope_id, candidate.network_id,
        candidate.device_id, candidate.destination_ip, candidate.destination_port, candidate.protocol.value,
        candidate.action.value, candidate.observed_at.isoformat(), candidate.device_last_seen.isoformat(),
        candidate.device_status, candidate.identity_confidence, candidate.rule_id, candidate.rule_version, candidate.reason,
    )
    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row
        connection.execute("BEGIN IMMEDIATE")
        event = connection.execute("SELECT site_id FROM perimeter_events WHERE id=?", (candidate.event_id,)).fetchone()
        if event is None or event["site_id"] != candidate.site_id:
            raise sqlite3.IntegrityError("Perimeter host correlation event is missing or site-mismatched.")
        device = connection.execute("SELECT network_id FROM devices WHERE id=?", (candidate.device_id,)).fetchone()
        if device is None or device["network_id"] != candidate.network_id:
            raise sqlite3.IntegrityError("Perimeter host correlation device is missing or network-mismatched.")
        binding = connection.execute(
            """SELECT 1 FROM remote_scope_sites rss
               JOIN network_scope_links nsl ON nsl.scope_id=rss.scope_id
               WHERE rss.site_id=? AND rss.scope_id=? AND nsl.network_id=?""",
            (candidate.site_id, candidate.scope_id, candidate.network_id),
        ).fetchone()
        if binding is None:
            raise sqlite3.IntegrityError("Perimeter host correlation scope is not bound to the site/network.")
        existing = connection.execute(
            "SELECT * FROM perimeter_host_correlations WHERE stable_key=?", (candidate.stable_key,)
        ).fetchone()
        if existing is not None:
            if any(existing[column] != value for column, value in zip(columns, values)):
                raise sqlite3.IntegrityError("Perimeter host correlation identity conflicts with existing evidence.")
            result = _row(existing)
            result["idempotent"] = True
            return result
        cursor = connection.execute(
            f"INSERT INTO perimeter_host_correlations({','.join(columns)},created_at) VALUES ({','.join('?' for _ in columns)},?)",
            (*values, created_at),
        )
        row = connection.execute("SELECT * FROM perimeter_host_correlations WHERE id=?", (cursor.lastrowid,)).fetchone()
        result = _row(row)
        result["idempotent"] = False
        return result


def get_perimeter_host_correlation(correlation_id: int, db_path=DB_PATH):
    initialize_database(db_path)
    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row
        return _row(connection.execute("SELECT * FROM perimeter_host_correlations WHERE id=?", (correlation_id,)).fetchone())


def query_perimeter_host_correlations(*, limit=20, offset=0, site_id=None, device_id=None, network_id=None,
                                      scope_id=None, protocol=None, action=None, destination_ip=None,
                                      destination_port=None, db_path=DB_PATH):
    initialize_database(db_path)
    clauses, params = [], []
    for column, value in (
        ("site_id", site_id), ("device_id", device_id), ("network_id", network_id), ("scope_id", scope_id),
        ("protocol", protocol), ("action", action), ("destination_ip", destination_ip),
        ("destination_port", destination_port),
    ):
        if value is not None:
            clauses.append(f"{column}=?")
            params.append(value)
    where = " WHERE " + " AND ".join(clauses) if clauses else ""
    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row
        total = connection.execute(f"SELECT COUNT(*) FROM perimeter_host_correlations{where}", tuple(params)).fetchone()[0]
        rows = connection.execute(
            f"SELECT * FROM perimeter_host_correlations{where} ORDER BY observed_at DESC,id DESC LIMIT ? OFFSET ?",
            (*params, limit, offset),
        ).fetchall()
        return {"total": total, "items": [_row(row) for row in rows]}
