"""Bounded, snapshot-consistent queries for legacy event exports."""

from datetime import datetime
import re
import sqlite3

from database.db import DB_PATH, get_connection
from services.export_contract import (
    EXPORT_MAX_AGGREGATE_TEXT_BYTES,
    EXPORT_MAX_TEXT_BYTES,
    ExportDataError,
    ExportTooLargeError,
)


_TEXT_FIELDS = (
    "timestamp",
    "source_ip",
    "username",
    "event_type",
    "severity",
    "message",
)
_SEVERITIES = ("INFO", "WARNING", "ALERT")
_LEGACY_TIMESTAMP = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?$"
)


def _where_clause(*, severity, source_ip, since, until):
    conditions = []
    parameters = []
    if severity is not None:
        conditions.append("severity = ?")
        parameters.append(severity)
    if source_ip is not None:
        conditions.append("source_ip = ?")
        parameters.append(source_ip)
    if since is not None:
        conditions.append("timestamp >= ?")
        parameters.append(since)
    if until is not None:
        conditions.append("timestamp < ?")
        parameters.append(until)
    where = "WHERE " + " AND ".join(conditions) if conditions else ""
    return where, parameters


def _preflight_columns():
    fields = ["id", "typeof(event_count) AS event_count_type", "event_count"]
    fields.append(
        "CASE WHEN severity IN ('INFO','WARNING','ALERT') THEN 1 ELSE 0 END "
        "AS severity_valid"
    )
    for name in _TEXT_FIELDS:
        fields.extend((
            f"typeof({name}) AS {name}_type",
            f"length(CAST({name} AS BLOB)) AS {name}_bytes",
        ))
    return ", ".join(fields)


def _validate_preflight_row(row, aggregate_budget):
    if not isinstance(row["id"], int) or row["id"] <= 0:
        raise ExportDataError("invalid event id")
    if row["event_count_type"] != "integer" or not isinstance(row["event_count"], int) or row["event_count"] <= 0:
        raise ExportDataError("invalid event count")
    if row["severity_valid"] != 1:
        raise ExportDataError("invalid event severity")

    total_text_bytes = 0
    for name in _TEXT_FIELDS:
        value_type = row[f"{name}_type"]
        byte_length = row[f"{name}_bytes"]
        if name == "username" and value_type == "null":
            continue
        if value_type != "text" or not isinstance(byte_length, int):
            raise ExportDataError(f"invalid {name}")
        if byte_length > EXPORT_MAX_TEXT_BYTES:
            raise ExportTooLargeError("event text value exceeds limit")
        total_text_bytes += byte_length
        if total_text_bytes > aggregate_budget:
            raise ExportTooLargeError("aggregate event text exceeds limit")
    return total_text_bytes


def _validate_event(event):
    if not isinstance(event["id"], int) or event["id"] <= 0:
        raise ExportDataError("invalid event id")
    if not isinstance(event["event_count"], int) or event["event_count"] <= 0:
        raise ExportDataError("invalid event count")
    if event["severity"] not in _SEVERITIES:
        raise ExportDataError("invalid event severity")

    for name in _TEXT_FIELDS:
        value = event[name]
        if name == "username" and value is None:
            continue
        if not isinstance(value, str):
            raise ExportDataError(f"invalid {name}")
        try:
            byte_length = len(value.encode("utf-8", errors="strict"))
        except UnicodeEncodeError as exc:
            raise ExportDataError("invalid event text encoding") from exc
        if byte_length > EXPORT_MAX_TEXT_BYTES:
            raise ExportTooLargeError("event text value exceeds limit")
        if name == "timestamp":
            if _LEGACY_TIMESTAMP.fullmatch(value) is None:
                raise ExportDataError("invalid event timestamp")
            try:
                datetime.fromisoformat(value)
            except ValueError as exc:
                raise ExportDataError("invalid event timestamp") from exc


def get_bounded_export_events(
    *,
    row_limit,
    severity=None,
    source_ip=None,
    since=None,
    until=None,
    aggregate_text_limit=EXPORT_MAX_AGGREGATE_TEXT_BYTES,
    db_path=DB_PATH,
):
    """Preflight bounded text metadata, then fetch only validated export rows.

    Both SELECTs share one explicit SQLite read transaction, so filtering,
    measured lengths, and exported values use the same database snapshot.
    """
    where, parameters = _where_clause(
        severity=severity,
        source_ip=source_ip,
        since=since,
        until=until,
    )
    try:
        with get_connection(db_path) as connection:
            connection.row_factory = sqlite3.Row
            connection.execute("BEGIN")
            encoding = connection.execute("PRAGMA encoding").fetchone()[0]
            if encoding.upper() != "UTF-8":
                raise ExportDataError("unsupported database text encoding")

            metadata = connection.execute(
                f"SELECT {_preflight_columns()} FROM events {where} "
                "ORDER BY id DESC LIMIT ?",
                [*parameters, row_limit + 1],
            ).fetchall()
            if len(metadata) > row_limit:
                raise ExportTooLargeError("event row limit exceeded")

            aggregate_text_bytes = 0
            for row in metadata:
                aggregate_text_bytes += _validate_preflight_row(row, aggregate_text_limit)

            if not metadata:
                return []

            selected = connection.execute(
                "SELECT id, timestamp, source_ip, username, event_type, severity, "
                "message, event_count FROM events "
                f"{where} ORDER BY id DESC LIMIT ?",
                [*parameters, row_limit],
            ).fetchall()
            events = [dict(row) for row in selected]
            if [event["id"] for event in events] != [row["id"] for row in metadata]:
                raise ExportDataError("event snapshot changed")

            exact_text_bytes = 0
            for event in events:
                _validate_event(event)
                for name in _TEXT_FIELDS:
                    value = event[name]
                    if value is not None:
                        exact_text_bytes += len(value.encode("utf-8", errors="strict"))
                        if exact_text_bytes > aggregate_text_limit:
                            raise ExportTooLargeError("aggregate event text exceeds limit")
            return events
    except (ExportDataError, ExportTooLargeError):
        raise
    except Exception as exc:
        raise ExportDataError("could not read export events") from exc
