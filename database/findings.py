import json
import sqlite3
from datetime import datetime

from database.db import DB_PATH, get_connection, initialize_database
from services.finding_models import (
    FindingRecord,
    FindingStatus,
    serialize_finding_metadata,
)


def _as_finding(row):
    if row is None:
        return None

    result = dict(row)
    result["metadata"] = None
    if result.get("metadata_json") is not None:
        result["metadata"] = json.loads(result["metadata_json"])
    return result


def create_finding(finding: FindingRecord, db_path=DB_PATH):
    if not isinstance(finding, FindingRecord):
        raise TypeError("finding must be a FindingRecord.")

    initialize_database(db_path)
    first_seen = finding.first_seen.isoformat(timespec="seconds")
    last_seen = finding.last_seen.isoformat(timespec="seconds")
    resolved_at = (
        finding.resolved_at.isoformat(timespec="seconds")
        if finding.resolved_at is not None
        else None
    )

    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row
        cursor = connection.execute(
            """
            INSERT INTO findings (
                finding_type, device_id, network_id, scope_id, port_id, service_id,
                change_id, severity, confidence, status, title, reason,
                recommendation, evidence_type, source, rule_id, rule_version,
                stable_key, first_seen, last_seen, resolved_at, metadata_json,
                created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                finding.finding_type.value,
                finding.device_id,
                finding.network_id,
                finding.scope_id,
                finding.port_id,
                finding.service_id,
                finding.change_id,
                finding.severity.value,
                finding.confidence.value,
                finding.status.value,
                finding.title,
                finding.reason,
                finding.recommendation,
                finding.evidence_type,
                finding.source,
                finding.rule_id,
                finding.rule_version,
                finding.stable_key,
                first_seen,
                last_seen,
                resolved_at,
                serialize_finding_metadata(finding.metadata),
                first_seen,
                last_seen,
            ),
        )
        row = connection.execute(
            "SELECT * FROM findings WHERE id = ?",
            (cursor.lastrowid,),
        ).fetchone()

    return _as_finding(row)


def get_finding(finding_id: int, db_path=DB_PATH):
    initialize_database(db_path)
    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row
        row = connection.execute(
            "SELECT * FROM findings WHERE id = ?", (finding_id,)
        ).fetchone()
    return _as_finding(row)


def get_finding_by_stable_key(stable_key: str, db_path=DB_PATH):
    initialize_database(db_path)
    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row
        row = connection.execute(
            "SELECT * FROM findings WHERE stable_key = ?", (stable_key,)
        ).fetchone()
    return _as_finding(row)


def list_findings(db_path=DB_PATH):
    return _list_filtered(None, None, db_path)


def list_device_findings(device_id: int, db_path=DB_PATH):
    return _list_filtered("device_id", device_id, db_path)


def list_network_findings(network_id: int, db_path=DB_PATH):
    return _list_filtered("network_id", network_id, db_path)


def list_findings_by_status(status: str, db_path=DB_PATH):
    return _list_filtered("status", status, db_path)


def list_findings_by_type(finding_type: str, db_path=DB_PATH):
    return _list_filtered("finding_type", finding_type, db_path)


def _list_filtered(field: str | None, value, db_path):
    initialize_database(db_path)
    parameters = []
    where_clause = ""
    if field is not None:
        if field not in {"device_id", "network_id", "status", "finding_type"}:
            raise ValueError("Unsupported finding filter.")
        where_clause = f"WHERE {field} = ?"
        parameters.append(value)

    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            f"""
            SELECT * FROM findings
            {where_clause}
            ORDER BY last_seen ASC, id ASC
            """,
            parameters,
        ).fetchall()
    return [_as_finding(row) for row in rows]


def touch_finding(
    finding_id: int,
    last_seen: datetime,
    db_path=DB_PATH,
):
    initialize_database(db_path)
    timestamp = last_seen.isoformat(timespec="seconds")
    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row
        connection.execute(
            "UPDATE findings SET last_seen = ?, updated_at = ? WHERE id = ?",
            (timestamp, timestamp, finding_id),
        )
        row = connection.execute(
            "SELECT * FROM findings WHERE id = ?", (finding_id,)
        ).fetchone()
    return _as_finding(row)


def update_finding_status(
    finding_id: int,
    status: str,
    resolved_at: datetime | None = None,
    db_path=DB_PATH,
):
    try:
        normalized_status = FindingStatus(status).value
    except ValueError as exc:
        raise ValueError("Invalid finding status.") from exc

    initialize_database(db_path)
    timestamp = datetime.now().isoformat(timespec="seconds")
    resolved_text = (
        resolved_at.isoformat(timespec="seconds")
        if resolved_at is not None
        else None
    )
    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row
        connection.execute(
            """
            UPDATE findings
            SET status = ?, resolved_at = ?, updated_at = ?
            WHERE id = ?
            """,
            (normalized_status, resolved_text, timestamp, finding_id),
        )
        row = connection.execute(
            "SELECT * FROM findings WHERE id = ?", (finding_id,)
        ).fetchone()
    return _as_finding(row)


def resolve_finding(finding_id: int, resolved_at: datetime, db_path=DB_PATH):
    return update_finding_status(
        finding_id,
        "RESOLVED",
        resolved_at=resolved_at,
        db_path=db_path,
    )
