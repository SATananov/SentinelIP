import json
import sqlite3
from datetime import datetime

from database.db import DB_PATH, get_connection, initialize_database
from services.cve_models import CveMatch, CveRecord


def _as_record(row):
    if row is None:
        return None
    result = dict(row)
    result["metadata"] = json.loads(result["metadata_json"]) if result.get("metadata_json") else None
    return result


def _metadata(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")) if value is not None else None


def create_cve_record(record: CveRecord, db_path=DB_PATH):
    initialize_database(db_path)
    now = datetime.now().isoformat(timespec="seconds")
    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row
        cursor = connection.execute(
            """
            INSERT INTO cve_records (
                cve_id, source, source_reference, product, vendor,
                version_expression, description, severity, cvss_score,
                published_at, modified_at, metadata_json, created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                record.cve_id,
                record.source,
                record.source_reference,
                record.product,
                record.vendor,
                record.affected_version_expression,
                record.description,
                record.severity,
                record.cvss_score,
                record.published_at.isoformat(timespec="seconds") if record.published_at else None,
                record.modified_at.isoformat(timespec="seconds") if record.modified_at else None,
                _metadata(record.metadata),
                now,
                now,
            ),
        )
        row = connection.execute(
            "SELECT * FROM cve_records WHERE id = ?", (cursor.lastrowid,)
        ).fetchone()
    return _as_record(row)


def get_cve_record(record_id: int, db_path=DB_PATH):
    initialize_database(db_path)
    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row
        row = connection.execute("SELECT * FROM cve_records WHERE id = ?", (record_id,)).fetchone()
    return _as_record(row)


def get_cve_record_by_identity(source: str, cve_id: str, product: str, version_expression: str, db_path=DB_PATH):
    initialize_database(db_path)
    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row
        row = connection.execute(
            """
            SELECT * FROM cve_records
            WHERE source = ? AND cve_id = ? AND product = ? AND version_expression = ?
            """,
            (source, cve_id, product, version_expression),
        ).fetchone()
    return _as_record(row)


def list_cve_records(db_path=DB_PATH):
    initialize_database(db_path)
    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute("SELECT * FROM cve_records ORDER BY id ASC").fetchall()
    return [_as_record(row) for row in rows]


def create_cve_match(match: CveMatch, db_path=DB_PATH):
    initialize_database(db_path)
    first_seen = match.first_seen.isoformat(timespec="seconds")
    last_seen = match.last_seen.isoformat(timespec="seconds")
    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row
        cursor = connection.execute(
            """
            INSERT INTO cve_matches (
                cve_record_id, device_id, port_id, service_id, finding_id,
                status, confidence, observed_product, observed_version,
                evidence_source, evidence_observed_at, match_reason, stable_key,
                first_seen, last_seen, metadata_json, created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                match.cve_record_id,
                match.device_id,
                match.port_id,
                match.service_id,
                match.finding_id,
                match.status.value,
                match.confidence.value,
                match.observed_product,
                match.observed_version,
                match.evidence_source,
                match.evidence_observed_at.isoformat(timespec="seconds"),
                match.match_reason,
                match.stable_key,
                first_seen,
                last_seen,
                _metadata(match.metadata),
                first_seen,
                last_seen,
            ),
        )
        row = connection.execute("SELECT * FROM cve_matches WHERE id = ?", (cursor.lastrowid,)).fetchone()
    return _as_record(row)


def get_cve_match(match_id: int, db_path=DB_PATH):
    initialize_database(db_path)
    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row
        row = connection.execute("SELECT * FROM cve_matches WHERE id = ?", (match_id,)).fetchone()
    return _as_record(row)


def get_cve_match_by_stable_key(stable_key: str, db_path=DB_PATH):
    initialize_database(db_path)
    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row
        row = connection.execute("SELECT * FROM cve_matches WHERE stable_key = ?", (stable_key,)).fetchone()
    return _as_record(row)


def list_cve_matches(db_path=DB_PATH):
    return _list_matches(None, None, db_path)


def list_service_cve_matches(service_id: int, db_path=DB_PATH):
    return _list_matches("service_id", service_id, db_path)


def list_device_cve_matches(device_id: int, db_path=DB_PATH):
    return _list_matches("device_id", device_id, db_path)


def list_matches_by_status(status: str, db_path=DB_PATH):
    return _list_matches("status", status, db_path)


def _list_matches(field, value, db_path):
    initialize_database(db_path)
    where = "" if field is None else f"WHERE {field} = ?"
    parameters = [] if field is None else [value]
    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            f"SELECT * FROM cve_matches {where} ORDER BY last_seen ASC, id ASC",
            parameters,
        ).fetchall()
    return [_as_record(row) for row in rows]


def touch_cve_match(match_id: int, last_seen: datetime, db_path=DB_PATH):
    initialize_database(db_path)
    timestamp = last_seen.isoformat(timespec="seconds")
    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row
        connection.execute("UPDATE cve_matches SET last_seen = ?, updated_at = ? WHERE id = ?", (timestamp, timestamp, match_id))
        row = connection.execute("SELECT * FROM cve_matches WHERE id = ?", (match_id,)).fetchone()
    return _as_record(row)


def update_cve_match_finding(match_id: int, finding_id: int, db_path=DB_PATH):
    initialize_database(db_path)
    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row
        connection.execute("UPDATE cve_matches SET finding_id = ? WHERE id = ?", (finding_id, match_id))
        row = connection.execute("SELECT * FROM cve_matches WHERE id = ?", (match_id,)).fetchone()
    return _as_record(row)