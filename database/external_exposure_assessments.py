import json
import sqlite3
from datetime import datetime, timezone

from database.db import DB_PATH, get_connection, initialize_database
from services.external_exposure_assessment_models import normalize_expected_tcp_ports


def _row(row):
    return dict(row) if row is not None else None


def _now():
    return datetime.now(timezone.utc).replace(tzinfo=None).isoformat(timespec="seconds")


def get_policy(scope_id: int, db_path=DB_PATH):
    initialize_database(db_path)
    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row
        row = connection.execute(
            "SELECT * FROM external_exposure_policies WHERE scope_id = ?", (scope_id,)
        ).fetchone()
    if row is None:
        return None
    result = _row(row)
    result["expected_tcp_ports"] = json.loads(result.pop("expected_tcp_ports_json"))
    return result


def upsert_policy(scope_id: int, expected_tcp_ports, db_path=DB_PATH):
    ports = normalize_expected_tcp_ports(expected_tcp_ports)
    now = _now()
    initialize_database(db_path)
    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row
        connection.execute(
            """
            INSERT INTO external_exposure_policies (
                scope_id, policy_mode, expected_tcp_ports_json, created_at, updated_at
            ) VALUES (?, 'ALLOWLIST', ?, ?, ?)
            ON CONFLICT(scope_id) DO UPDATE SET
                policy_mode='ALLOWLIST',
                expected_tcp_ports_json=excluded.expected_tcp_ports_json,
                updated_at=excluded.updated_at
            """,
            (scope_id, json.dumps(list(ports), separators=(",", ":")), now, now),
        )
        row = connection.execute(
            "SELECT * FROM external_exposure_policies WHERE scope_id = ?", (scope_id,)
        ).fetchone()
    result = _row(row)
    result["expected_tcp_ports"] = json.loads(result.pop("expected_tcp_ports_json"))
    return result


def delete_policy(scope_id: int, db_path=DB_PATH):
    initialize_database(db_path)
    with get_connection(db_path) as connection:
        cursor = connection.execute(
            "DELETE FROM external_exposure_policies WHERE scope_id = ?", (scope_id,)
        )
        return cursor.rowcount > 0


def upsert_assessment(*, exposure_id: int, scope_id: int, policy_id: int | None,
                      classification: str, reason: str, rule_id: str, rule_version: str,
                      assessed_at: str, db_path=DB_PATH):
    initialize_database(db_path)
    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row
        connection.execute(
            """
            INSERT INTO external_exposure_assessments (
                exposure_id, scope_id, policy_id, classification, reason,
                rule_id, rule_version, assessed_at, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(exposure_id) DO UPDATE SET
                scope_id=excluded.scope_id,
                policy_id=excluded.policy_id,
                classification=excluded.classification,
                reason=excluded.reason,
                rule_id=excluded.rule_id,
                rule_version=excluded.rule_version,
                assessed_at=excluded.assessed_at,
                updated_at=excluded.updated_at
            """,
            (
                exposure_id, scope_id, policy_id, classification, reason,
                rule_id, rule_version, assessed_at, assessed_at, assessed_at,
            ),
        )
        return _row(connection.execute(
            "SELECT * FROM external_exposure_assessments WHERE exposure_id = ?", (exposure_id,)
        ).fetchone())


def get_assessment(assessment_id: int, db_path=DB_PATH):
    initialize_database(db_path)
    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row
        return _row(connection.execute(
            """SELECT a.*, e.scope_type, e.canonical_target, e.device_id, e.target_ip,
                      e.port_number, e.transport, e.service_name, e.product, e.version,
                      e.service_confidence, e.first_seen, e.last_seen
               FROM external_exposure_assessments a
               JOIN external_exposures e ON e.id = a.exposure_id
               WHERE a.id = ?""",
            (assessment_id,),
        ).fetchone())


def query_assessments(*, scope_id=None, classification=None, target_ip=None, port_number=None,
                      limit=100, offset=0, db_path=DB_PATH):
    initialize_database(db_path)
    clauses, params = [], []
    for column, value in (
        ("a.scope_id", scope_id),
        ("a.classification", classification),
        ("e.target_ip", target_ip),
        ("e.port_number", port_number),
    ):
        if value is not None:
            clauses.append(f"{column} = ?")
            params.append(value)
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    base = f"""FROM external_exposure_assessments a
               JOIN external_exposures e ON e.id = a.exposure_id {where}"""
    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            f"""SELECT a.*, e.scope_type, e.canonical_target, e.device_id, e.target_ip,
                       e.port_number, e.transport, e.service_name, e.product, e.version,
                       e.service_confidence, e.first_seen, e.last_seen
                {base}
                ORDER BY a.assessed_at DESC, a.id DESC LIMIT ? OFFSET ?""",
            (*params, limit, offset),
        ).fetchall()
        total = connection.execute(f"SELECT COUNT(*) {base}", params).fetchone()[0]
    return {"total": total, "items": [_row(row) for row in rows]}
