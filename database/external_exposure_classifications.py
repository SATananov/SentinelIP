import sqlite3
from datetime import datetime, timezone

from database.db import DB_PATH, get_connection, initialize_database


def _row(row):
    return dict(row) if row is not None else None


def _now():
    return datetime.now(timezone.utc).replace(tzinfo=None).isoformat(timespec="seconds")


def upsert_classification(*, exposure_id: int, scope_id: int, service_role: str,
                          exposure_profile: str, rule_id: str, rule_version: str,
                          reason: str, classified_at: str | None = None, db_path=DB_PATH):
    classified_at = classified_at or _now()
    initialize_database(db_path)
    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row
        connection.execute(
            """INSERT INTO external_exposure_classifications (
                   exposure_id, scope_id, service_role, exposure_profile, rule_id,
                   rule_version, reason, classified_at, created_at, updated_at
               ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(exposure_id) DO UPDATE SET
                   scope_id=excluded.scope_id,
                   service_role=excluded.service_role,
                   exposure_profile=excluded.exposure_profile,
                   rule_id=excluded.rule_id,
                   rule_version=excluded.rule_version,
                   reason=excluded.reason,
                   classified_at=excluded.classified_at,
                   updated_at=excluded.updated_at""",
            (exposure_id, scope_id, service_role, exposure_profile, rule_id,
             rule_version, reason, classified_at, classified_at, classified_at),
        )
        return _row(connection.execute(
            "SELECT * FROM external_exposure_classifications WHERE exposure_id=?", (exposure_id,)
        ).fetchone())


def get_classification(classification_id: int, db_path=DB_PATH):
    initialize_database(db_path)
    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row
        return _row(connection.execute(
            """SELECT c.*, e.scope_type, e.canonical_target, e.device_id, e.target_ip,
                      e.port_number, e.transport, e.service_name, e.product, e.version,
                      e.service_confidence, e.first_seen, e.last_seen
               FROM external_exposure_classifications c
               JOIN external_exposures e ON e.id=c.exposure_id
               WHERE c.id=?""", (classification_id,)
        ).fetchone())


def query_classifications(*, scope_id=None, service_role=None, exposure_profile=None,
                          target_ip=None, port_number=None, limit=100, offset=0, db_path=DB_PATH):
    initialize_database(db_path)
    clauses, params = [], []
    for column, value in (
        ("c.scope_id", scope_id), ("c.service_role", service_role),
        ("c.exposure_profile", exposure_profile), ("e.target_ip", target_ip),
        ("e.port_number", port_number),
    ):
        if value is not None:
            clauses.append(f"{column} = ?")
            params.append(value)
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    base = f"""FROM external_exposure_classifications c
               JOIN external_exposures e ON e.id=c.exposure_id {where}"""
    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            f"""SELECT c.*, e.scope_type, e.canonical_target, e.device_id, e.target_ip,
                       e.port_number, e.transport, e.service_name, e.product, e.version,
                       e.service_confidence, e.first_seen, e.last_seen
                {base} ORDER BY c.classified_at DESC, c.id DESC LIMIT ? OFFSET ?""",
            (*params, limit, offset),
        ).fetchall()
        total = connection.execute(f"SELECT COUNT(*) {base}", params).fetchone()[0]
    return {"total": total, "items": [_row(row) for row in rows]}
