import hashlib
import sqlite3

from database.db import DB_PATH, get_connection, initialize_database


CHANGE_TYPES = frozenset({
    "NEW_EXPOSURE",
    "SERVICE_CHANGED",
    "FINGERPRINT_CHANGED",
    "EXPOSURE_DISAPPEARED",
    "EXPOSURE_REAPPEARED",
})
PRESENCE_STATES = frozenset({"PRESENT", "ABSENT"})


def _row(row):
    return dict(row) if row is not None else None


def _event_key(exposure_id: int, change_type: str, observed_at: str, detail: str) -> str:
    payload = f"{exposure_id}|{change_type}|{observed_at}|{detail}".encode()
    return hashlib.sha256(payload).hexdigest()


def get_presence(exposure_id: int, db_path=DB_PATH):
    initialize_database(db_path)
    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row
        return _row(connection.execute(
            "SELECT * FROM external_exposure_presence WHERE exposure_id=?", (exposure_id,)
        ).fetchone())


def upsert_presence(*, exposure_id: int, scope_id: int, state: str, changed_at: str,
                    last_present_at: str | None, last_absent_at: str | None, db_path=DB_PATH):
    if state not in PRESENCE_STATES:
        raise ValueError("Invalid external exposure presence state.")
    initialize_database(db_path)
    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row
        connection.execute(
            """INSERT INTO external_exposure_presence (
                   exposure_id, scope_id, presence_state, last_present_at, last_absent_at,
                   changed_at, created_at, updated_at
               ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(exposure_id) DO UPDATE SET
                   scope_id=excluded.scope_id,
                   presence_state=excluded.presence_state,
                   last_present_at=excluded.last_present_at,
                   last_absent_at=excluded.last_absent_at,
                   changed_at=excluded.changed_at,
                   updated_at=excluded.updated_at""",
            (exposure_id, scope_id, state, last_present_at, last_absent_at,
             changed_at, changed_at, changed_at),
        )
        return _row(connection.execute(
            "SELECT * FROM external_exposure_presence WHERE exposure_id=?", (exposure_id,)
        ).fetchone())


def insert_change(*, exposure_id: int, scope_id: int, change_type: str, observed_at: str,
                  previous_value: str | None, current_value: str | None,
                  reason: str, source: str, scanner: str, db_path=DB_PATH):
    if change_type not in CHANGE_TYPES:
        raise ValueError("Invalid external exposure change type.")
    detail = f"{previous_value or ''}->{current_value or ''}|{source}|{scanner}"
    event_key = _event_key(exposure_id, change_type, observed_at, detail)
    initialize_database(db_path)
    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row
        connection.execute(
            """INSERT OR IGNORE INTO external_exposure_changes (
                   event_key, exposure_id, scope_id, change_type, previous_value,
                   current_value, reason, observed_at, source, scanner, created_at
               ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (event_key, exposure_id, scope_id, change_type, previous_value,
             current_value, reason, observed_at, source, scanner, observed_at),
        )
        return _row(connection.execute(
            "SELECT * FROM external_exposure_changes WHERE event_key=?", (event_key,)
        ).fetchone())


def get_change(change_id: int, db_path=DB_PATH):
    initialize_database(db_path)
    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row
        return _row(connection.execute(
            """SELECT c.*, p.presence_state, e.scope_type, e.canonical_target, e.device_id,
                      e.target_ip, e.port_number, e.transport, e.service_name, e.product,
                      e.version, e.extra_info, e.service_confidence, e.first_seen, e.last_seen
               FROM external_exposure_changes c
               JOIN external_exposures e ON e.id=c.exposure_id
               LEFT JOIN external_exposure_presence p ON p.exposure_id=e.id
               WHERE c.id=?""", (change_id,)
        ).fetchone())


def query_changes(*, scope_id=None, change_type=None, target_ip=None, port_number=None,
                  presence_state=None, limit=100, offset=0, db_path=DB_PATH):
    initialize_database(db_path)
    clauses, params = [], []
    for column, value in (
        ("c.scope_id", scope_id), ("c.change_type", change_type),
        ("e.target_ip", target_ip), ("e.port_number", port_number),
        ("p.presence_state", presence_state),
    ):
        if value is not None:
            clauses.append(f"{column} = ?")
            params.append(value)
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    base = f"""FROM external_exposure_changes c
               JOIN external_exposures e ON e.id=c.exposure_id
               LEFT JOIN external_exposure_presence p ON p.exposure_id=e.id {where}"""
    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            f"""SELECT c.*, p.presence_state, e.scope_type, e.canonical_target, e.device_id,
                       e.target_ip, e.port_number, e.transport, e.service_name, e.product,
                       e.version, e.extra_info, e.service_confidence, e.first_seen, e.last_seen
                {base} ORDER BY c.observed_at DESC, c.id DESC LIMIT ? OFFSET ?""",
            (*params, limit, offset),
        ).fetchall()
        total = connection.execute(f"SELECT COUNT(*) {base}", params).fetchone()[0]
    return {"total": total, "items": [_row(row) for row in rows]}


def list_present_exposures_for_device(*, scope_id: int, device_id: int, db_path=DB_PATH):
    initialize_database(db_path)
    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row
        return [dict(row) for row in connection.execute(
            """SELECT e.*, p.presence_state, p.last_present_at, p.last_absent_at, p.changed_at
               FROM external_exposures e
               JOIN external_exposure_presence p ON p.exposure_id=e.id
               WHERE e.scope_id=? AND e.device_id=? AND p.presence_state='PRESENT'""",
            (scope_id, device_id),
        ).fetchall()]
