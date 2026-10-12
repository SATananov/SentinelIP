"""Immutable explicit incident-review persistence."""
import json
import sqlite3

from database.db import DB_PATH, get_connection, initialize_database
from services.incident_evidence import load_correlation_projection
from services.incident_models import Incident, IncidentError, build_incident


def _read(connection, incident_id):
    row = connection.execute("SELECT * FROM incidents WHERE id=?", (incident_id,)).fetchone()
    if row is None:
        return None
    result = dict(row)
    result["correlations"] = []
    rows = connection.execute(
        "SELECT * FROM incident_correlations WHERE incident_id=? ORDER BY source_correlation_id",
        (incident_id,),
    ).fetchall()
    for item in rows:
        value = dict(item)
        value["snapshot"] = json.loads(value["snapshot"])
        result["correlations"].append(value)
    return result


def persist_incident(connection, candidate):
    if not isinstance(candidate, Incident):
        raise TypeError("Incident is required.")
    existing = connection.execute("SELECT id FROM incidents WHERE stable_key=?", (candidate.stable_key,)).fetchone()
    if existing is not None:
        return _read(connection, existing[0])
    current = tuple(load_correlation_projection(connection, item.correlation_id) for item in candidate.correlations)
    if current != candidate.correlations:
        raise IncidentError("Incident correlations no longer match persisted evidence.")
    if build_incident(current, candidate.opened_at) != candidate:
        raise IncidentError("Incident candidate does not match deterministic review semantics.")
    first_seen, last_seen, opened_at = candidate.first_seen.isoformat(), candidate.last_seen.isoformat(), candidate.opened_at.isoformat()
    connection.execute(
        """INSERT INTO incidents(stable_key, incident_type, status, priority, primary_correlation_id, title, reason,
           recommendation, rule_id, rule_version, first_seen, last_seen, opened_at, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (candidate.stable_key, candidate.incident_type.value, candidate.status.value, candidate.priority.value,
         candidate.primary_correlation_id, candidate.title, candidate.reason, candidate.recommendation,
         candidate.rule_id, candidate.rule_version, first_seen, last_seen, opened_at, opened_at, opened_at),
    )
    incident_id = connection.execute("SELECT id FROM incidents WHERE stable_key=?", (candidate.stable_key,)).fetchone()[0]
    for correlation in candidate.correlations:
        snapshot = json.dumps(correlation.snapshot(), sort_keys=True, separators=(",", ":"))
        connection.execute(
            """INSERT INTO incident_correlations(incident_id, source_correlation_id, correlation_id, snapshot)
               VALUES (?, ?, ?, ?)""",
            (incident_id, correlation.correlation_id, correlation.correlation_id, snapshot),
        )
    return _read(connection, incident_id)


def upsert_incident(candidate, db_path=DB_PATH):
    initialize_database(db_path)
    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row
        connection.execute("BEGIN IMMEDIATE")
        return persist_incident(connection, candidate)


def get_incident(incident_id, db_path=DB_PATH):
    initialize_database(db_path)
    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row
        return _read(connection, incident_id)


def list_incidents(db_path=DB_PATH):
    initialize_database(db_path)
    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row
        ids = connection.execute("SELECT id FROM incidents ORDER BY id").fetchall()
        return [_read(connection, row[0]) for row in ids]


def query_incidents(
    *,
    limit=20,
    offset=0,
    incident_type=None,
    status=None,
    priority=None,
    db_path=DB_PATH,
):
    """Bounded read-only incident query for API presentation."""
    initialize_database(db_path)

    clauses = []
    params = []

    for column, value in (
        ("incident_type", incident_type),
        ("status", status),
        ("priority", priority),
    ):
        if value is not None:
            clauses.append(f"{column} = ?")
            params.append(value)

    where = " WHERE " + " AND ".join(clauses) if clauses else ""

    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row

        total = connection.execute(
            f"SELECT COUNT(*) FROM incidents{where}",
            tuple(params),
        ).fetchone()[0]

        rows = connection.execute(
            f"""SELECT id
                FROM incidents
                {where}
                ORDER BY id DESC
                LIMIT ? OFFSET ?""",
            (*params, limit, offset),
        ).fetchall()

        return {
            "total": total,
            "items": [_read(connection, row["id"]) for row in rows],
        }
