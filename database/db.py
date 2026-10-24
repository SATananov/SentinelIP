import sqlite3
from pathlib import Path

from database.migrations import apply_migrations
from services.ssh_input_limits import validate_ssh_username


DB_PATH = Path(__file__).resolve().parent / "sentinelip.db"


def get_connection(db_path=DB_PATH):
    connection = sqlite3.connect(db_path)
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def initialize_database(db_path=DB_PATH):
    with get_connection(db_path) as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                username TEXT,
                event_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                message TEXT NOT NULL,
                event_count INTEGER NOT NULL
            )
            """
        )
        connection.commit()
        apply_migrations(connection)


def save_event(
    timestamp: str,
    source_ip: str,
    username: str | None,
    event_type: str,
    severity: str,
    message: str,
    event_count: int,
    db_path=DB_PATH,
):
    validate_ssh_username(username)
    with get_connection(db_path) as connection:
        connection.execute(
            """
            INSERT INTO events (
                timestamp,
                source_ip,
                username,
                event_type,
                severity,
                message,
                event_count
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                timestamp,
                source_ip,
                username,
                event_type,
                severity,
                message,
                event_count,
            ),
        )
        connection.commit()


def get_recent_events(limit: int = 20, db_path=DB_PATH):
    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row

        rows = connection.execute(
            """
            SELECT
                id,
                timestamp,
                source_ip,
                username,
                event_type,
                severity,
                message,
                event_count
            FROM events
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

    return [dict(row) for row in rows]


def get_alerts(limit: int = 20, db_path=DB_PATH):
    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row

        rows = connection.execute(
            """
            SELECT
                id,
                timestamp,
                source_ip,
                username,
                event_type,
                severity,
                message,
                event_count
            FROM events
            WHERE severity = 'ALERT'
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

    return [dict(row) for row in rows]


def get_event_count(db_path=DB_PATH) -> int:
    with get_connection(db_path) as connection:
        row = connection.execute(
            "SELECT COUNT(*) FROM events"
        ).fetchone()

    return row[0]


def get_top_source_ips(limit: int = 10, db_path=DB_PATH):
    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row

        rows = connection.execute(
            """
            SELECT
                source_ip,
                COUNT(*) AS event_total
            FROM events
            GROUP BY source_ip
            ORDER BY event_total DESC, source_ip ASC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

    return [dict(row) for row in rows]


def get_source_ips(db_path=DB_PATH):
    with get_connection(db_path) as connection:
        rows = connection.execute(
            """
            SELECT DISTINCT source_ip
            FROM events
            ORDER BY source_ip ASC
            """
        ).fetchall()

    return [row[0] for row in rows]


def get_severity_counts(db_path=DB_PATH):
    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row

        rows = connection.execute(
            """
            SELECT
                severity,
                COUNT(*) AS total
            FROM events
            GROUP BY severity
            ORDER BY severity ASC
            """
        ).fetchall()

    return [dict(row) for row in rows]


def get_event_type_counts(db_path=DB_PATH):
    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row

        rows = connection.execute(
            """
            SELECT
                event_type,
                COUNT(*) AS total
            FROM events
            GROUP BY event_type
            ORDER BY total DESC, event_type ASC
            """
        ).fetchall()

    return [dict(row) for row in rows]


def get_events_over_time(limit: int = 30, db_path=DB_PATH):
    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row

        rows = connection.execute(
            """
            SELECT
                substr(timestamp, 1, 16) AS minute,
                COUNT(*) AS total,
                SUM(
                    CASE
                        WHEN severity = 'INFO'
                        THEN 1
                        ELSE 0
                    END
                ) AS info,
                SUM(
                    CASE
                        WHEN severity = 'WARNING'
                        THEN 1
                        ELSE 0
                    END
                ) AS warning,
                SUM(
                    CASE
                        WHEN severity = 'ALERT'
                        THEN 1
                        ELSE 0
                    END
                ) AS alert
            FROM events
            GROUP BY substr(timestamp, 1, 16)
            ORDER BY minute DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

    return [dict(row) for row in reversed(rows)]


def get_overview(db_path=DB_PATH):
    severity_counts = get_severity_counts(db_path=db_path)

    severity_map = {
        "INFO": 0,
        "WARNING": 0,
        "ALERT": 0,
    }

    for item in severity_counts:
        severity = item["severity"]

        if severity in severity_map:
            severity_map[severity] = item["total"]

    return {
        "total_events": get_event_count(db_path=db_path),
        "severity": severity_map,
        "top_ips": get_top_source_ips(
            limit=5,
            db_path=db_path,
        ),
        "event_types": get_event_type_counts(
            db_path=db_path,
        ),
    }


def get_paginated_events(
    limit: int = 20,
    offset: int = 0,
    severity: str | None = None,
    source_ip: str | None = None,
    since: str | None = None,
    db_path=DB_PATH,
):
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

    where_clause = ""

    if conditions:
        where_clause = "WHERE " + " AND ".join(conditions)

    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row

        rows = connection.execute(
            f"""
            SELECT
                id,
                timestamp,
                source_ip,
                username,
                event_type,
                severity,
                message,
                event_count
            FROM events
            {where_clause}
            ORDER BY id DESC
            LIMIT ?
            OFFSET ?
            """,
            (*parameters, limit, offset),
        ).fetchall()

        total = connection.execute(
            f"""
            SELECT COUNT(*)
            FROM events
            {where_clause}
            """,
            parameters,
        ).fetchone()[0]

    return {
        "total": total,
        "items": [dict(row) for row in rows],
    }


def get_filtered_events(
    severity: str | None = None,
    source_ip: str | None = None,
    since: str | None = None,
    db_path=DB_PATH,
):
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

    where_clause = ""

    if conditions:
        where_clause = "WHERE " + " AND ".join(conditions)

    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row

        rows = connection.execute(
            f"""
            SELECT
                id,
                timestamp,
                source_ip,
                username,
                event_type,
                severity,
                message,
                event_count
            FROM events
            {where_clause}
            ORDER BY id DESC
            """,
            parameters,
        ).fetchall()

    return [dict(row) for row in rows]
