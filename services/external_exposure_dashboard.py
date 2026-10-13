"""Read-only aggregate view for authorized external exposure evidence."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import sqlite3

from database.db import DB_PATH, get_connection, initialize_database

_TIME_RANGES = {
    "24h": timedelta(hours=24),
    "72h": timedelta(hours=72),
    "7d": timedelta(days=7),
    "30d": timedelta(days=30),
    "all": None,
}
_PUBLIC_SCOPE_TYPES = {"PUBLIC_IPV4", "PUBLIC_CIDR", "HOSTNAME"}


def _cutoff(time_range: str, now: datetime) -> str | None:
    if time_range not in _TIME_RANGES:
        raise ValueError("Unsupported external exposure dashboard time range.")
    delta = _TIME_RANGES[time_range]
    if delta is None:
        return None
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("External exposure dashboard clock must be timezone-aware.")
    return (now.astimezone(timezone.utc) - delta).isoformat(timespec="seconds")


def _scope_where(scope_id: int | None, alias: str = "e"):
    if scope_id is None:
        return "1=1", []
    return f"{alias}.scope_id=?", [scope_id]


def build_external_exposure_dashboard(
    *,
    scope_id: int | None = None,
    time_range: str = "7d",
    recent_limit: int = 20,
    db_path=DB_PATH,
    now: datetime | None = None,
):
    if scope_id is not None and (type(scope_id) is not int or scope_id <= 0):
        raise ValueError("scope_id must be a positive integer.")
    if type(recent_limit) is not int or not 1 <= recent_limit <= 50:
        raise ValueError("recent_limit must be between 1 and 50.")

    initialize_database(db_path)
    now = now or datetime.now(timezone.utc)
    cutoff = _cutoff(time_range, now)
    exposure_where, exposure_params = _scope_where(scope_id)

    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row

        if scope_id is not None:
            scope = connection.execute(
                "SELECT id, scope_type, canonical_target, name, authorized, enabled "
                "FROM authorized_scopes WHERE id=?",
                (scope_id,),
            ).fetchone()
            if scope is None:
                raise LookupError("Authorized scope not found.")
            if scope["scope_type"] not in _PUBLIC_SCOPE_TYPES:
                raise ValueError("External exposure dashboard requires an authorized public scope.")

        summary = connection.execute(
            f"""
            SELECT
                COUNT(*) AS total_exposures,
                SUM(CASE WHEN p.presence_state='PRESENT' THEN 1 ELSE 0 END) AS present,
                SUM(CASE WHEN p.presence_state='ABSENT' THEN 1 ELSE 0 END) AS absent,
                SUM(CASE WHEN a.classification='EXPECTED' THEN 1 ELSE 0 END) AS expected,
                SUM(CASE WHEN a.classification='UNEXPECTED' THEN 1 ELSE 0 END) AS unexpected,
                SUM(CASE WHEN a.classification='REVIEW' THEN 1 ELSE 0 END) AS review,
                SUM(CASE WHEN c.exposure_profile='SENSITIVE_ADMIN_SERVICE' THEN 1 ELSE 0 END) AS sensitive_admin,
                SUM(CASE WHEN c.exposure_profile='INTERNAL_STYLE_SERVICE' THEN 1 ELSE 0 END) AS internal_style,
                COUNT(DISTINCT e.target_ip) AS public_targets
            FROM external_exposures e
            LEFT JOIN external_exposure_presence p ON p.exposure_id=e.id
            LEFT JOIN external_exposure_assessments a ON a.exposure_id=e.id
            LEFT JOIN external_exposure_classifications c ON c.exposure_id=e.id
            WHERE {exposure_where}
            """,
            tuple(exposure_params),
        ).fetchone()

        role_rows = connection.execute(
            f"""
            SELECT c.service_role AS label, COUNT(*) AS total
            FROM external_exposure_classifications c
            JOIN external_exposures e ON e.id=c.exposure_id
            WHERE {exposure_where}
            GROUP BY c.service_role
            ORDER BY total DESC, c.service_role ASC
            """,
            tuple(exposure_params),
        ).fetchall()

        profile_rows = connection.execute(
            f"""
            SELECT c.exposure_profile AS label, COUNT(*) AS total
            FROM external_exposure_classifications c
            JOIN external_exposures e ON e.id=c.exposure_id
            WHERE {exposure_where}
            GROUP BY c.exposure_profile
            ORDER BY total DESC, c.exposure_profile ASC
            """,
            tuple(exposure_params),
        ).fetchall()

        top_ports = connection.execute(
            f"""
            SELECT e.port_number, e.transport, COUNT(*) AS total,
                   SUM(CASE WHEN p.presence_state='PRESENT' THEN 1 ELSE 0 END) AS present
            FROM external_exposures e
            LEFT JOIN external_exposure_presence p ON p.exposure_id=e.id
            WHERE {exposure_where}
            GROUP BY e.port_number, e.transport
            ORDER BY total DESC, e.port_number ASC
            LIMIT 10
            """,
            tuple(exposure_params),
        ).fetchall()

        top_targets = connection.execute(
            f"""
            SELECT e.target_ip, COUNT(*) AS total,
                   SUM(CASE WHEN p.presence_state='PRESENT' THEN 1 ELSE 0 END) AS present,
                   SUM(CASE WHEN a.classification='UNEXPECTED' THEN 1 ELSE 0 END) AS unexpected
            FROM external_exposures e
            LEFT JOIN external_exposure_presence p ON p.exposure_id=e.id
            LEFT JOIN external_exposure_assessments a ON a.exposure_id=e.id
            WHERE {exposure_where}
            GROUP BY e.target_ip
            ORDER BY total DESC, e.target_ip ASC
            LIMIT 10
            """,
            tuple(exposure_params),
        ).fetchall()

        change_clauses = []
        change_params: list[object] = []
        if scope_id is not None:
            change_clauses.append("ch.scope_id=?")
            change_params.append(scope_id)
        if cutoff is not None:
            change_clauses.append("ch.observed_at>=?")
            change_params.append(cutoff)
        change_where = " AND ".join(change_clauses) if change_clauses else "1=1"

        change_counts = connection.execute(
            f"""
            SELECT ch.change_type AS label, COUNT(*) AS total
            FROM external_exposure_changes ch
            WHERE {change_where}
            GROUP BY ch.change_type
            ORDER BY total DESC, ch.change_type ASC
            """,
            tuple(change_params),
        ).fetchall()

        recent_changes = connection.execute(
            f"""
            SELECT ch.id, ch.change_type, ch.previous_value, ch.current_value,
                   ch.reason, ch.observed_at, ch.source, ch.scanner,
                   e.id AS exposure_id, e.scope_id, e.scope_type, e.canonical_target,
                   e.target_ip, e.port_number, e.transport, e.service_name, e.product,
                   e.version, p.presence_state, a.classification,
                   c.service_role, c.exposure_profile
            FROM external_exposure_changes ch
            JOIN external_exposures e ON e.id=ch.exposure_id
            LEFT JOIN external_exposure_presence p ON p.exposure_id=e.id
            LEFT JOIN external_exposure_assessments a ON a.exposure_id=e.id
            LEFT JOIN external_exposure_classifications c ON c.exposure_id=e.id
            WHERE {change_where}
            ORDER BY ch.observed_at DESC, ch.id DESC
            LIMIT ?
            """,
            (*change_params, recent_limit),
        ).fetchall()

        recent_exposures = connection.execute(
            f"""
            SELECT e.id, e.scope_id, e.scope_type, e.canonical_target, e.target_ip,
                   e.port_number, e.transport, e.service_name, e.product, e.version,
                   e.service_confidence, e.first_seen, e.last_seen,
                   p.presence_state, a.classification,
                   c.service_role, c.exposure_profile
            FROM external_exposures e
            LEFT JOIN external_exposure_presence p ON p.exposure_id=e.id
            LEFT JOIN external_exposure_assessments a ON a.exposure_id=e.id
            LEFT JOIN external_exposure_classifications c ON c.exposure_id=e.id
            WHERE {exposure_where}
            ORDER BY e.last_seen DESC, e.id DESC
            LIMIT ?
            """,
            (*exposure_params, recent_limit),
        ).fetchall()

        scopes = connection.execute(
            """
            SELECT id, scope_type, canonical_target, name, authorized, enabled
            FROM authorized_scopes
            WHERE scope_type IN ('PUBLIC_IPV4','PUBLIC_CIDR','HOSTNAME')
            ORDER BY name COLLATE NOCASE, canonical_target COLLATE NOCASE, id
            """
        ).fetchall()

    return {
        "filters": {"scope_id": scope_id, "time_range": time_range},
        "summary": {
            "total_exposures": summary["total_exposures"] or 0,
            "present": summary["present"] or 0,
            "absent": summary["absent"] or 0,
            "expected": summary["expected"] or 0,
            "unexpected": summary["unexpected"] or 0,
            "review": summary["review"] or 0,
            "sensitive_admin": summary["sensitive_admin"] or 0,
            "internal_style": summary["internal_style"] or 0,
            "public_targets": summary["public_targets"] or 0,
            "recent_changes": sum(row["total"] for row in change_counts),
        },
        "service_roles": [dict(row) for row in role_rows],
        "exposure_profiles": [dict(row) for row in profile_rows],
        "change_counts": [dict(row) for row in change_counts],
        "top_ports": [dict(row) for row in top_ports],
        "top_targets": [dict(row) for row in top_targets],
        "recent_changes": [dict(row) for row in recent_changes],
        "recent_exposures": [dict(row) for row in recent_exposures],
        "options": {
            "scopes": [dict(row) for row in scopes],
            "time_ranges": list(_TIME_RANGES),
        },
    }
