"""Read-only aggregate view for perimeter external activity."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import sqlite3

from database.db import DB_PATH, get_connection, initialize_database

_TIME_RANGES = {
    "1h": timedelta(hours=1),
    "6h": timedelta(hours=6),
    "24h": timedelta(hours=24),
    "72h": timedelta(hours=72),
    "7d": timedelta(days=7),
    "all": None,
}
_SOURCE_TYPES = {"FIREWALL", "ROUTER", "GATEWAY", "SENSOR", "OTHER"}


def _cutoff(time_range: str, now: datetime) -> str | None:
    if time_range not in _TIME_RANGES:
        raise ValueError("Unsupported perimeter dashboard time range.")
    delta = _TIME_RANGES[time_range]
    if delta is None:
        return None
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("Perimeter dashboard clock must be timezone-aware.")
    return (now.astimezone(timezone.utc) - delta).isoformat(timespec="seconds")


def _where(*, site_id=None, source_type=None, cutoff=None, alias="pe"):
    clauses = [f"{alias}.direction='INBOUND'"]
    params: list[object] = []
    if site_id is not None:
        clauses.append(f"{alias}.site_id=?")
        params.append(site_id)
    if source_type is not None:
        clauses.append(f"{alias}.source_type=?")
        params.append(source_type)
    if cutoff is not None:
        clauses.append(f"{alias}.observed_at>=?")
        params.append(cutoff)
    return " AND ".join(clauses), params


def build_perimeter_dashboard(
    *,
    site_id: int | None = None,
    source_type: str | None = None,
    time_range: str = "24h",
    recent_limit: int = 20,
    db_path=DB_PATH,
    now: datetime | None = None,
):
    if site_id is not None and (type(site_id) is not int or site_id <= 0):
        raise ValueError("site_id must be a positive integer.")
    if source_type is not None and source_type not in _SOURCE_TYPES:
        raise ValueError("Unsupported perimeter source type.")
    if type(recent_limit) is not int or not 1 <= recent_limit <= 50:
        raise ValueError("recent_limit must be between 1 and 50.")

    initialize_database(db_path)
    now = now or datetime.now(timezone.utc)
    cutoff = _cutoff(time_range, now)
    where, params = _where(site_id=site_id, source_type=source_type, cutoff=cutoff)

    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row

        if site_id is not None:
            exists = connection.execute("SELECT 1 FROM sites WHERE id=?", (site_id,)).fetchone()
            if exists is None:
                raise LookupError("Site not found.")

        summary = connection.execute(
            f"""
            SELECT
                COUNT(*) AS inbound_total,
                SUM(CASE WHEN pe.action='ALLOW' THEN 1 ELSE 0 END) AS allowed,
                SUM(CASE WHEN pe.action='BLOCK' THEN 1 ELSE 0 END) AS blocked,
                SUM(CASE WHEN pe.action='REJECT' THEN 1 ELSE 0 END) AS rejected,
                SUM(CASE WHEN pe.action='UNKNOWN' THEN 1 ELSE 0 END) AS unknown,
                COUNT(DISTINCT pe.source_ip) AS unique_sources,
                COUNT(DISTINCT CASE WHEN phc.id IS NOT NULL THEN pe.id END) AS host_linked
            FROM perimeter_events pe
            LEFT JOIN perimeter_host_correlations phc ON phc.event_id=pe.id
            WHERE {where}
            """,
            tuple(params),
        ).fetchone()

        detection_where = ["d.detection_type='REPEATED_INBOUND_ATTEMPTS'"]
        detection_params: list[object] = []
        if site_id is not None:
            detection_where.append("d.site_id=?")
            detection_params.append(site_id)
        if source_type is not None:
            detection_where.append(
                "EXISTS (SELECT 1 FROM perimeter_events pe2 WHERE pe2.id=d.primary_event_id AND pe2.source_type=?)"
            )
            detection_params.append(source_type)
        if cutoff is not None:
            detection_where.append("d.last_seen>=?")
            detection_params.append(cutoff)
        repeated = connection.execute(
            f"SELECT COUNT(*) FROM perimeter_detections d WHERE {' AND '.join(detection_where)}",
            tuple(detection_params),
        ).fetchone()[0]

        policy_where = ["1=1"]
        policy_params: list[object] = []
        if site_id is not None:
            policy_where.append("pc.site_id=?")
            policy_params.append(site_id)
        if source_type is not None:
            policy_where.append("pc.source_type=?")
            policy_params.append(source_type)
        if cutoff is not None:
            policy_where.append("pc.last_seen>=?")
            policy_params.append(cutoff)
        policy_count = connection.execute(
            f"SELECT COUNT(*) FROM perimeter_policy_correlations pc WHERE {' AND '.join(policy_where)}",
            tuple(policy_params),
        ).fetchone()[0]

        top_sources = [dict(row) for row in connection.execute(
            f"""
            SELECT pe.source_ip, COUNT(*) AS total,
                   SUM(CASE WHEN pe.action='ALLOW' THEN 1 ELSE 0 END) AS allowed,
                   SUM(CASE WHEN pe.action IN ('BLOCK','REJECT') THEN 1 ELSE 0 END) AS blocked
            FROM perimeter_events pe
            WHERE {where}
            GROUP BY pe.source_ip
            ORDER BY total DESC, pe.source_ip ASC
            LIMIT 8
            """,
            tuple(params),
        ).fetchall()]

        top_ports = [dict(row) for row in connection.execute(
            f"""
            SELECT pe.protocol, pe.destination_port, COUNT(*) AS total
            FROM perimeter_events pe
            WHERE {where} AND pe.destination_port IS NOT NULL
            GROUP BY pe.protocol, pe.destination_port
            ORDER BY total DESC, pe.destination_port ASC
            LIMIT 8
            """,
            tuple(params),
        ).fetchall()]

        timeline = [dict(row) for row in connection.execute(
            f"""
            SELECT substr(pe.observed_at,1,13) || ':00:00+00:00' AS bucket,
                   COUNT(*) AS total,
                   SUM(CASE WHEN pe.action='ALLOW' THEN 1 ELSE 0 END) AS allowed,
                   SUM(CASE WHEN pe.action='BLOCK' THEN 1 ELSE 0 END) AS blocked,
                   SUM(CASE WHEN pe.action='REJECT' THEN 1 ELSE 0 END) AS rejected
            FROM perimeter_events pe
            WHERE {where}
            GROUP BY substr(pe.observed_at,1,13)
            ORDER BY bucket DESC
            LIMIT 48
            """,
            tuple(params),
        ).fetchall()]
        timeline.reverse()

        recent = [dict(row) for row in connection.execute(
            f"""
            SELECT pe.id, pe.observed_at, pe.site_id, s.name AS site_name,
                   pe.source_type, pe.source_key, pe.action, pe.protocol,
                   pe.source_ip, pe.destination_ip, pe.destination_port,
                   phc.device_id, d.hostname AS device_hostname, d.vendor AS device_vendor
            FROM perimeter_events pe
            JOIN sites s ON s.id=pe.site_id
            LEFT JOIN perimeter_host_correlations phc ON phc.event_id=pe.id
            LEFT JOIN devices d ON d.id=phc.device_id
            WHERE {where}
            ORDER BY pe.observed_at DESC, pe.id DESC
            LIMIT ?
            """,
            (*params, recent_limit),
        ).fetchall()]

        repeated_items = [dict(row) for row in connection.execute(
            f"""
            SELECT d.id, d.site_id, s.name AS site_name, d.source_ip, d.destination_ip,
                   d.destination_port, d.protocol, d.action, d.event_count, d.first_seen, d.last_seen
            FROM perimeter_detections d
            JOIN sites s ON s.id=d.site_id
            WHERE {' AND '.join(detection_where)}
            ORDER BY d.last_seen DESC, d.id DESC
            LIMIT 8
            """,
            tuple(detection_params),
        ).fetchall()]

        policy_items = [dict(row) for row in connection.execute(
            f"""
            SELECT pc.id, pc.site_id, s.name AS site_name, pc.correlation_type,
                   pc.source_ip, pc.destination_ip, pc.destination_port, pc.protocol,
                   pc.event_count, pc.allow_count, pc.blocked_count, pc.first_seen, pc.last_seen
            FROM perimeter_policy_correlations pc
            JOIN sites s ON s.id=pc.site_id
            WHERE {' AND '.join(policy_where)}
            ORDER BY pc.last_seen DESC, pc.id DESC
            LIMIT 8
            """,
            tuple(policy_params),
        ).fetchall()]

        sites = [dict(row) for row in connection.execute(
            "SELECT id,name,enabled FROM sites ORDER BY name COLLATE NOCASE,id"
        ).fetchall()]
        source_types = [row[0] for row in connection.execute(
            "SELECT DISTINCT source_type FROM perimeter_events ORDER BY source_type"
        ).fetchall()]

    return {
        "filters": {"site_id": site_id, "source_type": source_type, "time_range": time_range},
        "summary": {
            "inbound_total": summary["inbound_total"] or 0,
            "allowed": summary["allowed"] or 0,
            "blocked": summary["blocked"] or 0,
            "rejected": summary["rejected"] or 0,
            "unknown": summary["unknown"] or 0,
            "unique_sources": summary["unique_sources"] or 0,
            "host_linked": summary["host_linked"] or 0,
            "repeated_detections": repeated,
            "policy_correlations": policy_count,
        },
        "top_sources": top_sources,
        "top_ports": top_ports,
        "timeline": timeline,
        "recent_activity": recent,
        "repeated_detections": repeated_items,
        "policy_correlations": policy_items,
        "options": {"sites": sites, "source_types": source_types, "time_ranges": list(_TIME_RANGES)},
    }
