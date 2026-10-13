"""Deterministic site-scoped correlation of perimeter destinations to inventory devices."""
from __future__ import annotations

import sqlite3
from datetime import datetime, timezone

from database.db import DB_PATH, get_connection, initialize_database
from database.perimeter_host_correlations import persist_perimeter_host_correlation
from services.perimeter_host_models import PerimeterHostCorrelation


def _dt(value):
    return datetime.fromisoformat(value).astimezone(timezone.utc)


class PerimeterHostCorrelationEngine:
    def __init__(self, db_path=DB_PATH):
        self.db_path = db_path

    def evaluate_event(self, event_id: int):
        initialize_database(self.db_path)
        with get_connection(self.db_path) as connection:
            connection.row_factory = sqlite3.Row
            event = connection.execute("SELECT * FROM perimeter_events WHERE id=?", (event_id,)).fetchone()
            if event is None:
                raise LookupError("Perimeter event not found.")
            if event["direction"] != "INBOUND" or event["event_type"] not in {"CONNECTION_ATTEMPT", "POLICY_DECISION", "FLOW"}:
                return None
            candidates = connection.execute(
                """SELECT d.id AS device_id,d.last_seen,d.status,d.identity_confidence,
                          n.id AS network_id,s.id AS scope_id
                   FROM devices d
                   JOIN networks n ON n.id=d.network_id
                   JOIN network_scope_links nsl ON nsl.network_id=n.id
                   JOIN authorized_scopes s ON s.id=nsl.scope_id
                   JOIN remote_scope_sites rss ON rss.scope_id=s.id
                   WHERE rss.site_id=? AND s.scope_type='PRIVATE_NETWORK'
                     AND s.authorized=1 AND s.enabled=1
                     AND n.authorized=1 AND n.enabled=1
                     AND d.last_ip_address=?
                   ORDER BY d.id ASC LIMIT 2""",
                (event["site_id"], event["destination_ip"]),
            ).fetchall()
        # Fail closed when inventory has no unique site-scoped destination identity.
        if len(candidates) != 1:
            return None
        device = candidates[0]
        candidate = PerimeterHostCorrelation(
            site_id=event["site_id"], sensor_id=event["sensor_id"], event_id=event["id"],
            scope_id=device["scope_id"], network_id=device["network_id"], device_id=device["device_id"],
            destination_ip=event["destination_ip"], destination_port=event["destination_port"],
            protocol=event["protocol"], action=event["action"], observed_at=_dt(event["observed_at"]),
            device_last_seen=_dt(device["last_seen"]), device_status=device["status"],
            identity_confidence=device["identity_confidence"],
        )
        return persist_perimeter_host_correlation(candidate, self.db_path)

    def evaluate_events(self, event_ids):
        results = []
        for event_id in event_ids:
            row = self.evaluate_event(event_id)
            if row is not None:
                results.append(row)
        return results
