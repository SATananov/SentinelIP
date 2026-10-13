"""Deterministic correlation of allowed-vs-blocked perimeter evidence."""
from __future__ import annotations

import sqlite3
from datetime import datetime, timezone

from database.db import DB_PATH, get_connection, initialize_database
from database.perimeter_policy_correlations import persist_perimeter_policy_correlation
from services.perimeter_policy_rules import WINDOW, evaluate_policy_transition


def _event(row):
    if row is None:
        return None
    value = dict(row)
    value["observed_at"] = datetime.fromisoformat(value["observed_at"]).astimezone(timezone.utc)
    return value


class PerimeterPolicyCorrelationEngine:
    def __init__(self, db_path=DB_PATH):
        self.db_path = db_path

    def evaluate_event(self, event_id: int):
        initialize_database(self.db_path)
        with get_connection(self.db_path) as connection:
            connection.row_factory = sqlite3.Row
            primary = _event(connection.execute("SELECT * FROM perimeter_events WHERE id=?", (event_id,)).fetchone())
            if primary is None:
                raise LookupError("Perimeter event not found.")
            if primary["direction"] != "INBOUND" or primary["event_type"] not in {"CONNECTION_ATTEMPT", "POLICY_DECISION"}:
                return None
            if primary["action"] not in {"ALLOW", "BLOCK", "REJECT"}:
                return None
            start = (primary["observed_at"] - WINDOW).isoformat()
            rows = connection.execute(
                """SELECT * FROM perimeter_events
                   WHERE site_id=? AND direction='INBOUND'
                     AND event_type IN ('CONNECTION_ATTEMPT','POLICY_DECISION')
                     AND source_type=? AND source_key=?
                     AND source_ip=? AND destination_ip=?
                     AND protocol=? AND action IN ('ALLOW','BLOCK','REJECT')
                     AND ((destination_port IS NULL AND ? IS NULL) OR destination_port=?)
                     AND observed_at>=? AND observed_at<=?
                   ORDER BY observed_at ASC,id ASC LIMIT 256""",
                (
                    primary["site_id"], primary["source_type"], primary["source_key"],
                    primary["source_ip"], primary["destination_ip"], primary["protocol"],
                    primary["destination_port"], primary["destination_port"], start,
                    primary["observed_at"].isoformat(),
                ),
            ).fetchall()
            history = tuple(_event(row) for row in rows)
        candidate = evaluate_policy_transition(primary, history)
        return persist_perimeter_policy_correlation(candidate, self.db_path) if candidate else None

    def evaluate_events(self, event_ids):
        results = []
        for event_id in event_ids:
            row = self.evaluate_event(event_id)
            if row is not None:
                results.append(row)
        return results
