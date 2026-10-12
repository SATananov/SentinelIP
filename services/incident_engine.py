"""Explicit incident-review creation; no automatic incident generation."""
import sqlite3
from datetime import datetime, timezone

from database.db import DB_PATH, get_connection, initialize_database
from database.incidents import persist_incident
from services.incident_evidence import load_correlation_projection
from services.incident_models import IncidentError, build_incident
from services.threat_models import positive_id
from services.web_detection_models import utc

MAX_INCIDENT_CORRELATIONS = 25


class IncidentEngine:
    def __init__(self, db_path=DB_PATH):
        self.db_path = db_path

    def open_review(self, correlation_ids, *, opened_at=None):
        try:
            ids = tuple(correlation_ids)
        except TypeError:
            raise IncidentError("Correlation IDs must be an iterable of persisted IDs.") from None
        if not ids:
            raise IncidentError("At least one correlation is required.")
        if len(ids) > MAX_INCIDENT_CORRELATIONS:
            raise IncidentError("Incident correlation limit exceeded.")
        for correlation_id in ids:
            positive_id(correlation_id)
        if len(set(ids)) != len(ids):
            raise IncidentError("Duplicate correlation IDs are not allowed.")
        ids = tuple(sorted(ids))
        now = utc(opened_at if opened_at is not None else datetime.now(timezone.utc))
        initialize_database(self.db_path)
        with get_connection(self.db_path) as connection:
            connection.row_factory = sqlite3.Row
            connection.execute("BEGIN IMMEDIATE")
            correlations = tuple(load_correlation_projection(connection, correlation_id) for correlation_id in ids)
            return persist_incident(connection, build_incident(correlations, now))
