"""Explicit evaluation of one persisted observation with bounded local context."""
import sqlite3
from datetime import datetime, timezone

from database.db import DB_PATH, get_connection, initialize_database
from database.web_detections import upsert_detections
from services.web_detection_models import EVIDENCE_COLUMNS, WebDetectionError, WebEvidence, positive_id, utc
from services.web_detection_rules import DOWNLOAD_WINDOW, evaluate_rules

MAX_CONTEXT_OBSERVATIONS = 1000


class WebDetectionEngine:
    def __init__(self, db_path=DB_PATH):
        self.db_path = db_path

    def evaluate_observation(self, observation_id: int, *, evaluated_at=None) -> list[dict]:
        positive_id(observation_id)
        now = utc(evaluated_at if evaluated_at is not None else datetime.now(timezone.utc))
        initialize_database(self.db_path)
        with get_connection(self.db_path) as connection:
            connection.row_factory = sqlite3.Row
            connection.execute("BEGIN")
            row = connection.execute(f"SELECT {EVIDENCE_COLUMNS} FROM web_observations WHERE id = ?", (observation_id,)).fetchone()
            if row is None:
                raise WebDetectionError("Persisted web observation not found.")
            primary = WebEvidence.from_row(dict(row))
            history = ()
            if primary.context is not None:
                # julianday handles old rows with explicit non-UTC offsets correctly.
                rows = connection.execute(
                    f"""SELECT {EVIDENCE_COLUMNS} FROM web_observations
                       WHERE sensor_id = ? AND device_id IS ? AND browser_session_id = ? AND tab_id IS ?
                         AND id != ? AND julianday(observed_at) >= julianday(?)
                         AND julianday(observed_at) <= julianday(?)
                       ORDER BY julianday(observed_at), id LIMIT ?""",
                    (primary.sensor_id, primary.device_id, primary.browser_session_id, primary.tab_id,
                     primary.observation_id, (primary.observed_at - DOWNLOAD_WINDOW).isoformat(),
                     primary.observed_at.isoformat(), MAX_CONTEXT_OBSERVATIONS + 1),
                ).fetchall()
                if len(rows) > MAX_CONTEXT_OBSERVATIONS:
                    raise WebDetectionError("Browser context exceeds evaluation limit; no detections were written.")
                history = tuple(WebEvidence.from_row(dict(item)) for item in rows)
        candidates = evaluate_rules(primary, history, now)
        # Atomic batch write revalidates evidence against persisted rows to avoid stale snapshots.
        return upsert_detections(candidates, self.db_path)
