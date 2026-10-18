"""Fixed, bounded, read-only Incident Review report projection."""

import json
import sqlite3

from database.db import DB_PATH, get_connection


REPORT_SCHEMA_VERSION = 1
MAX_REPORT_EVIDENCE = 200
MAX_REPORT_NOTES = 50
MAX_REPORT_TIMELINE = 50
MAX_REPORT_JSON_BYTES = 4 * 1024 * 1024

REVIEW_FIELDS = (
    "id", "incident_key", "title", "summary", "state", "priority", "confidence",
    "disposition", "site_id", "scope_id", "device_id", "final_summary", "created_at",
    "updated_at", "closed_at", "first_evidence_at", "last_evidence_at",
)

# These queries intentionally reuse the small context projections used by the
# review evidence read path. Source payloads and descriptive source text never
# enter the report.
SOURCE_QUERIES = {
    "PERIMETER_DETECTION": "SELECT id,site_id,NULL scope_id,NULL device_id FROM perimeter_detections WHERE id IN ({ids})",
    "PERIMETER_POLICY_CORRELATION": "SELECT id,site_id,NULL scope_id,NULL device_id FROM perimeter_policy_correlations WHERE id IN ({ids})",
    "PERIMETER_HOST_CORRELATION": "SELECT id,site_id,scope_id,device_id FROM perimeter_host_correlations WHERE id IN ({ids})",
    "EXTERNAL_EXPOSURE_CHANGE": """SELECT c.id,rss.site_id,c.scope_id,e.device_id
        FROM external_exposure_changes c
        JOIN external_exposures e ON e.id=c.exposure_id
        LEFT JOIN remote_scope_sites rss ON rss.scope_id=c.scope_id
        WHERE c.id IN ({ids})""",
    "THREAT_DETECTION": "SELECT id,NULL site_id,NULL scope_id,device_id FROM threat_detections WHERE id IN ({ids})",
    "THREAT_CORRELATION": "SELECT id,NULL site_id,NULL scope_id,device_id FROM correlations WHERE id IN ({ids})",
    "WEB_DETECTION": "SELECT id,NULL site_id,NULL scope_id,device_id FROM web_detections WHERE id IN ({ids})",
}


class IncidentReviewReportError(ValueError):
    def __init__(self, message, status_code):
        super().__init__(message)
        self.status_code = status_code


def _collection(total, rows, mapper):
    items = [mapper(row) for row in reversed(rows)]
    returned = len(items)
    omitted = total - returned
    return {
        "total": total,
        "returned": returned,
        "omitted": omitted,
        "truncated": omitted > 0,
        "items": items,
    }


def build_incident_review_report(review_id, generated_at, db_path=DB_PATH):
    """Build one report from one SQLite read snapshot, without initializing/migrating DB."""
    if type(review_id) is not int or review_id <= 0:
        raise IncidentReviewReportError("Incident review ID must be positive.", 422)

    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA query_only=ON")
        connection.execute("BEGIN")

        review_row = connection.execute(
            f"SELECT {','.join(REVIEW_FIELDS)} FROM incident_reviews WHERE id=?",
            (review_id,),
        ).fetchone()
        if review_row is None:
            raise IncidentReviewReportError("Incident review not found.", 404)
        review = dict(review_row)

        evidence_total = connection.execute(
            "SELECT COUNT(*) FROM incident_review_evidence WHERE incident_id=?", (review_id,)
        ).fetchone()[0]
        evidence_rows = connection.execute(
            """SELECT id,evidence_type,evidence_id,observed_at,added_at
               FROM incident_review_evidence WHERE incident_id=?
               ORDER BY julianday(observed_at) DESC,id DESC LIMIT ?""",
            (review_id, MAX_REPORT_EVIDENCE),
        ).fetchall()

        source_ids = {}
        for link in evidence_rows:
            source_ids.setdefault(link["evidence_type"], []).append(link["evidence_id"])
        source_rows = {}
        for evidence_type, ids in source_ids.items():
            query = SOURCE_QUERIES.get(evidence_type)
            if query is None:
                # The evidence table has a fixed type constraint. Treat an
                # unexpected legacy value as unavailable rather than broadening
                # the source query surface.
                continue
            placeholders = ",".join("?" for _ in ids)
            rows = connection.execute(query.format(ids=placeholders), tuple(ids)).fetchall()
            source_rows[evidence_type] = {row["id"]: dict(row) for row in rows}

        notes_total = connection.execute(
            "SELECT COUNT(*) FROM incident_review_notes WHERE incident_review_id=?", (review_id,)
        ).fetchone()[0]
        note_rows = connection.execute(
            """SELECT id,created_at,actor_source,note_text FROM incident_review_notes
               WHERE incident_review_id=? ORDER BY created_at DESC,id DESC LIMIT ?""",
            (review_id, MAX_REPORT_NOTES),
        ).fetchall()

        timeline_total = connection.execute(
            "SELECT COUNT(*) FROM incident_review_events WHERE incident_review_id=?", (review_id,)
        ).fetchone()[0]
        timeline_rows = connection.execute(
            """SELECT id,created_at,event_type,actor_source,field_name,evidence_type,evidence_id,summary
               FROM incident_review_events WHERE incident_review_id=?
               ORDER BY created_at DESC,id DESC LIMIT ?""",
            (review_id, MAX_REPORT_TIMELINE),
        ).fetchall()

        def evidence_item(row):
            item = {
                "evidence_link_id": row["id"],
                "evidence_type": row["evidence_type"],
                "evidence_id": row["evidence_id"],
                "observed_at": row["observed_at"],
                "added_at": row["added_at"],
                "source_status": "MISSING",
            }
            source = source_rows.get(row["evidence_type"], {}).get(row["evidence_id"])
            if source is not None:
                item["source_status"] = "AVAILABLE"
                item.update({key: source[key] for key in ("site_id", "scope_id", "device_id")})
            return item

        evidence = _collection(evidence_total, evidence_rows, evidence_item)
        notes = _collection(notes_total, note_rows, lambda row: {
            "id": row["id"],
            "created_at": row["created_at"],
            "actor_source": row["actor_source"],
            "text": row["note_text"],
        })
        timeline = _collection(timeline_total, timeline_rows, lambda row: {
            "id": row["id"],
            "created_at": row["created_at"],
            "event_type": row["event_type"],
            "actor_source": row["actor_source"],
            "field_name": row["field_name"],
            "evidence_type": row["evidence_type"],
            "evidence_id": row["evidence_id"],
            "summary": row["summary"],
        })

    return {
        "report_schema_version": REPORT_SCHEMA_VERSION,
        "generated_at": generated_at,
        "review": review,
        "evidence": evidence,
        "notes": notes,
        "timeline": timeline,
    }


def serialize_incident_review_report(report):
    try:
        content = json.dumps(report, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise IncidentReviewReportError("Incident review report could not be serialized.", 500) from exc
    if len(content) > MAX_REPORT_JSON_BYTES:
        raise IncidentReviewReportError("Incident review report exceeds the output size limit.", 413)
    return content
