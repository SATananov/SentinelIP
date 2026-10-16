"""Read-only workload overview and queue for analyst incident reviews."""
from datetime import datetime, timedelta, timezone
import sqlite3

from database.db import DB_PATH, get_connection, initialize_database
from database.incident_reviews import DISPOSITIONS, IncidentReviewError, PRIORITIES, STATES

AGE_BUCKETS = ('LT_1H', 'H1_24', 'D1_3', 'D3_7', 'GT_7D')
SORTS = ('newest', 'oldest', 'priority', 'recently_updated', 'oldest_open')
MAX_LIMIT = 100
MAX_OFFSET = 100000
RECENT_ACTIVITY_LIMIT = 20


def _validate(*, limit, offset, sort, state, priority, disposition, site_id, scope_id,
              device_id, has_evidence, age_bucket, unresolved_only):
    if type(limit) is not int or not 1 <= limit <= MAX_LIMIT:
        raise IncidentReviewError('Operations limit must be between 1 and 100.')
    if type(offset) is not int or not 0 <= offset <= MAX_OFFSET:
        raise IncidentReviewError('Operations offset must be between 0 and 100000.')
    if sort not in SORTS:
        raise IncidentReviewError('Unsupported incident review operations sort.')
    if state is not None and state not in STATES:
        raise IncidentReviewError('Unsupported review state.')
    if priority is not None and priority not in PRIORITIES:
        raise IncidentReviewError('Unsupported review priority.')
    if disposition is not None and disposition not in DISPOSITIONS:
        raise IncidentReviewError('Unsupported review disposition.')
    if age_bucket is not None and age_bucket not in AGE_BUCKETS:
        raise IncidentReviewError('Unsupported active review age bucket.')
    for value in (site_id, scope_id, device_id):
        if value is not None and (type(value) is not int or value < 1):
            raise IncidentReviewError('Attribution filters must be positive integers.')
    if has_evidence is not None and type(has_evidence) is not bool:
        raise IncidentReviewError('has_evidence must be a boolean.')
    if type(unresolved_only) is not bool:
        raise IncidentReviewError('unresolved_only must be a boolean.')
    if unresolved_only and state == 'CLOSED':
        raise IncidentReviewError('unresolved_only conflicts with state=CLOSED.')


def build_incident_review_operations(*, limit=20, offset=0, sort='newest', state=None,
        priority=None, disposition=None, site_id=None, scope_id=None, device_id=None,
        has_evidence=None, age_bucket=None, unresolved_only=False, db_path=DB_PATH,
        now=None, explain=False):
    _validate(limit=limit, offset=offset, sort=sort, state=state, priority=priority,
        disposition=disposition, site_id=site_id, scope_id=scope_id, device_id=device_id,
        has_evidence=has_evidence, age_bucket=age_bucket, unresolved_only=unresolved_only)
    initialize_database(db_path)
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None or now.utcoffset() is None:
        raise IncidentReviewError('Operations clock must be timezone-aware.')
    now = now.astimezone(timezone.utc)
    now_text = now.isoformat(timespec='microseconds')
    cutoff = (now - timedelta(hours=24)).isoformat(timespec='microseconds')
    where, params = [], []
    for column, value in (('state', state), ('priority', priority), ('disposition', disposition),
                          ('site_id', site_id), ('scope_id', scope_id), ('device_id', device_id)):
        if value is not None:
            where.append(f'r.{column}=?')
            params.append(value)
    if unresolved_only:
        where.append("r.state != 'CLOSED'")
    if has_evidence is not None:
        where.append(('r.linked_evidence_count>0' if has_evidence
                      else 'r.linked_evidence_count=0'))
    if age_bucket:
        where.append('r.age_bucket=?')
        params.append(age_bucket)
    where_sql = ' WHERE ' + ' AND '.join(where) if where else ''
    order_sql = {
        'newest': 'r.created_at DESC,r.id DESC',
        'oldest': 'r.created_at ASC,r.id ASC',
        'priority': "CASE r.priority WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 ELSE 3 END,r.created_at ASC,r.id ASC",
        'recently_updated': 'r.updated_at DESC,r.id DESC',
        'oldest_open': "CASE WHEN r.state IN ('OPEN','IN_REVIEW') THEN 0 ELSE 1 END,r.created_at ASC,r.id ASC",
    }[sort]
    cte = """WITH evidence_counts AS (
        SELECT incident_id,COUNT(*) linked_evidence_count FROM incident_review_evidence GROUP BY incident_id
      ), note_counts AS (
        SELECT incident_review_id,COUNT(*) note_count FROM incident_review_notes GROUP BY incident_review_id
      ), event_times AS (
        SELECT incident_review_id,MAX(created_at) latest_event_at FROM incident_review_events GROUP BY incident_review_id
      ), note_times AS (
        SELECT incident_review_id,MAX(created_at) latest_note_at FROM incident_review_notes GROUP BY incident_review_id
      ), review_rows AS (
        SELECT r.id,r.incident_key,r.title,r.state,r.priority,r.confidence,r.disposition,
          r.site_id,r.scope_id,r.device_id,r.created_at,r.updated_at,r.first_evidence_at,
          r.last_evidence_at,r.closed_at,
          CASE WHEN r.final_summary IS NOT NULL AND trim(r.final_summary)!='' THEN 1 ELSE 0 END has_final_summary,
          COALESCE(ec.linked_evidence_count,0) linked_evidence_count,
          COALESCE(nc.note_count,0) note_count,
          COALESCE(CASE WHEN et.latest_event_at IS NULL THEN nt.latest_note_at
            WHEN nt.latest_note_at IS NULL THEN et.latest_event_at
            WHEN julianday(et.latest_event_at)>=julianday(nt.latest_note_at) THEN et.latest_event_at
            ELSE nt.latest_note_at END,r.updated_at) latest_activity_at,
          CASE WHEN r.state IN ('OPEN','IN_REVIEW') THEN CAST((julianday(?) - julianday(r.created_at))*86400 AS INTEGER) END age_seconds,
          CASE WHEN r.state NOT IN ('OPEN','IN_REVIEW') THEN NULL
            WHEN julianday(?) - julianday(r.created_at) < 1.0/24 THEN 'LT_1H'
            WHEN julianday(?) - julianday(r.created_at) < 1 THEN 'H1_24'
            WHEN julianday(?) - julianday(r.created_at) < 3 THEN 'D1_3'
            WHEN julianday(?) - julianday(r.created_at) < 7 THEN 'D3_7' ELSE 'GT_7D' END age_bucket
        FROM incident_reviews r
        LEFT JOIN evidence_counts ec ON ec.incident_id=r.id
        LEFT JOIN note_counts nc ON nc.incident_review_id=r.id
        LEFT JOIN event_times et ON et.incident_review_id=r.id
        LEFT JOIN note_times nt ON nt.incident_review_id=r.id
      )"""
    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row
        summary = {}
        counts = connection.execute("""SELECT COUNT(*) total_reviews,
            SUM(state='OPEN') open_count,SUM(state='IN_REVIEW') in_review_count,
            SUM(state='CLOSED') closed_count,SUM(state!='CLOSED') unresolved_count,
            SUM(julianday(created_at)>=julianday(?)) created_last_24h,
            SUM(state='CLOSED' AND julianday(closed_at)>=julianday(?)) closed_last_24h
            FROM incident_reviews""", (cutoff, cutoff)).fetchone()
        summary.update({key: counts[key] or 0 for key in counts.keys()})
        priority_rows = connection.execute('SELECT priority,COUNT(*) total FROM incident_reviews GROUP BY priority').fetchall()
        summary['priority_distribution'] = {key: 0 for key in ('CRITICAL','HIGH','MEDIUM','LOW')}
        summary['priority_distribution'].update({row['priority']: row['total'] for row in priority_rows})
        disposition_rows = connection.execute('SELECT disposition,COUNT(*) total FROM incident_reviews GROUP BY disposition').fetchall()
        summary['disposition_distribution'] = {key: 0 for key in sorted(DISPOSITIONS)}
        summary['disposition_distribution'].update({row['disposition']: row['total'] for row in disposition_rows})
        age_rows = connection.execute(f"""{cte}
            SELECT age_bucket,COUNT(*) total FROM review_rows
            WHERE state IN ('OPEN','IN_REVIEW') GROUP BY age_bucket""", (now_text,)*5).fetchall()
        summary['active_age_buckets'] = {key: 0 for key in AGE_BUCKETS}
        summary['active_age_buckets'].update({row['age_bucket']: row['total'] for row in age_rows if row['age_bucket']})
        summary['reviews_by_site'] = [dict(row) for row in connection.execute(
            'SELECT site_id,COUNT(*) count FROM incident_reviews GROUP BY site_id ORDER BY count DESC,site_id ASC LIMIT 100').fetchall()]
        recent = connection.execute("""SELECT e.incident_review_id,e.event_type,e.created_at,e.actor_source,e.summary,r.incident_key
            FROM incident_review_events e JOIN incident_reviews r ON r.id=e.incident_review_id
            ORDER BY julianday(e.created_at) DESC,e.id DESC LIMIT ?""", (RECENT_ACTIVITY_LIMIT,)).fetchall()
        summary['recent_activity'] = [dict(row) for row in recent]
        query_params = [now_text] * 5 + params
        if explain:
            plan = connection.execute(f'EXPLAIN QUERY PLAN {cte} SELECT * FROM review_rows r{where_sql} ORDER BY {order_sql} LIMIT ? OFFSET ?',
                (*query_params, limit, offset)).fetchall()
            summary['query_plan'] = [dict(row) for row in plan]
        rows = connection.execute(f'{cte} SELECT * FROM review_rows r{where_sql} ORDER BY {order_sql} LIMIT ? OFFSET ?',
            (*query_params, limit, offset)).fetchall()
        total = connection.execute(f'{cte} SELECT COUNT(*) FROM review_rows r{where_sql}',
            (*query_params,)).fetchone()[0]
        queue = [dict(row) for row in rows]
        for row in queue:
            row['has_final_summary'] = bool(row['has_final_summary'])
        return {'summary': summary, 'queue': queue,
                'pagination': {'total': total, 'limit': limit, 'offset': offset}}
