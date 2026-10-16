"""Read-only workload overview and queue for analyst incident reviews."""
from datetime import datetime, timedelta, timezone
import sqlite3

from database.db import DB_PATH, get_connection, initialize_database
from database.incident_reviews import DISPOSITIONS, IncidentReviewError, PRIORITIES, STATES

AGE_BUCKETS = ('LT_1H', 'H1_24', 'D1_3', 'D3_7', 'GT_7D')
SORTS = ('newest', 'oldest', 'priority', 'recently_updated', 'oldest_open')
SIGNAL_ORDER = (
    'HIGH_PRIORITY_UNRESOLVED', 'AGING_REVIEW', 'NO_RECENT_ACTIVITY',
    'REOPENED_REVIEW', 'MISSING_SOURCE_EVIDENCE', 'NO_LINKED_EVIDENCE',
)
SIGNAL_LABELS = {
    'HIGH_PRIORITY_UNRESOLVED': 'High-priority unresolved',
    'AGING_REVIEW': 'Review aging',
    'NO_RECENT_ACTIVITY': 'No recent activity',
    'REOPENED_REVIEW': 'Reopened review',
    'MISSING_SOURCE_EVIDENCE': 'Missing source evidence',
    'NO_LINKED_EVIDENCE': 'No linked evidence',
}
SIGNAL_REASONS = {
    'HIGH_PRIORITY_UNRESOLVED': 'High-priority analyst review remains unresolved',
    'AGING_REVIEW': 'Active review has been open for at least 24 hours',
    'NO_RECENT_ACTIVITY': 'Active review has had no recorded review activity for at least 7 days',
    'REOPENED_REVIEW': 'Active review was reopened after its latest closure',
    'MISSING_SOURCE_EVIDENCE': 'One or more linked evidence sources are no longer available',
    'NO_LINKED_EVIDENCE': 'Review has no linked evidence',
}
MAX_LIMIT = 100
MAX_OFFSET = 100000
RECENT_ACTIVITY_LIMIT = 20
SITE_SORTS = ('unresolved_desc', 'attention_desc', 'oldest_active', 'recent_activity', 'site_name')
_SITE_ID_TIEBREAK = '(site_id IS NULL) ASC,site_id ASC'


def _review_rollup_cte():
    return """WITH available_evidence AS (
        SELECT l.incident_id,l.evidence_type,l.evidence_id
          FROM incident_review_evidence l JOIN perimeter_detections s ON s.id=l.evidence_id
          WHERE l.evidence_type='PERIMETER_DETECTION'
        UNION ALL
        SELECT l.incident_id,l.evidence_type,l.evidence_id
          FROM incident_review_evidence l JOIN perimeter_policy_correlations s ON s.id=l.evidence_id
          WHERE l.evidence_type='PERIMETER_POLICY_CORRELATION'
        UNION ALL
        SELECT l.incident_id,l.evidence_type,l.evidence_id
          FROM incident_review_evidence l JOIN perimeter_host_correlations s ON s.id=l.evidence_id
          WHERE l.evidence_type='PERIMETER_HOST_CORRELATION'
        UNION ALL
        SELECT l.incident_id,l.evidence_type,l.evidence_id
          FROM incident_review_evidence l JOIN external_exposure_changes s ON s.id=l.evidence_id
          JOIN external_exposures x ON x.id=s.exposure_id
          WHERE l.evidence_type='EXTERNAL_EXPOSURE_CHANGE'
        UNION ALL
        SELECT l.incident_id,l.evidence_type,l.evidence_id
          FROM incident_review_evidence l JOIN threat_detections s ON s.id=l.evidence_id
          WHERE l.evidence_type='THREAT_DETECTION'
        UNION ALL
        SELECT l.incident_id,l.evidence_type,l.evidence_id
          FROM incident_review_evidence l JOIN correlations s ON s.id=l.evidence_id
          WHERE l.evidence_type='THREAT_CORRELATION'
        UNION ALL
        SELECT l.incident_id,l.evidence_type,l.evidence_id
          FROM incident_review_evidence l JOIN web_detections s ON s.id=l.evidence_id
          WHERE l.evidence_type='WEB_DETECTION'
      ), evidence_status AS (
        SELECT l.incident_id,COUNT(*) linked_evidence_count,
          SUM(CASE WHEN a.evidence_id IS NULL THEN 1 ELSE 0 END) missing_source_evidence_count
        FROM incident_review_evidence l LEFT JOIN available_evidence a
          ON a.incident_id=l.incident_id AND a.evidence_type=l.evidence_type AND a.evidence_id=l.evidence_id
        GROUP BY l.incident_id
      ), note_counts AS (
        SELECT incident_review_id,COUNT(*) note_count FROM incident_review_notes GROUP BY incident_review_id
      ), event_times AS (
        SELECT incident_review_id,MAX(created_at) latest_event_at FROM incident_review_events GROUP BY incident_review_id
      ), note_times AS (
        SELECT incident_review_id,MAX(created_at) latest_note_at FROM incident_review_notes GROUP BY incident_review_id
      ), state_event_rank AS (
        SELECT incident_review_id,event_type,created_at,id,
          ROW_NUMBER() OVER (PARTITION BY incident_review_id,event_type ORDER BY julianday(created_at) DESC,id DESC) event_rank
        FROM incident_review_events WHERE event_type IN ('REVIEW_CLOSED','REVIEW_REOPENED')
      ), state_event_times AS (
        SELECT incident_review_id,
          MAX(CASE WHEN event_type='REVIEW_CLOSED' AND event_rank=1 THEN julianday(created_at) END) latest_closed_jd,
          MAX(CASE WHEN event_type='REVIEW_CLOSED' AND event_rank=1 THEN id END) latest_closed_id,
          MAX(CASE WHEN event_type='REVIEW_REOPENED' AND event_rank=1 THEN julianday(created_at) END) latest_reopened_jd,
          MAX(CASE WHEN event_type='REVIEW_REOPENED' AND event_rank=1 THEN id END) latest_reopened_id
        FROM state_event_rank GROUP BY incident_review_id
      ), base_review_rows AS (
        SELECT r.id,r.incident_key,r.title,r.state,r.priority,r.confidence,r.disposition,
          r.site_id,r.scope_id,r.device_id,r.created_at,r.updated_at,r.first_evidence_at,
          r.last_evidence_at,r.closed_at,
          CASE WHEN r.final_summary IS NOT NULL AND trim(r.final_summary)!='' THEN 1 ELSE 0 END has_final_summary,
          COALESCE(es.linked_evidence_count,0) linked_evidence_count,
          COALESCE(es.missing_source_evidence_count,0) missing_source_evidence_count,
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
            WHEN julianday(?) - julianday(r.created_at) < 7 THEN 'D3_7' ELSE 'GT_7D' END age_bucket,
          CASE WHEN r.state IN ('OPEN','IN_REVIEW') AND
            setv.latest_closed_jd IS NOT NULL AND setv.latest_reopened_id IS NOT NULL AND
            (setv.latest_reopened_jd>setv.latest_closed_jd OR
             (setv.latest_reopened_jd=setv.latest_closed_jd AND setv.latest_reopened_id>setv.latest_closed_id))
            THEN 1 ELSE 0 END reopened_after_latest_close
        FROM incident_reviews r
        LEFT JOIN evidence_status es ON es.incident_id=r.id
        LEFT JOIN note_counts nc ON nc.incident_review_id=r.id
        LEFT JOIN event_times et ON et.incident_review_id=r.id
        LEFT JOIN note_times nt ON nt.incident_review_id=r.id
        LEFT JOIN state_event_times setv ON setv.incident_review_id=r.id
      ), review_rows AS (
        SELECT b.*,
          CASE WHEN b.state!='CLOSED' AND b.priority IN ('HIGH','CRITICAL') THEN 1 ELSE 0 END high_priority_unresolved,
          CASE WHEN b.state IN ('OPEN','IN_REVIEW') AND b.age_seconds>=86400 THEN 1 ELSE 0 END aging_review,
          CASE WHEN b.state IN ('OPEN','IN_REVIEW') AND julianday(b.latest_activity_at)<=julianday(?) THEN 1 ELSE 0 END no_recent_activity,
          b.reopened_after_latest_close reopened_review,
          CASE WHEN b.state IN ('OPEN','IN_REVIEW') AND b.missing_source_evidence_count>0 THEN 1 ELSE 0 END missing_source_evidence,
          CASE WHEN b.state IN ('OPEN','IN_REVIEW') AND b.linked_evidence_count=0 THEN 1 ELSE 0 END no_linked_evidence,
          CASE WHEN (b.state!='CLOSED' AND b.priority IN ('HIGH','CRITICAL')) OR
            (b.state IN ('OPEN','IN_REVIEW') AND b.age_seconds>=86400) OR
            (b.state IN ('OPEN','IN_REVIEW') AND julianday(b.latest_activity_at)<=julianday(?)) OR
            b.reopened_after_latest_close=1 OR
            (b.state IN ('OPEN','IN_REVIEW') AND b.missing_source_evidence_count>0) OR
            (b.state IN ('OPEN','IN_REVIEW') AND b.linked_evidence_count=0)
            THEN 1 ELSE 0 END has_attention
        FROM base_review_rows b
      )"""


def _validate(*, limit, offset, sort, state, priority, disposition, site_id, scope_id,
              device_id, has_evidence, age_bucket, unresolved_only, has_attention,
              attention_signal, unattributed_only=False):
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
    if has_attention is not None and type(has_attention) is not bool:
        raise IncidentReviewError('has_attention must be a boolean.')
    if attention_signal is not None and attention_signal not in SIGNAL_ORDER:
        raise IncidentReviewError('Unsupported incident review attention signal.')
    if type(unattributed_only) is not bool:
        raise IncidentReviewError('unattributed_only must be a boolean.')
    if unattributed_only and site_id is not None:
        raise IncidentReviewError('unattributed_only conflicts with site_id.')
    if has_attention is False and attention_signal is not None:
        raise IncidentReviewError('has_attention=false conflicts with attention_signal.')
    if unresolved_only and state == 'CLOSED':
        raise IncidentReviewError('unresolved_only conflicts with state=CLOSED.')


def build_incident_review_operations(*, limit=20, offset=0, sort='newest', state=None,
        priority=None, disposition=None, site_id=None, scope_id=None, device_id=None,
        has_evidence=None, age_bucket=None, unresolved_only=False, has_attention=None,
        attention_signal=None, unattributed_only=False, db_path=DB_PATH,
        now=None, explain=False):
    _validate(limit=limit, offset=offset, sort=sort, state=state, priority=priority,
        disposition=disposition, site_id=site_id, scope_id=scope_id, device_id=device_id,
        has_evidence=has_evidence, age_bucket=age_bucket, unresolved_only=unresolved_only,
        has_attention=has_attention, attention_signal=attention_signal,
        unattributed_only=unattributed_only)
    initialize_database(db_path)
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None or now.utcoffset() is None:
        raise IncidentReviewError('Operations clock must be timezone-aware.')
    now = now.astimezone(timezone.utc)
    now_text = now.isoformat(timespec='microseconds')
    cutoff = (now - timedelta(hours=24)).isoformat(timespec='microseconds')
    inactivity_cutoff = (now - timedelta(days=7)).isoformat(timespec='microseconds')
    where, params = [], []
    for column, value in (('state', state), ('priority', priority), ('disposition', disposition),
                          ('site_id', site_id), ('scope_id', scope_id), ('device_id', device_id)):
        if value is not None:
            where.append(f'r.{column}=?')
            params.append(value)
    if unattributed_only:
        where.append('r.site_id IS NULL')
    if unresolved_only:
        where.append("r.state != 'CLOSED'")
    if has_evidence is not None:
        where.append(('r.linked_evidence_count>0' if has_evidence
                      else 'r.linked_evidence_count=0'))
    if age_bucket:
        where.append('r.age_bucket=?')
        params.append(age_bucket)
    if has_attention is not None:
        where.append('r.has_attention=?')
        params.append(int(has_attention))
    if attention_signal is not None:
        signal_columns = {
            'HIGH_PRIORITY_UNRESOLVED': 'high_priority_unresolved',
            'AGING_REVIEW': 'aging_review',
            'NO_RECENT_ACTIVITY': 'no_recent_activity',
            'REOPENED_REVIEW': 'reopened_review',
            'MISSING_SOURCE_EVIDENCE': 'missing_source_evidence',
            'NO_LINKED_EVIDENCE': 'no_linked_evidence',
        }
        where.append(f"r.{signal_columns[attention_signal]}=1")
    where_sql = ' WHERE ' + ' AND '.join(where) if where else ''
    order_sql = {
        'newest': 'r.created_at DESC,r.id DESC',
        'oldest': 'r.created_at ASC,r.id ASC',
        'priority': "CASE r.priority WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 ELSE 3 END,r.created_at ASC,r.id ASC",
        'recently_updated': 'r.updated_at DESC,r.id DESC',
        'oldest_open': "CASE WHEN r.state IN ('OPEN','IN_REVIEW') THEN 0 ELSE 1 END,r.created_at ASC,r.id ASC",
    }[sort]
    cte = _review_rollup_cte()
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
        cte_params = [now_text] * 5 + [inactivity_cutoff] * 2
        age_rows = connection.execute(f"""{cte}
            SELECT age_bucket,COUNT(*) total FROM review_rows
            WHERE state IN ('OPEN','IN_REVIEW') GROUP BY age_bucket""", cte_params).fetchall()
        summary['active_age_buckets'] = {key: 0 for key in AGE_BUCKETS}
        summary['active_age_buckets'].update({row['age_bucket']: row['total'] for row in age_rows if row['age_bucket']})
        summary['reviews_by_site'] = [dict(row) for row in connection.execute(
            'SELECT site_id,COUNT(*) count FROM incident_reviews GROUP BY site_id ORDER BY count DESC,site_id ASC LIMIT 100').fetchall()]
        recent = connection.execute("""SELECT e.incident_review_id,e.event_type,e.created_at,e.actor_source,e.summary,r.incident_key
            FROM incident_review_events e JOIN incident_reviews r ON r.id=e.incident_review_id
            ORDER BY julianday(e.created_at) DESC,e.id DESC LIMIT ?""", (RECENT_ACTIVITY_LIMIT,)).fetchall()
        summary['recent_activity'] = [dict(row) for row in recent]
        signal_rows = connection.execute(f"""{cte}
            SELECT COALESCE(SUM(has_attention),0) reviews_needing_attention,
              COALESCE(SUM(high_priority_unresolved),0) HIGH_PRIORITY_UNRESOLVED,
              COALESCE(SUM(aging_review),0) AGING_REVIEW,
              COALESCE(SUM(no_recent_activity),0) NO_RECENT_ACTIVITY,
              COALESCE(SUM(reopened_review),0) REOPENED_REVIEW,
              COALESCE(SUM(missing_source_evidence),0) MISSING_SOURCE_EVIDENCE,
              COALESCE(SUM(no_linked_evidence),0) NO_LINKED_EVIDENCE
            FROM review_rows""", cte_params).fetchone()
        summary['reviews_needing_attention'] = signal_rows['reviews_needing_attention']
        summary['signal_distribution'] = {
            code: signal_rows[code] for code in SIGNAL_ORDER
        }
        query_params = cte_params + params
        if explain:
            plan = connection.execute(f'EXPLAIN QUERY PLAN {cte} SELECT * FROM review_rows r{where_sql} ORDER BY {order_sql} LIMIT ? OFFSET ?',
                (*query_params, limit, offset)).fetchall()
            summary['query_plan'] = [dict(row) for row in plan]
        rows = connection.execute(f'{cte} SELECT * FROM review_rows r{where_sql} ORDER BY {order_sql} LIMIT ? OFFSET ?',
            (*query_params, limit, offset)).fetchall()
        total = connection.execute(f'{cte} SELECT COUNT(*) FROM review_rows r{where_sql}',
            (*query_params,)).fetchone()[0]
        queue = []
        for result_row in rows:
            row = dict(result_row)
            signals = [
                {'code': code, 'label': SIGNAL_LABELS[code], 'reason': SIGNAL_REASONS[code]}
                for code in SIGNAL_ORDER if row[{
                    'HIGH_PRIORITY_UNRESOLVED': 'high_priority_unresolved',
                    'AGING_REVIEW': 'aging_review',
                    'NO_RECENT_ACTIVITY': 'no_recent_activity',
                    'REOPENED_REVIEW': 'reopened_review',
                    'MISSING_SOURCE_EVIDENCE': 'missing_source_evidence',
                    'NO_LINKED_EVIDENCE': 'no_linked_evidence',
                }[code]]
            ]
            row['attention_signals'] = signals
            row['attention_signal_count'] = len(signals)
            row['has_attention'] = bool(row['has_attention'])
            row['has_final_summary'] = bool(row['has_final_summary'])
            for key in ('missing_source_evidence_count', 'reopened_after_latest_close',
                        'high_priority_unresolved', 'aging_review', 'no_recent_activity',
                        'reopened_review', 'missing_source_evidence', 'no_linked_evidence'):
                row.pop(key, None)
            queue.append(row)
        return {'summary': summary, 'queue': queue,
                'pagination': {'total': total, 'limit': limit, 'offset': offset}}


def build_incident_review_site_workload(*, limit=20, offset=0, sort='unresolved_desc',
                                        db_path=DB_PATH, now=None, explain=False):
    if type(limit) is not int or not 1 <= limit <= MAX_LIMIT:
        raise IncidentReviewError('Site workload limit must be between 1 and 100.')
    if type(offset) is not int or not 0 <= offset <= MAX_OFFSET:
        raise IncidentReviewError('Site workload offset must be between 0 and 100000.')
    if sort not in SITE_SORTS:
        raise IncidentReviewError('Unsupported site workload sort.')
    initialize_database(db_path)
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None or now.utcoffset() is None:
        raise IncidentReviewError('Site workload clock must be timezone-aware.')
    now = now.astimezone(timezone.utc)
    now_text = now.isoformat(timespec='microseconds')
    inactivity_cutoff = (now - timedelta(days=7)).isoformat(timespec='microseconds')
    cte = _review_rollup_cte()
    params = (now_text, now_text, now_text, now_text, now_text,
              inactivity_cutoff, inactivity_cutoff)
    site_rows = """site_rows AS (
      SELECT r.site_id,
        CASE WHEN r.site_id IS NULL THEN 'Unattributed' ELSE s.name END site_name,
        COUNT(*) total_reviews,
        SUM(r.state!='CLOSED') unresolved_reviews,
        SUM(r.state='OPEN') open_reviews,
        SUM(r.state='IN_REVIEW') in_review_reviews,
        SUM(r.state='CLOSED') closed_reviews,
        SUM(CASE WHEN r.state IN ('OPEN','IN_REVIEW') THEN r.has_attention ELSE 0 END) reviews_needing_attention,
        SUM(r.high_priority_unresolved) high_priority_unresolved,
        MIN(CASE WHEN r.state IN ('OPEN','IN_REVIEW') THEN r.created_at END) oldest_active_created_at,
        MAX(r.latest_activity_at) latest_review_activity_at
      FROM review_rows r LEFT JOIN sites s ON s.id=r.site_id
      GROUP BY r.site_id
    )"""
    ordering = {
        'unresolved_desc': f"unresolved_reviews DESC,{_SITE_ID_TIEBREAK}",
        'attention_desc': f"reviews_needing_attention DESC,unresolved_reviews DESC,{_SITE_ID_TIEBREAK}",
        'oldest_active': f"CASE WHEN oldest_active_created_at IS NULL THEN 1 ELSE 0 END,oldest_active_created_at ASC,{_SITE_ID_TIEBREAK}",
        'recent_activity': f"CASE WHEN latest_review_activity_at IS NULL THEN 1 ELSE 0 END,latest_review_activity_at DESC,{_SITE_ID_TIEBREAK}",
        'site_name': f"CASE WHEN site_name IS NULL THEN 1 ELSE 0 END,lower(site_name) ASC,{_SITE_ID_TIEBREAK}",
    }[sort]
    query = f"""{cte}, {site_rows}
      SELECT site_id,site_name,total_reviews,unresolved_reviews,open_reviews,
        in_review_reviews,closed_reviews,reviews_needing_attention,high_priority_unresolved,
        oldest_active_created_at,
        CASE WHEN oldest_active_created_at IS NULL THEN NULL
          ELSE CAST((julianday(?) - julianday(oldest_active_created_at))*86400 AS INTEGER) END oldest_active_age_seconds,
        latest_review_activity_at
      FROM site_rows"""
    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row
        count = connection.execute(
            'SELECT COUNT(*) FROM (SELECT site_id FROM incident_reviews GROUP BY site_id)'
        ).fetchone()[0]
        page_params = (*params, now_text, limit, offset)
        rows = connection.execute(f"WITH {query.split('WITH ',1)[1]} ORDER BY {ordering} LIMIT ? OFFSET ?", page_params).fetchall()
        if explain:
            plan = connection.execute(
                f"EXPLAIN QUERY PLAN WITH {query.split('WITH ',1)[1]} ORDER BY {ordering} LIMIT ? OFFSET ?",
                page_params).fetchall()
        sites = [dict(row) for row in rows]
        result = {'sites': sites, 'pagination': {'limit': limit, 'offset': offset, 'total': count}}
        if explain:
            result['query_plan'] = [dict(row) for row in plan]
        return result
