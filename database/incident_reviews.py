"""Manual incident review containers over immutable persisted evidence."""
import sqlite3
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from database.db import DB_PATH, get_connection, initialize_database

STATES = frozenset({'OPEN', 'IN_REVIEW', 'CLOSED'})
PRIORITIES = frozenset({'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'})
CONFIDENCES = frozenset({'LOW', 'MEDIUM', 'HIGH'})
DISPOSITIONS = frozenset({'UNREVIEWED', 'EXPECTED_ACTIVITY', 'BENIGN', 'NEEDS_MONITORING',
                          'ACTION_REQUIRED', 'FALSE_POSITIVE', 'INCONCLUSIVE'})

# Static query templates are the only supported evidence references. IDs never
# select a table name, and the incident API never returns source evidence blobs.
EVIDENCE_QUERIES = {
    'PERIMETER_DETECTION': "SELECT id,site_id,NULL scope_id,NULL device_id,first_seen observed_at FROM perimeter_detections WHERE id=?",
    'PERIMETER_POLICY_CORRELATION': "SELECT id,site_id,NULL scope_id,NULL device_id,first_seen observed_at FROM perimeter_policy_correlations WHERE id=?",
    'PERIMETER_HOST_CORRELATION': "SELECT id,site_id,scope_id,device_id,observed_at FROM perimeter_host_correlations WHERE id=?",
    'EXTERNAL_EXPOSURE_CHANGE': """SELECT c.id,rss.site_id,c.scope_id,e.device_id,c.observed_at
        FROM external_exposure_changes c
        JOIN external_exposures e ON e.id=c.exposure_id
        LEFT JOIN remote_scope_sites rss ON rss.scope_id=c.scope_id WHERE c.id=?""",
    'THREAT_DETECTION': "SELECT id,NULL site_id,NULL scope_id,device_id,first_seen observed_at FROM threat_detections WHERE id=?",
    'THREAT_CORRELATION': "SELECT id,NULL site_id,NULL scope_id,device_id,first_seen observed_at FROM correlations WHERE id=?",
    'WEB_DETECTION': "SELECT id,NULL site_id,NULL scope_id,device_id,first_seen observed_at FROM web_detections WHERE id=?",
}

RELATED_EVIDENCE_QUERIES = {
    'PERIMETER_DETECTION': "SELECT id,site_id,NULL scope_id,NULL device_id,first_seen observed_at FROM perimeter_detections",
    'PERIMETER_POLICY_CORRELATION': "SELECT id,site_id,NULL scope_id,NULL device_id,first_seen observed_at FROM perimeter_policy_correlations",
    'PERIMETER_HOST_CORRELATION': "SELECT id,site_id,scope_id,device_id,observed_at FROM perimeter_host_correlations",
    'EXTERNAL_EXPOSURE_CHANGE': """SELECT c.id,rss.site_id,c.scope_id,e.device_id,c.observed_at
        FROM external_exposure_changes c
        JOIN external_exposures e ON e.id=c.exposure_id
        LEFT JOIN remote_scope_sites rss ON rss.scope_id=c.scope_id""",
    'THREAT_DETECTION': "SELECT id,NULL site_id,NULL scope_id,device_id,first_seen observed_at FROM threat_detections",
    'THREAT_CORRELATION': "SELECT id,NULL site_id,NULL scope_id,device_id,first_seen observed_at FROM correlations",
    'WEB_DETECTION': "SELECT id,NULL site_id,NULL scope_id,device_id,first_seen observed_at FROM web_detections",
}

RELATED_EVIDENCE_WINDOW = timedelta(minutes=30)
RELATED_EVIDENCE_BATCH_SIZE = 100
RELATED_EVIDENCE_SCAN_LIMIT = 1000
REVIEW_EVENT_TYPES = frozenset({'REVIEW_CREATED','STATE_CHANGED','REVIEW_CLOSED','REVIEW_REOPENED',
    'PRIORITY_CHANGED','CONFIDENCE_CHANGED','DISPOSITION_CHANGED','REVIEW_FIELD_CHANGED',
    'FINAL_SUMMARY_CHANGED','ANALYST_NOTE_ADDED','ANALYST_NOTE_CLEARED',
    'EVIDENCE_ATTACHED','EVIDENCE_DETACHED'})
REVIEW_FIELD_NAMES = frozenset({'title','summary','site_id','scope_id','device_id'})
REVIEW_HISTORY_MAX_OFFSET = 100000


class IncidentReviewError(ValueError):
    def __init__(self, message, status_code=422):
        super().__init__(message)
        self.status_code = status_code


def _now():
    return datetime.now(timezone.utc).isoformat(timespec='microseconds')


def _closure_time(connection, incident_id):
    value = datetime.now(timezone.utc)
    previous = connection.execute('''SELECT created_at FROM incident_review_events
        WHERE incident_review_id=? AND event_type='REVIEW_CLOSED'
        ORDER BY created_at DESC,id DESC LIMIT 1''',(incident_id,)).fetchone()
    if previous is not None:
        previous_time = datetime.fromisoformat(previous['created_at'])
        if previous_time.tzinfo is None:
            previous_time = previous_time.replace(tzinfo=timezone.utc)
        if value <= previous_time:
            value = previous_time + timedelta(microseconds=1)
    return value.isoformat(timespec='microseconds')


def _valid_text(value, name, maximum, *, required=False):
    if not isinstance(value, str) or len(value) > maximum or (required and not value.strip()):
        raise IncidentReviewError(f'{name} is invalid.')
    return value.strip() if required else value


def _normalize_final_summary(value):
    if value is None:
        return None
    normalized = _valid_text(value,'Final analyst summary',4000)
    normalized = normalized.strip()
    return normalized or None


def _validate_attribution(connection, *, site_id, scope_id, device_id):
    if site_id is not None and connection.execute('SELECT 1 FROM sites WHERE id=?',(site_id,)).fetchone() is None:
        raise IncidentReviewError('Site not found.',404)
    scope = None
    if scope_id is not None:
        scope = connection.execute('SELECT * FROM authorized_scopes WHERE id=?',(scope_id,)).fetchone()
        if scope is None:
            raise IncidentReviewError('Scope not found.',404)
    device = None
    if device_id is not None:
        device = connection.execute('SELECT * FROM devices WHERE id=?',(device_id,)).fetchone()
        if device is None:
            raise IncidentReviewError('Device not found.',404)
    if site_id is not None and scope_id is not None:
        if connection.execute('SELECT 1 FROM remote_scope_sites WHERE site_id=? AND scope_id=?',
                              (site_id, scope_id)).fetchone() is None:
            raise IncidentReviewError('Site and scope attribution do not match.')
    if scope_id is not None and device_id is not None:
        if not _scope_represents_device(connection,scope,device):
            raise IncidentReviewError('Device is not represented by the attributed scope.')
    elif site_id is not None and device_id is not None:
        scopes = connection.execute('''SELECT DISTINCT s.id FROM authorized_scopes s
            JOIN remote_scope_sites rss ON rss.scope_id=s.id
            WHERE rss.site_id=? AND (
                (s.scope_type='PRIVATE_NETWORK' AND EXISTS (
                    SELECT 1 FROM network_scope_links l WHERE l.scope_id=s.id AND l.network_id=?))
                OR (s.scope_type IN ('PUBLIC_IPV4','PUBLIC_CIDR','HOSTNAME') AND ? IS NOT NULL AND ?=s.id))''',
            (site_id,device['network_id'],device['scope_id'],device['scope_id'])).fetchall()
        if len(scopes) != 1:
            raise IncidentReviewError('Site and device do not have one unambiguous scope relationship.')


def _scope_represents_device(connection,scope,device):
    if scope['scope_type'] == 'PRIVATE_NETWORK':
        return (device['network_id'] is not None and connection.execute('''SELECT 1 FROM network_scope_links
            WHERE scope_id=? AND network_id=?''',(scope['id'],device['network_id'])).fetchone() is not None)
    if scope['scope_type'] in {'PUBLIC_IPV4','PUBLIC_CIDR','HOSTNAME'}:
        return device['scope_id'] == scope['id'] and device['network_id'] is None
    return False


def _device_scope_ids(connection,device):
    rows = connection.execute('''SELECT scope_id FROM network_scope_links WHERE network_id=?
        UNION SELECT scope_id FROM devices WHERE id=? AND scope_id IS NOT NULL''',
        (device['network_id'],device['id'])).fetchall()
    return {row['scope_id'] for row in rows}


def _resolve_evidence_attribution(connection,evidence):
    result = dict(evidence)
    device_id = result['device_id']
    if device_id is not None:
        device = connection.execute('SELECT * FROM devices WHERE id=?',(device_id,)).fetchone()
        if device is None:
            raise IncidentReviewError('Evidence device attribution cannot be verified.')
        scope_ids = _device_scope_ids(connection,device)
        if result['scope_id'] is not None:
            scope = connection.execute('SELECT * FROM authorized_scopes WHERE id=?',(result['scope_id'],)).fetchone()
            if scope is None or not _scope_represents_device(connection,scope,device):
                raise IncidentReviewError('Evidence scope and device attribution conflict.')
        elif len(scope_ids) == 1:
            result['scope_id'] = next(iter(scope_ids))
        if result['scope_id'] is not None and result['site_id'] is None:
            sites = connection.execute('SELECT site_id FROM remote_scope_sites WHERE scope_id=?',
                                       (result['scope_id'],)).fetchall()
            if len(sites) == 1:
                result['site_id'] = sites[0]['site_id']
        if result['site_id'] is not None and result['scope_id'] is not None:
            if connection.execute('SELECT 1 FROM remote_scope_sites WHERE site_id=? AND scope_id=?',
                                   (result['site_id'],result['scope_id'])).fetchone() is None:
                raise IncidentReviewError('Evidence site and scope attribution conflict.')
    elif result['scope_id'] is not None and result['site_id'] is None:
        sites = connection.execute('SELECT site_id FROM remote_scope_sites WHERE scope_id=?',
                                   (result['scope_id'],)).fetchall()
        if len(sites) == 1:
            result['site_id'] = sites[0]['site_id']
    return result


def _review(connection, incident_id):
    row = connection.execute('SELECT * FROM incident_reviews WHERE id=?', (incident_id,)).fetchone()
    return dict(row) if row is not None else None


def _record_event(connection, incident_id, event_type, *, now=None, field_name=None,
                  old_value=None, new_value=None, evidence_type=None, evidence_id=None,
                  note_id=None, summary=None):
    if event_type not in REVIEW_EVENT_TYPES:
        raise IncidentReviewError('Review event type is unsupported.')
    if field_name is not None and field_name not in REVIEW_FIELD_NAMES | {
            'state','priority','confidence','disposition','analyst_note'}:
        raise IncidentReviewError('Review event field is unsupported.')
    connection.execute('''INSERT INTO incident_review_events (
        incident_review_id,event_type,actor_source,created_at,field_name,old_value,new_value,
        evidence_type,evidence_id,note_id,summary) VALUES (?,?,?,?,?,?,?,?,?,?,?)''',
        (incident_id,event_type,'OPERATOR',now or _now(),field_name,
         None if old_value is None else str(old_value),
         None if new_value is None else str(new_value),
         evidence_type,evidence_id,note_id,summary))


def _field_event(connection, incident_id, field, old, new, now):
    if old == new:
        return
    if field == 'state':
        event_type = ('REVIEW_CLOSED' if new == 'CLOSED' else 'REVIEW_REOPENED') \
            if old == 'CLOSED' or new == 'CLOSED' else 'STATE_CHANGED'
    elif field == 'priority':
        event_type = 'PRIORITY_CHANGED'
    elif field == 'confidence':
        event_type = 'CONFIDENCE_CHANGED'
    elif field == 'disposition':
        event_type = 'DISPOSITION_CHANGED'
    elif field == 'final_summary':
        event_type = 'FINAL_SUMMARY_CHANGED'
    elif field == 'analyst_note':
        event_type = 'ANALYST_NOTE_CLEARED' if new is None or new == '' else 'ANALYST_NOTE_ADDED'
    else:
        event_type = 'REVIEW_FIELD_CHANGED'
    _record_event(connection,incident_id,event_type,now=now,
                  field_name=None if field == 'final_summary' else field,
                  old_value=old,new_value=new,summary=f'{field.replace("_"," ").title()} changed')


def create_review(*, title, summary='', state='OPEN', priority='MEDIUM', confidence='MEDIUM',
                  site_id=None, scope_id=None, device_id=None, disposition='UNREVIEWED',
                  analyst_note=None, final_summary=None, db_path=DB_PATH):
    initialize_database(db_path)
    title = _valid_text(title, 'Title', 160, required=True)
    summary = _valid_text(summary, 'Summary', 4000)
    analyst_note = None if analyst_note is None else _valid_text(analyst_note, 'Analyst note', 4000)
    final_summary = _normalize_final_summary(final_summary)
    if state == 'CLOSED':
        raise IncidentReviewError('New incident reviews cannot be created CLOSED.')
    if state not in {'OPEN','IN_REVIEW'} or priority not in PRIORITIES or confidence not in CONFIDENCES or disposition not in DISPOSITIONS:
        raise IncidentReviewError('Incident review state, priority, confidence, or disposition is unsupported.')
    now = _now()
    closed_at = None
    incident_key = f'IR-{uuid4().hex}'
    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row
        connection.execute('BEGIN IMMEDIATE')
        _validate_attribution(connection, site_id=site_id, scope_id=scope_id, device_id=device_id)
        cursor = connection.execute('''INSERT INTO incident_reviews (
            incident_key,title,summary,state,priority,confidence,site_id,scope_id,device_id,
            created_at,updated_at,closed_at,disposition,analyst_note,final_summary)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',
            (incident_key,title,summary,state,priority,confidence,site_id,scope_id,device_id,
             now,now,closed_at,disposition,analyst_note,final_summary))
        incident_id = cursor.lastrowid
        _record_event(connection,incident_id,'REVIEW_CREATED',now=now,
                      summary='Incident review created')
        return _review(connection, incident_id)


def get_review(incident_id, db_path=DB_PATH):
    initialize_database(db_path)
    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row
        return _review(connection, incident_id)


def add_note(incident_id, note_text, db_path=DB_PATH):
    note_text = _valid_text(note_text,'Note',4000,required=True)
    initialize_database(db_path)
    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row
        connection.execute('BEGIN IMMEDIATE')
        if _review(connection,incident_id) is None:
            raise IncidentReviewError('Incident review not found.',404)
        now = _now()
        cursor = connection.execute('''INSERT INTO incident_review_notes
            (incident_review_id,note_text,actor_source,created_at) VALUES (?,?,?,?)''',
            (incident_id,note_text,'OPERATOR',now))
        note_id = cursor.lastrowid
        _record_event(connection,incident_id,'ANALYST_NOTE_ADDED',now=now,
                      note_id=note_id,new_value=note_text,summary='Analyst note added')
        return dict(connection.execute('SELECT * FROM incident_review_notes WHERE id=?',
                                       (note_id,)).fetchone())


def list_notes(incident_id, *, limit=100, offset=0, db_path=DB_PATH):
    if type(limit) is not int or not 1 <= limit <= 100 or type(offset) is not int \
            or not 0 <= offset <= REVIEW_HISTORY_MAX_OFFSET:
        raise IncidentReviewError('Note pagination is invalid.')
    initialize_database(db_path)
    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row
        if _review(connection,incident_id) is None:
            raise IncidentReviewError('Incident review not found.',404)
        total = connection.execute('SELECT COUNT(*) FROM incident_review_notes WHERE incident_review_id=?',
                                   (incident_id,)).fetchone()[0]
        rows = connection.execute('''SELECT * FROM incident_review_notes WHERE incident_review_id=?
            ORDER BY created_at DESC,id DESC LIMIT ? OFFSET ?''',
            (incident_id,limit,offset)).fetchall()
        return {'total':total,'items':[dict(row) for row in rows]}


def list_timeline(incident_id, *, limit=100, offset=0, db_path=DB_PATH):
    if type(limit) is not int or not 1 <= limit <= 100 or type(offset) is not int \
            or not 0 <= offset <= REVIEW_HISTORY_MAX_OFFSET:
        raise IncidentReviewError('Timeline pagination is invalid.')
    initialize_database(db_path)
    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row
        if _review(connection,incident_id) is None:
            raise IncidentReviewError('Incident review not found.',404)
        total = connection.execute('SELECT COUNT(*) FROM incident_review_events WHERE incident_review_id=?',
                                   (incident_id,)).fetchone()[0]
        rows = connection.execute('''SELECT * FROM incident_review_events WHERE incident_review_id=?
            ORDER BY created_at DESC,id DESC LIMIT ? OFFSET ?''',
            (incident_id,limit,offset)).fetchall()
        return {'total':total,'items':[dict(row) for row in rows]}


def list_reviews(*, limit=20, offset=0, state=None, priority=None, site_id=None,
                 scope_id=None, device_id=None, disposition=None, db_path=DB_PATH):
    if type(limit) is not int or not 1 <= limit <= 100 or type(offset) is not int \
            or not 0 <= offset <= REVIEW_HISTORY_MAX_OFFSET:
        raise IncidentReviewError('Incident review pagination is invalid.')
    initialize_database(db_path)
    clauses, params = [], []
    for column, value in (('state',state),('priority',priority),('site_id',site_id),
                          ('scope_id',scope_id),('device_id',device_id),('disposition',disposition)):
        if value is not None:
            clauses.append(f'{column}=?')
            params.append(value)
    where = ' WHERE ' + ' AND '.join(clauses) if clauses else ''
    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row
        total = connection.execute(f'SELECT COUNT(*) FROM incident_reviews{where}', params).fetchone()[0]
        rows = connection.execute(f'SELECT id FROM incident_reviews{where} ORDER BY updated_at DESC,id DESC LIMIT ? OFFSET ?',
                                  (*params,limit,offset)).fetchall()
        return {'total': total, 'items': [_review(connection,row['id']) for row in rows]}


def update_review(incident_id, updates, db_path=DB_PATH):
    allowed = {'title','summary','state','priority','confidence','disposition','analyst_note',
               'final_summary','site_id','scope_id','device_id'}
    if not isinstance(updates, dict) or not updates or set(updates) - allowed:
        raise IncidentReviewError('Update fields are unsupported or empty.')
    values = dict(updates)
    for field, maximum in (('title',160),('summary',4000),('analyst_note',4000)):
        if field in values and values[field] is None and field != 'analyst_note':
            raise IncidentReviewError(f'{field.replace("_"," ").title()} cannot be null.')
        if field in values and values[field] is not None:
            values[field] = _valid_text(values[field], field.replace('_',' ').title(), maximum,
                                        required=(field == 'title'))
    if 'final_summary' in values:
        values['final_summary'] = _normalize_final_summary(values['final_summary'])
    for field, allowed_values in (('state',STATES),('priority',PRIORITIES),('confidence',CONFIDENCES),('disposition',DISPOSITIONS)):
        if field in values and values[field] not in allowed_values:
            raise IncidentReviewError(f'{field.replace("_"," ").title()} is unsupported.')
    initialize_database(db_path)
    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row
        connection.execute('BEGIN IMMEDIATE')
        current = _review(connection, incident_id)
        if current is None:
            raise IncidentReviewError('Incident review not found.',404)
        attribution = {field: values.get(field,current[field]) for field in ('site_id','scope_id','device_id')}
        _validate_attribution(connection,**attribution)
        state = values.get('state', current['state'])
        disposition = values.get('disposition',current['disposition'])
        final_summary = values.get('final_summary',current['final_summary'])
        if state == 'CLOSED' and current['state'] != 'CLOSED':
            if disposition == 'UNREVIEWED':
                raise IncidentReviewError('A review disposition is required before closing.')
            if final_summary is None or not final_summary.strip():
                raise IncidentReviewError('A final analyst summary is required before closing.')
        if current['state'] == 'CLOSED' and any(
                field != 'state' and current[field] != value
                for field,value in values.items()):
            raise IncidentReviewError('Reopen the review before editing it.')
        now = _closure_time(connection,incident_id) if state == 'CLOSED' and current['state'] != 'CLOSED' else _now()
        changed = [(field,current[field],value) for field,value in values.items()
                   if field not in {'closed_at','updated_at'} and current[field] != value]
        closed_at = current['closed_at']
        if state == 'CLOSED' and current['state'] != 'CLOSED':
            closed_at = now
        elif state != 'CLOSED':
            closed_at = None
        values.update({'closed_at':closed_at, 'updated_at':now})
        assignments = ','.join(f'{key}=?' for key in values)
        connection.execute(f'UPDATE incident_reviews SET {assignments} WHERE id=?', (*values.values(),incident_id))
        # Stable field ordering makes events from a multi-field patch deterministic.
        field_order = ('state','priority','confidence','disposition','final_summary','title','summary',
                       'site_id','scope_id','device_id','analyst_note')
        changes = {field:(old,new) for field,old,new in changed}
        for field in field_order:
            if field in changes:
                old,new = changes[field]
                _field_event(connection,incident_id,field,old,new,now)
        return _review(connection, incident_id)


def _evidence(connection, evidence_type, evidence_id):
    query = EVIDENCE_QUERIES.get(evidence_type)
    if query is None:
        raise IncidentReviewError('Evidence type is unsupported.')
    row = connection.execute(query, (evidence_id,)).fetchone()
    if row is None:
        raise IncidentReviewError('Evidence object not found.',404)
    return dict(row)


def _validate_link_attribution(connection, incident, evidence):
    evidence = _resolve_evidence_attribution(connection,evidence)
    for field in ('site_id','scope_id','device_id'):
        linked = incident[field]
        candidate = evidence[field]
        if linked is not None and (candidate is None or linked != candidate):
            raise IncidentReviewError(f'Evidence {field} attribution cannot be proven consistent.')
    previous = connection.execute('''SELECT e.evidence_type,e.evidence_id FROM incident_review_evidence e
                                      WHERE e.incident_id=?''',(incident['id'],)).fetchall()
    for item in previous:
        old = _evidence(connection,item['evidence_type'],item['evidence_id'])
        old = _resolve_evidence_attribution(connection,old)
        for field in ('site_id','scope_id','device_id'):
            if old[field] is not None and old[field] != evidence[field]:
                raise IncidentReviewError(f'Linked evidence has conflicting {field} attribution.')


def _recompute_evidence_times(connection, incident_id):
    rows = connection.execute('SELECT observed_at FROM incident_review_evidence WHERE incident_id=?',
                              (incident_id,)).fetchall()
    values = [row['observed_at'] for row in rows]
    # ISO timestamps in evidence can use different UTC offsets; compare actual instants.
    parsed = []
    for value in values:
        instant = datetime.fromisoformat(value.replace('Z','+00:00'))
        if instant.tzinfo is None:
            instant = instant.replace(tzinfo=timezone.utc)
        parsed.append((instant,value))
    if parsed:
        first = min(parsed,key=lambda item:item[0])[1]
        last = max(parsed,key=lambda item:item[0])[1]
    else:
        first = last = None
    connection.execute('UPDATE incident_reviews SET first_evidence_at=?,last_evidence_at=? WHERE id=?',
                       (first,last,incident_id))


def _as_utc(value):
    instant = datetime.fromisoformat(value.replace('Z','+00:00'))
    if instant.tzinfo is None:
        instant = instant.replace(tzinfo=timezone.utc)
    return instant.astimezone(timezone.utc)


def _match_reason(review, evidence, anchors):
    """Return the strongest exact attribution match, or None if unsafe."""
    matches = []
    anchor_matches = []
    for field, label in (('device_id','device'),('scope_id','scope'),('site_id','site')):
        actual = evidence.get(field)
        expected = review.get(field)
        if expected is not None and actual is None:
            return None
        if expected is not None and expected != actual:
            return None
        if expected is not None:
            matches.append(label)
        for context in anchors:
            expected = context.get(field)
            if expected is not None and actual is None:
                return None
            if expected is not None and expected != actual:
                return None
            if expected is not None:
                anchor_matches.append(label)
    if not matches and not anchor_matches:
        return None
    return f"Same {(matches or anchor_matches)[0]} within review time window"


def list_related_evidence(incident_id, *, limit=100, evidence_type=None, db_path=DB_PATH):
    """Return bounded read-only suggestions compatible with a review."""
    if type(limit) is not int or not 1 <= limit <= 100:
        raise IncidentReviewError('Related evidence limit must be between 1 and 100.')
    if evidence_type is not None and evidence_type not in EVIDENCE_QUERIES:
        raise IncidentReviewError('Evidence type is unsupported.')
    initialize_database(db_path)
    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row
        review = _review(connection, incident_id)
        if review is None:
            raise IncidentReviewError('Incident review not found.',404)
        if not review['first_evidence_at'] or not review['last_evidence_at']:
            return {'total':0,'items':[]}

        first = _as_utc(review['first_evidence_at']) - RELATED_EVIDENCE_WINDOW
        last = _as_utc(review['last_evidence_at']) + RELATED_EVIDENCE_WINDOW
        start, end = first.isoformat(), last.isoformat()
        linked = {(row['evidence_type'],row['evidence_id']) for row in connection.execute(
            'SELECT evidence_type,evidence_id FROM incident_review_evidence WHERE incident_id=?',
            (incident_id,)).fetchall()}
        anchors = []
        for kind, source_id in linked:
            try:
                anchors.append(_resolve_evidence_attribution(
                    connection,_evidence(connection,kind,source_id)))
            except IncidentReviewError as exc:
                if exc.status_code != 404:
                    # Invalid or ambiguous persisted attribution cannot anchor
                    # suggestions. Keep the stale link visible through 13A.
                    continue
        candidates = []
        evidence_types = (evidence_type,) if evidence_type else tuple(EVIDENCE_QUERIES)
        for kind in evidence_types:
            query = RELATED_EVIDENCE_QUERIES[kind]
            # Pull bounded pages. Scanning stops after 100 compatible rows per
            # type, which is sufficient to compute the global top 100.
            scanned = 0
            offset = 0
            while scanned < RELATED_EVIDENCE_SCAN_LIMIT:
                page_size = min(RELATED_EVIDENCE_BATCH_SIZE,
                                RELATED_EVIDENCE_SCAN_LIMIT - scanned)
                rows = connection.execute(
                    f"SELECT * FROM ({query.rstrip(';')}) WHERE julianday(observed_at) >= julianday(?) "
                    "AND julianday(observed_at) <= julianday(?) "
                    "ORDER BY julianday(observed_at) DESC,id ASC LIMIT ? OFFSET ?",
                    (start,end,page_size,offset)).fetchall()
                if not rows:
                    break
                scanned += len(rows)
                offset += len(rows)
                for row in rows:
                    try:
                        source = _resolve_evidence_attribution(connection,dict(row))
                    except IncidentReviewError:
                        continue
                    if kind == 'EXTERNAL_EXPOSURE_CHANGE' and source['scope_id'] is not None:
                        site_count = connection.execute(
                            'SELECT COUNT(DISTINCT site_id) FROM remote_scope_sites WHERE scope_id=?',
                            (source['scope_id'],)).fetchone()[0]
                        if site_count != 1:
                            continue
                    reason = _match_reason(review,source,anchors)
                    if reason is None:
                        continue
                    key = (kind,source['id'])
                    candidates.append({
                        'evidence_type':kind,
                        'evidence_id':source['id'],
                        'observed_at':source['observed_at'],
                        'source_status':'AVAILABLE',
                        'already_linked':key in linked,
                        'match_reason':reason,
                    })
                if len([item for item in candidates if item['evidence_type']==kind]) >= 100:
                    break
                if len(rows) < page_size:
                    break
        # Stable passes preserve ascending type/ID ties under descending time.
        candidates.sort(key=lambda item:(item['evidence_type'],item['evidence_id']))
        candidates.sort(key=lambda item:_as_utc(item['observed_at']),reverse=True)
        bounded = candidates[:100]
        return {'total':len(bounded),'items':bounded[:limit]}


def add_evidence(incident_id, *, evidence_type, evidence_id, reason=None, db_path=DB_PATH):
    if type(evidence_id) is not int or evidence_id <= 0:
        raise IncidentReviewError('Evidence ID must be a positive integer.')
    if reason is not None:
        reason = _valid_text(reason,'Evidence relation reason',500)
    initialize_database(db_path)
    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row
        connection.execute('BEGIN IMMEDIATE')
        incident = _review(connection,incident_id)
        if incident is None:
            raise IncidentReviewError('Incident review not found.',404)
        evidence = _evidence(connection,evidence_type,evidence_id)
        _validate_link_attribution(connection,incident,evidence)
        now = _now()
        cursor = connection.execute('''INSERT OR IGNORE INTO incident_review_evidence
            (incident_id,evidence_type,evidence_id,observed_at,added_at,reason) VALUES (?,?,?,?,?,?)''',
            (incident_id,evidence_type,evidence_id,evidence['observed_at'],now,reason))
        linked = connection.execute('SELECT * FROM incident_review_evidence WHERE incident_id=? AND evidence_type=? AND evidence_id=?',
                                    (incident_id,evidence_type,evidence_id)).fetchone()
        _recompute_evidence_times(connection,incident_id)
        connection.execute('UPDATE incident_reviews SET updated_at=? WHERE id=?',(now,incident_id))
        if cursor.rowcount:
            _record_event(connection,incident_id,'EVIDENCE_ATTACHED',now=now,
                          evidence_type=evidence_type,evidence_id=evidence_id,
                          summary='Evidence attached to review')
        result = dict(linked)
        result['idempotent'] = cursor.rowcount == 0
        return result


def list_evidence(incident_id, *, limit=100, offset=0, db_path=DB_PATH):
    if type(limit) is not int or not 1 <= limit <= 500 or type(offset) is not int \
            or not 0 <= offset <= REVIEW_HISTORY_MAX_OFFSET:
        raise IncidentReviewError('Incident evidence pagination is invalid.')
    initialize_database(db_path)
    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row
        if _review(connection,incident_id) is None:
            raise IncidentReviewError('Incident review not found.',404)
        rows = connection.execute('''SELECT * FROM incident_review_evidence WHERE incident_id=?
            ORDER BY julianday(observed_at),id LIMIT ? OFFSET ?''',(incident_id,limit,offset)).fetchall()
        total = connection.execute('SELECT COUNT(*) FROM incident_review_evidence WHERE incident_id=?',(incident_id,)).fetchone()[0]
        items = []
        for row in rows:
            item = dict(row)
            try:
                _evidence(connection,item['evidence_type'],item['evidence_id'])
            except IncidentReviewError as exc:
                if exc.status_code != 404:
                    raise
                item['source_status'] = 'MISSING'
            else:
                item['source_status'] = 'AVAILABLE'
            items.append(item)
        return {'total':total,'items':items}


def remove_evidence(incident_id, evidence_type, evidence_id, db_path=DB_PATH):
    if evidence_type not in EVIDENCE_QUERIES:
        raise IncidentReviewError('Evidence type is unsupported.')
    initialize_database(db_path)
    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row
        connection.execute('BEGIN IMMEDIATE')
        if _review(connection,incident_id) is None:
            raise IncidentReviewError('Incident review not found.',404)
        cursor = connection.execute('DELETE FROM incident_review_evidence WHERE incident_id=? AND evidence_type=? AND evidence_id=?',
                                   (incident_id,evidence_type,evidence_id))
        if cursor.rowcount == 0:
            raise IncidentReviewError('Incident evidence link not found.',404)
        _recompute_evidence_times(connection,incident_id)
        now = _now()
        connection.execute('UPDATE incident_reviews SET updated_at=? WHERE id=?',(now,incident_id))
        _record_event(connection,incident_id,'EVIDENCE_DETACHED',now=now,
                       evidence_type=evidence_type,evidence_id=evidence_id,
                       summary='Evidence detached from review')
        return {'removed':True}
