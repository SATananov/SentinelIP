"""Manual incident review containers over immutable persisted evidence."""
import sqlite3
from datetime import datetime, timezone
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


class IncidentReviewError(ValueError):
    def __init__(self, message, status_code=422):
        super().__init__(message)
        self.status_code = status_code


def _now():
    return datetime.now(timezone.utc).isoformat(timespec='seconds')


def _valid_text(value, name, maximum, *, required=False):
    if not isinstance(value, str) or len(value) > maximum or (required and not value.strip()):
        raise IncidentReviewError(f'{name} is invalid.')
    return value.strip() if required else value


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


def create_review(*, title, summary='', state='OPEN', priority='MEDIUM', confidence='MEDIUM',
                  site_id=None, scope_id=None, device_id=None, disposition='UNREVIEWED',
                  analyst_note=None, db_path=DB_PATH):
    initialize_database(db_path)
    title = _valid_text(title, 'Title', 160, required=True)
    summary = _valid_text(summary, 'Summary', 4000)
    analyst_note = None if analyst_note is None else _valid_text(analyst_note, 'Analyst note', 4000)
    if state not in STATES or priority not in PRIORITIES or confidence not in CONFIDENCES or disposition not in DISPOSITIONS:
        raise IncidentReviewError('Incident review state, priority, confidence, or disposition is unsupported.')
    now = _now()
    closed_at = now if state == 'CLOSED' else None
    incident_key = f'IR-{uuid4().hex}'
    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row
        connection.execute('BEGIN IMMEDIATE')
        _validate_attribution(connection, site_id=site_id, scope_id=scope_id, device_id=device_id)
        cursor = connection.execute('''INSERT INTO incident_reviews (
            incident_key,title,summary,state,priority,confidence,site_id,scope_id,device_id,
            created_at,updated_at,closed_at,disposition,analyst_note)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',
            (incident_key,title,summary,state,priority,confidence,site_id,scope_id,device_id,
             now,now,closed_at,disposition,analyst_note))
        return _review(connection, cursor.lastrowid)


def get_review(incident_id, db_path=DB_PATH):
    initialize_database(db_path)
    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row
        return _review(connection, incident_id)


def list_reviews(*, limit=20, offset=0, state=None, priority=None, site_id=None,
                 scope_id=None, device_id=None, disposition=None, db_path=DB_PATH):
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
               'site_id','scope_id','device_id'}
    if not isinstance(updates, dict) or not updates or set(updates) - allowed:
        raise IncidentReviewError('Update fields are unsupported or empty.')
    values = dict(updates)
    for field, maximum in (('title',160),('summary',4000),('analyst_note',4000)):
        if field in values and values[field] is None and field != 'analyst_note':
            raise IncidentReviewError(f'{field.replace("_"," ").title()} cannot be null.')
        if field in values and values[field] is not None:
            values[field] = _valid_text(values[field], field.replace('_',' ').title(), maximum,
                                        required=(field == 'title'))
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
        now = _now()
        closed_at = current['closed_at']
        if state == 'CLOSED' and current['state'] != 'CLOSED':
            closed_at = now
        elif state != 'CLOSED':
            closed_at = None
        values.update({'closed_at':closed_at, 'updated_at':now})
        assignments = ','.join(f'{key}=?' for key in values)
        connection.execute(f'UPDATE incident_reviews SET {assignments} WHERE id=?', (*values.values(),incident_id))
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
        result = dict(linked)
        result['idempotent'] = cursor.rowcount == 0
        return result


def list_evidence(incident_id, *, limit=100, offset=0, db_path=DB_PATH):
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
        connection.execute('UPDATE incident_reviews SET updated_at=? WHERE id=?',(_now(),incident_id))
        return {'removed':True}
