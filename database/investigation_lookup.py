"""Bounded, typed, operator-safe cross-domain investigation lookups."""
from datetime import datetime, timezone
import ipaddress
import re
import sqlite3
import uuid

from database.db import DB_PATH, get_connection, initialize_database
from services.remote_sensor_models import fleet_sensor_health


QUERY_TYPES = frozenset({
    'IP_ADDRESS', 'DEVICE_ID', 'SENSOR_ID', 'SITE_ID', 'SCOPE_ID',
    'INCIDENT_REVIEW_ID', 'INCIDENT_REVIEW_KEY', 'TASK_ID', 'EVIDENCE_REFERENCE',
})
EVIDENCE_TYPES = frozenset({
    'PERIMETER_DETECTION', 'PERIMETER_POLICY_CORRELATION',
    'PERIMETER_HOST_CORRELATION', 'EXTERNAL_EXPOSURE_CHANGE',
    'THREAT_DETECTION', 'THREAT_CORRELATION',
})
IP_GLOBAL_LIMIT = 25
IP_TYPE_LIMIT = 5
_REVIEW_KEY = re.compile(r'^IR-[0-9a-f]{32}$')
_POSITIVE_INTEGER = re.compile(r'^[1-9][0-9]*$')


class InvestigationLookupError(ValueError):
    pass


def _utc_timestamp(value):
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            return None
        return parsed.astimezone(timezone.utc).isoformat()
    except (ValueError, OverflowError):
        return None


def _base(entity_type, entity_id, label, *, context_label=None, site_id=None,
          site_name=None, scope_id=None, scope_name=None, device_id=None,
          sensor_id=None, occurred_at=None, destination_kind=None,
          destination_id=None):
    return {
        'entity_type': entity_type,
        'entity_id': str(entity_id),
        'label': str(label),
        'context_label': context_label,
        'site_id': site_id,
        'site_name': site_name,
        'scope_id': scope_id,
        'scope_name': scope_name,
        'device_id': device_id,
        'sensor_id': sensor_id,
        'occurred_at': _utc_timestamp(occurred_at),
        'destination_kind': destination_kind or entity_type,
        'destination_id': str(destination_id if destination_id is not None else entity_id),
    }


def _numeric(value):
    if not isinstance(value, str) or not _POSITIVE_INTEGER.fullmatch(value):
        raise InvestigationLookupError('value must be a positive base-10 integer.')
    parsed = int(value)
    if parsed > 9223372036854775807:
        raise InvestigationLookupError('value is outside the supported identifier range.')
    return parsed


def _validate(query_type, value, evidence_type, evidence_id):
    if query_type not in QUERY_TYPES:
        raise InvestigationLookupError('Unsupported query_type.')
    if query_type == 'EVIDENCE_REFERENCE':
        if value is not None:
            raise InvestigationLookupError('value is not accepted for EVIDENCE_REFERENCE.')
        if evidence_type is None or evidence_id is None:
            raise InvestigationLookupError('evidence_type and evidence_id are required.')
        if evidence_type not in EVIDENCE_TYPES:
            raise InvestigationLookupError('Unsupported evidence_type.')
        return _numeric(evidence_id)
    if evidence_type is not None or evidence_id is not None:
        raise InvestigationLookupError('Evidence fields are only accepted for EVIDENCE_REFERENCE.')
    if not isinstance(value, str) or not value or not value.strip() or value != value.strip():
        raise InvestigationLookupError('value must be non-empty and contain no surrounding whitespace.')
    if query_type in {'DEVICE_ID', 'SENSOR_ID', 'SITE_ID', 'SCOPE_ID', 'INCIDENT_REVIEW_ID'}:
        return _numeric(value)
    if query_type == 'INCIDENT_REVIEW_KEY':
        if not _REVIEW_KEY.fullmatch(value):
            raise InvestigationLookupError('value must be an exact lowercase Incident Review key.')
        return value
    if query_type == 'TASK_ID':
        try:
            parsed = uuid.UUID(value)
        except (ValueError, AttributeError) as exc:
            raise InvestigationLookupError('value must be a canonical UUID.') from exc
        if str(parsed) != value:
            raise InvestigationLookupError('value must be a canonical lowercase UUID.')
        return value
    if query_type == 'IP_ADDRESS':
        try:
            parsed = ipaddress.IPv4Address(value)
        except ipaddress.AddressValueError as exc:
            raise InvestigationLookupError('value must be a canonical IPv4 address.') from exc
        if str(parsed) != value:
            raise InvestigationLookupError('value must be a canonical IPv4 address.')
        return value
    raise InvestigationLookupError('Unsupported query_type.')


def _one(connection, sql, params=()):
    row = connection.execute(sql, params).fetchone()
    return dict(row) if row is not None else None


def _lookup_device(connection, device_id):
    row = _one(connection, """SELECT d.id,d.last_ip_address,d.last_seen,d.identity_confidence,
        COALESCE(d.scope_id,nsl.scope_id) AS scope_id,s.name AS scope_name,
        rss.site_id,site.name AS site_name
        FROM devices d
        LEFT JOIN network_scope_links nsl ON nsl.network_id=d.network_id
        LEFT JOIN authorized_scopes s ON s.id=COALESCE(d.scope_id,nsl.scope_id)
        LEFT JOIN remote_scope_sites rss ON rss.scope_id=s.id
        LEFT JOIN sites site ON site.id=rss.site_id WHERE d.id=?""", (device_id,))
    if row is None:
        return None
    context = [row['last_ip_address']]
    if row['identity_confidence'] in {'HIGH', 'MEDIUM', 'LOW'}:
        context.append(f"Identity confidence {row['identity_confidence'].lower()}")
    return _base('DEVICE', row['id'], f"Device {row['id']}",
        context_label=' · '.join(part for part in context if part),
        site_id=row['site_id'], site_name=row['site_name'], scope_id=row['scope_id'],
        scope_name=row['scope_name'], device_id=row['id'], occurred_at=row['last_seen'])


def _lookup_sensor(connection, sensor_id):
    row = _one(connection, """SELECT rs.id,rs.site_id,rs.name,rs.platform,rs.version,rs.enabled,
        rs.credential_revoked_at,rs.last_seen_at,site.name AS site_name,site.enabled AS site_enabled
        FROM remote_sensors rs LEFT JOIN sites site ON site.id=rs.site_id WHERE rs.id=?""", (sensor_id,))
    if row is None:
        return None
    now = datetime.now(timezone.utc)
    status, _age = fleet_sensor_health(enabled=bool(row['enabled']),
        site_enabled=None if row['site_enabled'] is None else bool(row['site_enabled']),
        credential_revoked_at=row['credential_revoked_at'], last_seen_at=row['last_seen_at'], now=now)
    metadata = ' · '.join(value for value in (row['platform'], row['version']) if value)
    return _base('SENSOR', row['id'], row['name'],
        context_label=' · '.join(value for value in (status, metadata) if value),
        site_id=row['site_id'], site_name=row['site_name'], sensor_id=row['id'],
        occurred_at=row['last_seen_at'])


def _lookup_site(connection, site_id):
    row = _one(connection, 'SELECT id,name FROM sites WHERE id=?', (site_id,))
    if row is None:
        return None
    return _base('SITE', row['id'], row['name'], site_id=row['id'], site_name=row['name'])


def _lookup_scope(connection, scope_id):
    row = _one(connection, """SELECT s.id,s.name,s.scope_type,s.canonical_target,s.enabled,
        s.authorized,rss.site_id,site.name AS site_name
        FROM authorized_scopes s LEFT JOIN remote_scope_sites rss ON rss.scope_id=s.id
        LEFT JOIN sites site ON site.id=rss.site_id WHERE s.id=?""", (scope_id,))
    if row is None:
        return None
    state = 'Enabled' if row['enabled'] else 'Disabled'
    authorization = 'Authorized' if row['authorized'] else 'Not authorized'
    context = ' · '.join(part for part in (row['scope_type'], row['canonical_target'], state, authorization) if part)
    return _base('SCOPE', row['id'], row['name'] or f"Scope {row['id']}",
        context_label=context, site_id=row['site_id'], site_name=row['site_name'],
        scope_id=row['id'], scope_name=row['name'])


def _lookup_review(connection, incident_id):
    row = _one(connection, """SELECT r.id,r.title,r.state,r.priority,r.confidence,r.disposition,
        r.site_id,site.name AS site_name,r.scope_id,scope.name AS scope_name,r.device_id,r.created_at
        FROM incident_reviews r LEFT JOIN sites site ON site.id=r.site_id
        LEFT JOIN authorized_scopes scope ON scope.id=r.scope_id WHERE r.id=?""", (incident_id,))
    if row is None:
        return None
    context = ' · '.join(value for value in (row['state'], row['priority'], row['confidence'], row['disposition']) if value)
    return _base('INCIDENT_REVIEW', row['id'], row['title'], context_label=context,
        site_id=row['site_id'], site_name=row['site_name'], scope_id=row['scope_id'],
        scope_name=row['scope_name'], device_id=row['device_id'], occurred_at=row['created_at'])


def _lookup_task(connection, task_id):
    row = _one(connection, """SELECT t.id,t.sensor_id,sensor.name AS sensor_name,t.site_id,
        site.name AS site_name,t.scope_id,scope.name AS scope_name,t.target_device_id,t.target_ip,
        t.task_type,t.status,t.created_at FROM remote_sensor_tasks t
        LEFT JOIN remote_sensors sensor ON sensor.id=t.sensor_id
        LEFT JOIN sites site ON site.id=t.site_id
        LEFT JOIN authorized_scopes scope ON scope.id=t.scope_id WHERE t.id=?""", (task_id,))
    if row is None:
        return None
    context = ' · '.join(value for value in (row['task_type'], row['status'], row['target_ip']) if value)
    return _base('SENSOR_TASK', row['id'], f"Sensor task {row['id']}", context_label=context,
        site_id=row['site_id'], site_name=row['site_name'], scope_id=row['scope_id'],
        scope_name=row['scope_name'], device_id=row['target_device_id'], sensor_id=row['sensor_id'],
        occurred_at=row['created_at'])


def _evidence_lookup(connection, evidence_type, evidence_id):
    if evidence_type == 'THREAT_DETECTION':
        row = _one(connection, "SELECT id,threat_type,severity,device_id,last_seen FROM threat_detections WHERE id=?", (evidence_id,))
        if row is None: return None
        return _base(evidence_type, row['id'], f"Threat detection {row['id']}",
            context_label=' · '.join((row['threat_type'], row['severity'])), device_id=row['device_id'], occurred_at=row['last_seen'])
    if evidence_type == 'THREAT_CORRELATION':
        row = _one(connection, "SELECT id,correlation_type,severity,device_id,last_seen FROM correlations WHERE id=?", (evidence_id,))
        if row is None: return None
        return _base(evidence_type, row['id'], f"Threat correlation {row['id']}",
            context_label=' · '.join((row['correlation_type'], row['severity'])), device_id=row['device_id'], occurred_at=row['last_seen'])
    if evidence_type == 'PERIMETER_DETECTION':
        row = _one(connection, "SELECT id,site_id,detection_type,action,first_seen FROM perimeter_detections WHERE id=?", (evidence_id,))
        if row is None: return None
        site = _one(connection, 'SELECT name FROM sites WHERE id=?', (row['site_id'],))
        return _base(evidence_type, row['id'], f"Perimeter detection {row['id']}",
            context_label=' · '.join(value for value in (row['detection_type'], row['action']) if value),
            site_id=row['site_id'], site_name=site['name'] if site else None, occurred_at=row['first_seen'])
    if evidence_type == 'PERIMETER_POLICY_CORRELATION':
        row = _one(connection, "SELECT id,site_id,correlation_type,primary_action,first_seen FROM perimeter_policy_correlations WHERE id=?", (evidence_id,))
        if row is None: return None
        site = _one(connection, 'SELECT name FROM sites WHERE id=?', (row['site_id'],))
        return _base(evidence_type, row['id'], f"Perimeter policy correlation {row['id']}",
            context_label=' · '.join(value for value in (row['correlation_type'], row['primary_action']) if value),
            site_id=row['site_id'], site_name=site['name'] if site else None, occurred_at=row['first_seen'])
    if evidence_type == 'PERIMETER_HOST_CORRELATION':
        row = _one(connection, """SELECT h.id,h.site_id,site.name AS site_name,h.scope_id,scope.name AS scope_name,
            h.device_id,h.correlation_type,h.action,h.observed_at FROM perimeter_host_correlations h
            LEFT JOIN sites site ON site.id=h.site_id LEFT JOIN authorized_scopes scope ON scope.id=h.scope_id
            WHERE h.id=?""", (evidence_id,))
        if row is None: return None
        return _base(evidence_type, row['id'], f"Perimeter host correlation {row['id']}",
            context_label=' · '.join(value for value in (row['correlation_type'], row['action']) if value),
            site_id=row['site_id'], site_name=row['site_name'], scope_id=row['scope_id'],
            scope_name=row['scope_name'], device_id=row['device_id'], occurred_at=row['observed_at'])
    if evidence_type == 'EXTERNAL_EXPOSURE_CHANGE':
        row = _one(connection, """SELECT c.id,c.change_type,c.observed_at,c.scope_id,scope.name AS scope_name,
            rss.site_id,site.name AS site_name,e.device_id FROM external_exposure_changes c
            LEFT JOIN authorized_scopes scope ON scope.id=c.scope_id
            LEFT JOIN remote_scope_sites rss ON rss.scope_id=c.scope_id
            LEFT JOIN sites site ON site.id=rss.site_id
            LEFT JOIN external_exposures e ON e.id=c.exposure_id WHERE c.id=?""", (evidence_id,))
        if row is None: return None
        return _base(evidence_type, row['id'], f"External exposure change {row['id']}",
            context_label=row['change_type'], site_id=row['site_id'], site_name=row['site_name'],
            scope_id=row['scope_id'], scope_name=row['scope_name'], device_id=row['device_id'],
            occurred_at=row['observed_at'])
    raise InvestigationLookupError('Unsupported evidence_type.')


def _ip_rows(connection, ip):
    # Fixed projections only. Each source fetches at most one row beyond its type cap.
    queries = [
        ('DEVICE', """SELECT d.id,d.last_seen,d.identity_confidence FROM devices d WHERE d.last_ip_address=?
            ORDER BY julianday(d.last_seen) DESC,d.id DESC""", (ip,), 'last_seen'),
        ('LEGACY_EVENT', "SELECT id,timestamp AS occurred_at,severity FROM events WHERE source_ip=? ORDER BY julianday(timestamp) DESC,id DESC", (ip,), 'occurred_at'),
        ('THREAT_DETECTION', "SELECT id,last_seen AS occurred_at,threat_type,severity,device_id FROM threat_detections WHERE source_ip=? ORDER BY julianday(last_seen) DESC,id DESC", (ip,), 'occurred_at'),
        ('THREAT_CORRELATION', "SELECT id,last_seen AS occurred_at,correlation_type,severity,device_id FROM correlations WHERE source_ip=? ORDER BY julianday(last_seen) DESC,id DESC", (ip,), 'occurred_at'),
        ('PERIMETER_EVENT', "SELECT e.id,e.site_id,site.name AS site_name,e.event_type,e.direction,e.action,e.observed_at AS occurred_at FROM perimeter_events e LEFT JOIN sites site ON site.id=e.site_id WHERE e.source_ip=? OR e.destination_ip=? ORDER BY julianday(e.observed_at) DESC,e.id DESC", (ip, ip), 'occurred_at'),
        ('PERIMETER_DETECTION', "SELECT d.id,d.site_id,site.name AS site_name,d.detection_type,d.action,d.first_seen AS occurred_at FROM perimeter_detections d LEFT JOIN sites site ON site.id=d.site_id WHERE d.source_ip=? OR d.destination_ip=? ORDER BY julianday(d.first_seen) DESC,d.id DESC", (ip, ip), 'occurred_at'),
        ('PERIMETER_POLICY_CORRELATION', "SELECT c.id,c.site_id,site.name AS site_name,c.correlation_type,c.primary_action,c.first_seen AS occurred_at FROM perimeter_policy_correlations c LEFT JOIN sites site ON site.id=c.site_id WHERE c.source_ip=? OR c.destination_ip=? ORDER BY julianday(c.first_seen) DESC,c.id DESC", (ip, ip), 'occurred_at'),
        ('PERIMETER_HOST_CORRELATION', "SELECT h.id,h.site_id,site.name AS site_name,h.scope_id,scope.name AS scope_name,h.device_id,h.correlation_type,h.action,h.observed_at AS occurred_at FROM perimeter_host_correlations h LEFT JOIN sites site ON site.id=h.site_id LEFT JOIN authorized_scopes scope ON scope.id=h.scope_id WHERE h.destination_ip=? ORDER BY julianday(h.observed_at) DESC,h.id DESC", (ip,), 'occurred_at'),
        ('EXTERNAL_EXPOSURE', "SELECT e.id,e.scope_id,scope.name AS scope_name,e.device_id,e.target_ip,e.port_number,e.transport,e.last_seen AS occurred_at,rss.site_id,site.name AS site_name FROM external_exposures e LEFT JOIN authorized_scopes scope ON scope.id=e.scope_id LEFT JOIN remote_scope_sites rss ON rss.scope_id=e.scope_id LEFT JOIN sites site ON site.id=rss.site_id WHERE e.target_ip=? ORDER BY julianday(e.last_seen) DESC,e.id DESC", (ip,), 'occurred_at'),
        ('EXTERNAL_EXPOSURE_CHANGE', """SELECT c.id,c.scope_id,scope.name AS scope_name,e.device_id,c.change_type,c.observed_at AS occurred_at,
            rss.site_id,site.name AS site_name
            FROM external_exposure_changes c JOIN external_exposures e ON e.id=c.exposure_id
            LEFT JOIN authorized_scopes scope ON scope.id=c.scope_id
            LEFT JOIN remote_scope_sites rss ON rss.scope_id=c.scope_id
            LEFT JOIN sites site ON site.id=rss.site_id
            WHERE e.target_ip=? ORDER BY julianday(c.observed_at) DESC,c.id DESC""", (ip,), 'occurred_at'),
    ]
    items, truncated = [], False
    for entity_type, sql, params, time_key in queries:
        rows = [dict(row) for row in connection.execute(sql + ' LIMIT ?', (*params, IP_TYPE_LIMIT + 1)).fetchall()]
        if len(rows) > IP_TYPE_LIMIT:
            truncated = True
        for row in rows[:IP_TYPE_LIMIT]:
            entity_id = row['id']
            if entity_type == 'DEVICE':
                item = _base(entity_type, entity_id, f"Device {entity_id}",
                    context_label=' · '.join(value for value in (ip, f"Identity confidence {row['identity_confidence'].lower()}" if row['identity_confidence'] in {'HIGH','MEDIUM','LOW'} else None) if value),
                    device_id=entity_id, occurred_at=row[time_key])
            elif entity_type == 'LEGACY_EVENT':
                severity = row['severity'] if row['severity'] in {'INFO','WARNING','ALERT'} else None
                item = _base(entity_type, entity_id, f"Legacy event {entity_id}", context_label=severity, occurred_at=row[time_key])
            elif entity_type in {'THREAT_DETECTION','THREAT_CORRELATION'}:
                kind_key = 'threat_type' if entity_type == 'THREAT_DETECTION' else 'correlation_type'
                item = _base(entity_type, entity_id, f"{entity_type.replace('_',' ').title()} {entity_id}",
                    context_label=' · '.join(value for value in (row[kind_key], row['severity']) if value),
                    device_id=row['device_id'], occurred_at=row[time_key])
            elif entity_type == 'PERIMETER_EVENT':
                item = _base(entity_type, entity_id, f"Perimeter event {entity_id}",
                    context_label=' · '.join(value for value in (row['event_type'],row['direction'],row['action']) if value),
                    site_id=row['site_id'],site_name=row['site_name'],occurred_at=row[time_key])
            elif entity_type == 'PERIMETER_DETECTION':
                item = _base(entity_type, entity_id, f"Perimeter detection {entity_id}",
                    context_label=' · '.join(value for value in (row['detection_type'],row['action']) if value),
                    site_id=row['site_id'],site_name=row['site_name'],occurred_at=row[time_key])
            elif entity_type == 'PERIMETER_POLICY_CORRELATION':
                item = _base(entity_type, entity_id, f"Perimeter policy correlation {entity_id}",
                    context_label=' · '.join(value for value in (row['correlation_type'],row['primary_action']) if value),
                    site_id=row['site_id'],site_name=row['site_name'],occurred_at=row[time_key])
            elif entity_type == 'PERIMETER_HOST_CORRELATION':
                item = _base(entity_type, entity_id, f"Perimeter host correlation {entity_id}",
                    context_label=' · '.join(value for value in (row['correlation_type'],row['action']) if value),
                    site_id=row['site_id'],site_name=row['site_name'],scope_id=row['scope_id'],
                    scope_name=row['scope_name'],device_id=row['device_id'],occurred_at=row[time_key])
            elif entity_type == 'EXTERNAL_EXPOSURE':
                item = _base(entity_type, entity_id, f"External exposure {entity_id}",
                    context_label=f"{row['target_ip']} · TCP/{row['port_number']}",site_id=row['site_id'],
                    site_name=row['site_name'],scope_id=row['scope_id'],
                    scope_name=row['scope_name'],device_id=row['device_id'],occurred_at=row[time_key])
            else:
                item = _base(entity_type, entity_id, f"External exposure change {entity_id}",
                    context_label=row['change_type'],site_id=row['site_id'],
                    site_name=row['site_name'],scope_id=row['scope_id'],
                    scope_name=row['scope_name'],device_id=row['device_id'],occurred_at=row[time_key])
            items.append(item)

    scope = _one(connection, """SELECT id,name,canonical_target FROM authorized_scopes
        WHERE scope_type='PUBLIC_IPV4' AND canonical_target=? ORDER BY id LIMIT 1""", (ip,))
    if scope is not None:
        items.append(_base('SCOPE',scope['id'],scope['name'] or f"Scope {scope['id']}",
            context_label=f"PUBLIC_IPV4 · {scope['canonical_target']}",scope_id=scope['id'],scope_name=scope['name']))
    by_key = {}
    for item in items:
        by_key[(item['entity_type'],item['entity_id'])] = item
    items = list(by_key.values())
    # Stable sorts implement timestamp DESC (null last), type ASC, ID DESC.
    items.sort(key=lambda item: int(item['entity_id']), reverse=True)
    items.sort(key=lambda item: item['entity_type'])
    items.sort(key=lambda item: (item['occurred_at'] is not None, item['occurred_at'] or ''), reverse=True)
    if len(items) > IP_GLOBAL_LIMIT:
        truncated = True
    return items[:IP_GLOBAL_LIMIT], truncated


def investigation_lookup(query_type, *, value=None, evidence_type=None,
                         evidence_id=None, db_path=DB_PATH):
    selected = _validate(query_type, value, evidence_type, evidence_id)
    initialize_database(db_path)
    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row
        if query_type == 'IP_ADDRESS':
            items, truncated = _ip_rows(connection, selected)
        elif query_type == 'DEVICE_ID':
            item, truncated = _lookup_device(connection, selected), False
            items = [item] if item else []
        elif query_type == 'SENSOR_ID':
            item, truncated = _lookup_sensor(connection, selected), False
            items = [item] if item else []
        elif query_type == 'SITE_ID':
            item, truncated = _lookup_site(connection, selected), False
            items = [item] if item else []
        elif query_type == 'SCOPE_ID':
            item, truncated = _lookup_scope(connection, selected), False
            items = [item] if item else []
        elif query_type in {'INCIDENT_REVIEW_ID','INCIDENT_REVIEW_KEY'}:
            if query_type == 'INCIDENT_REVIEW_KEY':
                row = _one(connection, 'SELECT id FROM incident_reviews WHERE incident_key=?', (selected,))
                selected = row['id'] if row else None
            item = _lookup_review(connection, selected) if selected is not None else None
            truncated = False
            items = [item] if item else []
        elif query_type == 'TASK_ID':
            item, truncated = _lookup_task(connection, selected), False
            items = [item] if item else []
        else:
            item = _evidence_lookup(connection, evidence_type, selected)
            truncated = False
            items = [item] if item else []
    return {'query_type': query_type, 'items': items, 'truncated': truncated}
