"""Typed, assignment-bound remote sensor task persistence."""
from datetime import datetime, timedelta, timezone
import ipaddress
import uuid

from database.db import get_connection
from database.remote_sensors import RemoteSensorStore
from database.management_audit import record_event
from services.remote_sensor_models import Capability, RemoteSensorError, private_lan
from services.scope_authorization import require_private_network_scope

TASK_TYPES = frozenset({'DISCOVER_NETWORK', 'DISCOVER_SERVICES'})
TASK_TTL_SECONDS = 900
MAX_ACTIVE_TASKS_PER_SENSOR = 20
TASK_STATES = frozenset({'PENDING', 'CLAIMED', 'RUNNING', 'COMPLETED', 'FAILED', 'CANCELLED'})
TASK_FAILURE_MESSAGES = {
    'TASK_EXPIRED': 'Task expired before completion.',
    'SENSOR_DISABLED': 'Sensor was unavailable for this task.',
    'SCOPE_DISABLED': 'Assigned scope was unavailable for this task.',
    'SCOPE_NOT_ASSIGNED': 'The task scope was no longer assigned.',
    'CAPABILITY_NOT_ALLOWED': 'The sensor did not have the required declared capability.',
    'TARGET_OUTSIDE_SCOPE': 'The task target was outside the assigned scope.',
    'CANCELLED': 'Task was cancelled by the sensor.',
    'SCANNER_TIMEOUT': 'Sensor scanner timed out.',
    'SCANNER_FAILED': 'Sensor scanner reported a failure.',
    'INVALID_RESULT': 'Sensor returned an invalid result.',
    'RESULT_OUTSIDE_SCOPE': 'Sensor result was outside the assigned scope.',
}
TASK_FAILURE_CODES = frozenset(TASK_FAILURE_MESSAGES)
TERMINAL_TASK_STATES = frozenset({'COMPLETED', 'FAILED', 'CANCELLED'})
TASK_HISTORY_MAX_RANGE = timedelta(days=90)


class RemoteTaskError(ValueError):
    def __init__(self, code, message, status_code=400):
        super().__init__(message)
        self.code = code
        self.status_code = status_code


class RemoteTaskStore:
    def __init__(self, sensor_store: RemoteSensorStore):
        self.sensors = sensor_store
        self.db_path = sensor_store.db_path

    @staticmethod
    def _task(row):
        return dict(row) if row is not None else None

    @staticmethod
    def _history_datetime(value):
        if value is None:
            return None
        if isinstance(value, datetime):
            parsed = value
        elif isinstance(value, str):
            try:
                parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
            except ValueError:
                return None
        else:
            return None
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            return None
        return parsed.astimezone(timezone.utc)

    @classmethod
    def _history_timestamp(cls, value):
        parsed = cls._history_datetime(value)
        return parsed.isoformat() if parsed is not None else None

    def list_task_history(self, *, limit=100, offset=0, sensor_id=None, site_id=None,
                          scope_id=None, device_id=None, task_type=None, status=None,
                          created_after=None, created_before=None):
        """Return a bounded operator-safe task projection without mutating tasks."""
        if type(limit) is not int or not 1 <= limit <= 100 or type(offset) is not int or not 0 <= offset <= 100000:
            raise RemoteTaskError('INVALID_HISTORY_PAGINATION', 'Invalid task history pagination.', 422)
        for value, label in ((sensor_id, 'sensor_id'), (site_id, 'site_id'),
                             (scope_id, 'scope_id'), (device_id, 'device_id')):
            if value is not None and (type(value) is not int or value <= 0):
                raise RemoteTaskError('INVALID_HISTORY_FILTER', f'{label} must be a positive integer.', 422)
        if task_type is not None and task_type not in TASK_TYPES:
            raise RemoteTaskError('INVALID_HISTORY_FILTER', 'Unsupported task type filter.', 422)
        if status is not None and status not in TASK_STATES:
            raise RemoteTaskError('INVALID_HISTORY_FILTER', 'Unsupported task status filter.', 422)

        after = self._history_datetime(created_after)
        before = self._history_datetime(created_before)
        if ((created_after is not None and after is None)
                or (created_before is not None and before is None)):
            raise RemoteTaskError('INVALID_HISTORY_FILTER', 'Creation time filters must be valid timezone-aware timestamps.', 422)
        if (after is None) != (before is None):
            raise RemoteTaskError('INVALID_HISTORY_FILTER', 'Provide both creation time bounds.', 422)
        if after is not None and (after >= before or before - after > TASK_HISTORY_MAX_RANGE):
            raise RemoteTaskError('INVALID_HISTORY_FILTER', 'Creation time range must be ordered and no longer than 90 days.', 422)

        evaluated_at = self.sensors._now()
        clauses = []
        parameters = []
        for column, value in (
            ('t.sensor_id', sensor_id), ('t.site_id', site_id), ('t.scope_id', scope_id),
            ('t.target_device_id', device_id), ('t.task_type', task_type), ('t.status', status),
        ):
            if value is not None:
                clauses.append(f'{column}=?')
                parameters.append(value)
        if after is not None:
            clauses.extend(('t.created_at>=?', 't.created_at<=?'))
            parameters.extend((after.isoformat(), before.isoformat()))
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ''
        with self.sensors._connection() as connection:
            rows = connection.execute(f'''SELECT
                    t.id, t.sensor_id, rs.name AS sensor_name,
                    t.site_id, s.name AS site_name,
                    t.scope_id, sc.name AS scope_name, sc.canonical_target,
                    t.target_device_id, t.target_ip, t.task_type, t.status,
                    t.created_at, t.expires_at, t.claimed_at, t.started_at,
                    t.completed_at, t.failed_at, t.attempt_count, t.error_code
                FROM remote_sensor_tasks t
                LEFT JOIN remote_sensors rs ON rs.id=t.sensor_id AND rs.site_id=t.site_id
                LEFT JOIN sites s ON s.id=t.site_id
                LEFT JOIN authorized_scopes sc ON sc.id=t.scope_id
                {where}
                ORDER BY t.created_at DESC, t.id DESC
                LIMIT ? OFFSET ?''', (*parameters, limit + 1, offset)).fetchall()

        items = []
        for row in rows[:limit]:
            persisted_status = row['status'] if row['status'] in TASK_STATES else 'UNKNOWN'
            task_type_value = row['task_type'] if row['task_type'] in TASK_TYPES else 'UNKNOWN'
            expires_at = self._history_datetime(row['expires_at'])
            failure_code = None
            failure_message_safe = None
            if persisted_status in {'FAILED', 'CANCELLED'}:
                failure_code = row['error_code'] if row['error_code'] in TASK_FAILURE_CODES else 'UNKNOWN_FAILURE'
                failure_message_safe = TASK_FAILURE_MESSAGES.get(failure_code, 'Unknown task failure.')
            items.append({
                'id': row['id'], 'sensor_id': row['sensor_id'], 'sensor_name': row['sensor_name'],
                'site_id': row['site_id'], 'site_name': row['site_name'],
                'scope_id': row['scope_id'], 'scope_name': row['scope_name'],
                'canonical_target': row['canonical_target'],
                'target_device_id': row['target_device_id'], 'target_ip': row['target_ip'],
                'task_type': task_type_value, 'status': persisted_status,
                'created_at': self._history_timestamp(row['created_at']),
                'expires_at': self._history_timestamp(row['expires_at']),
                'claimed_at': self._history_timestamp(row['claimed_at']),
                'started_at': self._history_timestamp(row['started_at']),
                'completed_at': self._history_timestamp(row['completed_at']),
                'failed_at': self._history_timestamp(row['failed_at']),
                'attempt_count': row['attempt_count'], 'failure_code': failure_code,
                'failure_message_safe': failure_message_safe,
                'expired': bool(expires_at is not None and expires_at < evaluated_at
                                and persisted_status not in TERMINAL_TASK_STATES),
            })
        return {
            'evaluated_at': evaluated_at.isoformat(), 'items': items,
            'limit': limit, 'offset': offset, 'has_more': len(rows) > limit,
        }

    def _context(self, connection, sensor_id, scope_id):
        try:
            sensor = self.sensors._sensor(connection, sensor_id, active=True)
        except RemoteSensorError as exc:
            raise RemoteTaskError('SENSOR_DISABLED', 'Sensor is unavailable.', 403) from exc
        try:
            scope = self.sensors._scope(connection, scope_id)
        except RemoteSensorError as exc:
            code = 'SCOPE_DISABLED' if 'disabled' in str(exc).lower() else 'SCOPE_NOT_ASSIGNED'
            raise RemoteTaskError(code, 'Assigned private network scope is unavailable.', 403) from exc
        assignment = connection.execute(
            'SELECT * FROM sensor_scope_assignments WHERE sensor_id=? AND scope_id=? AND site_id=?',
            (sensor_id, scope_id, sensor['site_id']),
        ).fetchone()
        if assignment is None or assignment['canonical_target'] != scope['canonical_target']:
            raise RemoteTaskError('SCOPE_NOT_ASSIGNED', 'No current assignment authorizes this task.', 403)
        return sensor, scope, assignment

    def list_eligible_task_scopes(self, sensor_id, *, limit=100, offset=0):
        if type(limit) is not int or not 1 <= limit <= 100 or type(offset) is not int or not 0 <= offset <= 100000:
            raise RemoteTaskError('INVALID_TASK_SELECTOR_PAGINATION', 'Invalid task selector pagination.', 422)
        with self.sensors._connection() as c:
            sensor = self.sensors._sensor(c, sensor_id, active=True)
            declared = set(sensor['capabilities'])
            supported = []
            if Capability.HOST_DISCOVERY.value in declared:
                supported.append('DISCOVER_NETWORK')
            if Capability.SERVICE_DISCOVERY.value in declared:
                supported.append('DISCOVER_SERVICES')
            if not supported:
                return {'items': [], 'limit': limit, 'offset': offset, 'has_more': False}

            def eligible_scope(scope_type, target, authorized, enabled, confirmed_at,
                               confirmation_version, authorization_source, scope_network_id,
                               network_id, network_cidr, network_authorized, network_enabled):
                scope = {
                    'scope_type': scope_type, 'canonical_target': target,
                    'authorized': bool(authorized), 'enabled': bool(enabled),
                    'authorization_confirmed_at': confirmed_at,
                    'authorization_confirmation_version': confirmation_version,
                    'authorization_source': authorization_source,
                    'network_id': scope_network_id,
                }
                network = {
                    'id': network_id, 'cidr': network_cidr,
                    'authorized': bool(network_authorized), 'enabled': bool(network_enabled),
                }
                try:
                    require_private_network_scope(network, scope)
                    private_lan(target)
                    return 1
                except (ValueError, TypeError):
                    return 0

            c.create_function('remote_task_scope_eligible', 12, eligible_scope, deterministic=False)
            rows = c.execute('''SELECT s.id, s.name, s.canonical_target
                FROM sensor_scope_assignments a
                JOIN remote_sensors rs ON rs.id=a.sensor_id AND rs.site_id=a.site_id
                JOIN sites st ON st.id=rs.site_id
                JOIN authorized_scopes s ON s.id=a.scope_id
                JOIN network_scope_links l ON l.scope_id=s.id
                JOIN networks n ON n.id=l.network_id
                WHERE a.sensor_id=? AND a.site_id=? AND rs.enabled=1
                  AND rs.credential_revoked_at IS NULL AND st.enabled=1
                  AND s.scope_type='PRIVATE_NETWORK'
                  AND remote_task_scope_eligible(s.scope_type,s.canonical_target,s.authorized,s.enabled,
                    s.authorization_confirmed_at,s.authorization_confirmation_version,s.authorization_source,
                    l.network_id,n.id,n.cidr,n.authorized,n.enabled)=1
                  AND a.canonical_target=s.canonical_target
                ORDER BY s.id ASC LIMIT ? OFFSET ?''',
                (sensor_id, sensor['site_id'], limit + 1, offset)).fetchall()
        items = [{
            'scope_id': row['id'], 'scope_name': row['name'],
            'canonical_target': row['canonical_target'],
            'supported_task_types': supported,
        } for row in rows[:limit]]
        return {'items': items, 'limit': limit, 'offset': offset, 'has_more': len(rows) > limit}

    def list_eligible_task_devices(self, sensor_id, scope_id, *, limit=100, offset=0):
        if type(limit) is not int or not 1 <= limit <= 100 or type(offset) is not int or not 0 <= offset <= 100000:
            raise RemoteTaskError('INVALID_TASK_SELECTOR_PAGINATION', 'Invalid task selector pagination.', 422)
        with self.sensors._connection() as c:
            sensor, scope, _ = self._context(c, sensor_id, scope_id)
            if Capability.SERVICE_DISCOVERY.value not in sensor['capabilities']:
                raise RemoteTaskError('CAPABILITY_NOT_ALLOWED', 'Sensor has not declared the required capability.', 403)
            network_id = scope['network_id']
            cidr = private_lan(scope['canonical_target'])

            def device_eligible(address):
                try:
                    parsed = ipaddress.IPv4Address(address)
                    return int(str(parsed) == address and parsed in cidr)
                except (ValueError, TypeError):
                    return 0

            c.create_function('remote_task_device_eligible', 1, device_eligible, deterministic=False)
            rows = c.execute('''SELECT d.id, d.last_ip_address
                FROM devices d
                WHERE d.network_id=? AND remote_task_device_eligible(d.last_ip_address)=1
                ORDER BY d.id ASC LIMIT ? OFFSET ?''',
                (network_id, limit + 1, offset)).fetchall()
        return {
            'items': [{'device_id': row['id'], 'scope_id': scope_id,
                       'ip_address': row['last_ip_address']} for row in rows[:limit]],
            'limit': limit, 'offset': offset, 'has_more': len(rows) > limit,
        }

    def create_task(self, sensor_id, scope_id, task_type, *, device_id=None, ttl_seconds=TASK_TTL_SECONDS):
        if task_type not in TASK_TYPES:
            raise RemoteTaskError('INVALID_TASK_TYPE', 'Unsupported task type.')
        if type(ttl_seconds) is not int or not 60 <= ttl_seconds <= TASK_TTL_SECONDS:
            raise RemoteTaskError('INVALID_EXPIRY', 'Task lifetime must be 60–900 seconds.')
        if task_type == 'DISCOVER_NETWORK' and device_id is not None:
            raise RemoteTaskError('INVALID_TASK', 'Network discovery cannot target a device.')
        if task_type == 'DISCOVER_SERVICES' and (type(device_id) is not int or device_id <= 0):
            raise RemoteTaskError('INVALID_TASK', 'Service discovery requires a persisted device.')
        required = Capability.HOST_DISCOVERY.value if task_type == 'DISCOVER_NETWORK' else Capability.SERVICE_DISCOVERY.value
        now = self.sensors._now()
        with self.sensors._connection(write=True) as c:
            sensor, scope, assignment = self._context(c, sensor_id, scope_id)
            if required not in sensor['capabilities']:
                raise RemoteTaskError('CAPABILITY_NOT_ALLOWED', 'Sensor has not declared the required capability.', 403)
            network = c.execute('SELECT * FROM networks WHERE id=?', (scope['network_id'],)).fetchone()
            if network is None or not network['authorized'] or not network['enabled']:
                raise RemoteTaskError('SCOPE_DISABLED', 'Assigned network is unavailable.', 403)
            cidr = private_lan(assignment['canonical_target'])
            target_ip = None
            if task_type == 'DISCOVER_SERVICES':
                device = c.execute('SELECT * FROM devices WHERE id=?', (device_id,)).fetchone()
                if device is None or device['network_id'] != network['id']:
                    raise RemoteTaskError('TARGET_OUTSIDE_SCOPE', 'Device is not in the assigned network.', 403)
                try:
                    address = ipaddress.IPv4Address(device['last_ip_address'])
                except (ValueError, TypeError) as exc:
                    raise RemoteTaskError('TARGET_OUTSIDE_SCOPE', 'Device address is invalid.', 403) from exc
                if str(address) != device['last_ip_address'] or address not in cidr:
                    raise RemoteTaskError('TARGET_OUTSIDE_SCOPE', 'Device is outside the assigned network.', 403)
                target_ip = str(address)
            active_count = c.execute('''SELECT COUNT(*) FROM remote_sensor_tasks
                WHERE sensor_id=? AND status IN ('PENDING','CLAIMED','RUNNING') AND expires_at>?''',
                (sensor_id, now.isoformat())).fetchone()[0]
            if active_count >= MAX_ACTIVE_TASKS_PER_SENSOR:
                raise RemoteTaskError('TASK_QUEUE_FULL', 'Sensor task queue is at capacity.', 409)
            task_id = str(uuid.uuid4())
            c.execute('''INSERT INTO remote_sensor_tasks
                (id,sensor_id,site_id,scope_id,task_type,status,target_device_id,target_ip,created_at,expires_at,created_by_source)
                VALUES (?,?,?,?,?,'PENDING',?,?,?,?,?)''',
                (task_id, sensor_id, sensor['site_id'], scope_id, task_type, device_id, target_ip,
                 now.isoformat(), (now + timedelta(seconds=ttl_seconds)).isoformat(), 'local_management'))
            record_event(c, event_type='SENSOR_TASK_CREATED', entity_type='SENSOR_TASK',
                         entity_id=task_id, sensor_id=sensor_id, site_id=sensor['site_id'],
                         scope_id=scope_id, actor_type='LOCAL_OPERATOR', new_state='CREATED',
                         task_type=task_type, target_device_id=device_id)
            return self._task(c.execute('SELECT * FROM remote_sensor_tasks WHERE id=?', (task_id,)).fetchone())

    def _revalidate(self, connection, task):
        sensor, scope, assignment = self._context(connection, task['sensor_id'], task['scope_id'])
        required = Capability.HOST_DISCOVERY.value if task['task_type'] == 'DISCOVER_NETWORK' else Capability.SERVICE_DISCOVERY.value
        if required not in sensor['capabilities']:
            raise RemoteTaskError('CAPABILITY_NOT_ALLOWED', 'Required sensor capability is unavailable.', 403)
        if task['task_type'] == 'DISCOVER_SERVICES':
            device = connection.execute('SELECT * FROM devices WHERE id=?', (task['target_device_id'],)).fetchone()
            try:
                current_ip = str(ipaddress.IPv4Address(device['last_ip_address'])) if device else None
                assigned_network = private_lan(assignment['canonical_target'])
            except (ValueError, TypeError) as exc:
                raise RemoteTaskError('TARGET_OUTSIDE_SCOPE', 'Task device is no longer eligible.', 403) from exc
            if (device is None or device['network_id'] != scope['network_id']
                    or current_ip != task['target_ip'] or ipaddress.IPv4Address(current_ip) not in assigned_network):
                raise RemoteTaskError('TARGET_OUTSIDE_SCOPE', 'Task device changed or left the assigned network.', 403)
        return sensor, scope, assignment

    def claim_next(self, sensor_id):
        now = self.sensors._now()
        with self.sensors._connection(write=True) as c:
            c.execute("""UPDATE remote_sensor_tasks SET status='FAILED',failed_at=?,error_code='TASK_EXPIRED',
                       error_message='Task expired.' WHERE sensor_id=? AND status IN ('PENDING','CLAIMED','RUNNING') AND expires_at<=?""",
                      (now.isoformat(), sensor_id, now.isoformat()))
            task = c.execute("""SELECT * FROM remote_sensor_tasks WHERE sensor_id=? AND status='PENDING'
                              AND expires_at>? ORDER BY created_at,id LIMIT 1""",
                             (sensor_id, now.isoformat())).fetchone()
            if task is None:
                return None
            task = dict(task)
            try:
                sensor, scope, assignment = self._revalidate(c, task)
            except RemoteTaskError as exc:
                c.execute("UPDATE remote_sensor_tasks SET status='FAILED',failed_at=?,error_code=?,error_message=? WHERE id=?",
                          (now.isoformat(), exc.code, str(exc), task['id']))
                return None
            cursor = c.execute("""UPDATE remote_sensor_tasks SET status='CLAIMED',claimed_at=?,attempt_count=attempt_count+1
                                  WHERE id=? AND status='PENDING' AND expires_at>?""",
                                (now.isoformat(), task['id'], now.isoformat()))
            if cursor.rowcount != 1:
                return None
            claimed = dict(c.execute('SELECT * FROM remote_sensor_tasks WHERE id=?', (task['id'],)).fetchone())
            claimed['scope_cidr'] = assignment['canonical_target']
            claimed['scope_type'] = scope['scope_type']
            claimed['sensor_uuid'] = sensor['sensor_uuid']
            claimed['network_id'] = scope['network_id']
            return claimed

    def transition(self, sensor_id, task_id, action):
        now = self.sensors._now()
        delayed_error = None
        result = None
        with self.sensors._connection(write=True) as c:
            task = c.execute('SELECT * FROM remote_sensor_tasks WHERE id=? AND sensor_id=?',
                             (task_id, sensor_id)).fetchone()
            if task is None:
                raise RemoteTaskError('TASK_NOT_FOUND', 'Task not found.', 404)
            task = dict(task)
            if now.isoformat() >= task['expires_at']:
                c.execute("UPDATE remote_sensor_tasks SET status='FAILED',failed_at=?,error_code='TASK_EXPIRED',error_message='Task expired.' WHERE id=?",
                          (now.isoformat(), task_id))
                delayed_error = RemoteTaskError('TASK_EXPIRED', 'Task expired.', 409)
            if delayed_error is None:
                try:
                    self._revalidate(c, task)
                except RemoteTaskError as exc:
                    c.execute("UPDATE remote_sensor_tasks SET status='FAILED',failed_at=?,error_code=?,error_message=? WHERE id=?",
                              (now.isoformat(), exc.code, str(exc), task_id))
                    delayed_error = exc
            if delayed_error is None and action == 'start' and task['status'] == 'CLAIMED':
                c.execute("UPDATE remote_sensor_tasks SET status='RUNNING',started_at=? WHERE id=? AND status='CLAIMED'",
                          (now.isoformat(), task_id))
            elif delayed_error is None and action == 'cancel' and task['status'] in {'PENDING', 'CLAIMED'}:
                c.execute("UPDATE remote_sensor_tasks SET status='CANCELLED',failed_at=?,error_code='CANCELLED',error_message='Cancelled by sensor.' WHERE id=?",
                          (now.isoformat(), task_id))
            elif delayed_error is None:
                raise RemoteTaskError('INVALID_TRANSITION', 'Task state transition is not allowed.', 409)
            if delayed_error is None:
                result = self._task(c.execute('SELECT * FROM remote_sensor_tasks WHERE id=?', (task_id,)).fetchone())
        if delayed_error is not None:
            raise delayed_error
        return result

    def begin_result(self, sensor_id, task_id, task_type, result_digest):
        now = self.sensors._now()
        expired = False
        with self.sensors._connection(write=True) as c:
            task = c.execute('SELECT * FROM remote_sensor_tasks WHERE id=? AND sensor_id=?',
                             (task_id, sensor_id)).fetchone()
            if task is None:
                raise RemoteTaskError('TASK_NOT_FOUND', 'Task not found.', 404)
            task = dict(task)
            if task['status'] != 'RUNNING' or task['result_digest'] is not None:
                raise RemoteTaskError('INVALID_TRANSITION', 'Task result is duplicate or task is not running.', 409)
            if task['task_type'] != task_type:
                raise RemoteTaskError('INVALID_RESULT', 'Result type does not match task.', 400)
            if now.isoformat() >= task['expires_at']:
                c.execute("UPDATE remote_sensor_tasks SET status='FAILED',failed_at=?,error_code='TASK_EXPIRED',error_message='Task expired.' WHERE id=?",
                          (now.isoformat(), task_id))
                expired = True
            if not expired:
                sensor, scope, assignment = self._revalidate(c, task)
                network = c.execute('SELECT * FROM networks WHERE id=?', (scope['network_id'],)).fetchone()
                network = dict(network)
                network['authorized'], network['enabled'] = bool(network['authorized']), bool(network['enabled'])
                task['network'] = network
                task['scope_cidr'] = assignment['canonical_target']
                task['sensor_uuid'] = sensor['sensor_uuid']
                if task['target_device_id'] is not None:
                    task['device'] = dict(c.execute('SELECT * FROM devices WHERE id=?',
                                                    (task['target_device_id'],)).fetchone())
                c.execute('UPDATE remote_sensor_tasks SET result_digest=? WHERE id=? AND status=\'RUNNING\' AND result_digest IS NULL',
                          (result_digest, task_id))
        if expired:
            raise RemoteTaskError('TASK_EXPIRED', 'Task expired.', 409)
        return task

    def finish_result(self, task_id, digest, *, error_code=None):
        now = self.sensors._now()
        with self.sensors._connection(write=True) as c:
            row = c.execute('SELECT * FROM remote_sensor_tasks WHERE id=?', (task_id,)).fetchone()
            if row is None or row['status'] != 'RUNNING' or row['result_digest'] != digest:
                raise RemoteTaskError('INVALID_TRANSITION', 'Task result reservation was lost.', 409)
            if error_code is None:
                c.execute("UPDATE remote_sensor_tasks SET status='COMPLETED',completed_at=?,error_code=NULL,error_message=NULL WHERE id=?",
                          (now.isoformat(), task_id))
            else:
                c.execute("UPDATE remote_sensor_tasks SET status='FAILED',failed_at=?,error_code=?,error_message='Result could not be safely ingested.' WHERE id=?",
                          (now.isoformat(), error_code, task_id))

    def fail(self, sensor_id, task_id, code):
        allowed = {'SCANNER_TIMEOUT', 'SCANNER_FAILED', 'INVALID_RESULT', 'RESULT_OUTSIDE_SCOPE'}
        if code not in allowed:
            raise RemoteTaskError('INVALID_FAILURE', 'Unsupported task failure code.')
        now = self.sensors._now()
        with self.sensors._connection(write=True) as c:
            row = c.execute('SELECT * FROM remote_sensor_tasks WHERE id=? AND sensor_id=?',
                             (task_id, sensor_id)).fetchone()
            if row is None:
                raise RemoteTaskError('TASK_NOT_FOUND', 'Task not found.', 404)
            if row['status'] not in {'CLAIMED', 'RUNNING'} or row['result_digest'] is not None:
                raise RemoteTaskError('INVALID_TRANSITION', 'Task cannot be failed in its current state.', 409)
            if now.isoformat() >= row['expires_at']:
                c.execute("UPDATE remote_sensor_tasks SET status='FAILED',failed_at=?,error_code='TASK_EXPIRED',error_message='Task expired.' WHERE id=?",
                          (now.isoformat(), task_id))
                expired = True
            else:
                expired = False
            if expired:
                row = None
            else:
                c.execute("UPDATE remote_sensor_tasks SET status='FAILED',failed_at=?,error_code=?,error_message='Sensor reported task failure.' WHERE id=?",
                          (now.isoformat(), code, task_id))
                row = c.execute('SELECT * FROM remote_sensor_tasks WHERE id=?', (task_id,)).fetchone()
        if expired:
            raise RemoteTaskError('TASK_EXPIRED', 'Task expired.', 409)
        return self._task(row)
