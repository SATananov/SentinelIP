"""Typed, assignment-bound remote sensor task persistence."""
from datetime import timedelta
import ipaddress
import uuid

from database.db import get_connection
from database.remote_sensors import RemoteSensorStore
from services.remote_sensor_models import Capability, RemoteSensorError, private_lan

TASK_TYPES = frozenset({'DISCOVER_NETWORK', 'DISCOVER_SERVICES'})
TASK_TTL_SECONDS = 900


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
            task_id = str(uuid.uuid4())
            c.execute('''INSERT INTO remote_sensor_tasks
                (id,sensor_id,site_id,scope_id,task_type,status,target_device_id,target_ip,created_at,expires_at,created_by_source)
                VALUES (?,?,?,?,?,'PENDING',?,?,?,?,?)''',
                (task_id, sensor_id, sensor['site_id'], scope_id, task_type, device_id, target_ip,
                 now.isoformat(), (now + timedelta(seconds=ttl_seconds)).isoformat(), 'local_management'))
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
