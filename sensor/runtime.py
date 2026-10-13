"""Single-threaded sensor heartbeat, polling, validation, and typed execution loop."""
from datetime import datetime, timezone
import json
import logging
import time
from threading import Event
from uuid import UUID

from services.remote_sensor_executor import RemoteSensorExecutor, task_context_from_claim
from services.remote_sensor_models import LocalExecutorGrant, RemoteSensorError, validate_remote_task
from services.scanner_adapters.nmap_adapter import ScannerTimeoutError

from .client import CoreClient, SensorClientError
from .config import SensorConfig

BACKOFF_SECONDS = (5, 10, 30, 60)


def _json_log(logger: logging.Logger, *, sensor_uuid: str, status: str,
              task_id: str | None = None, task_type: str | None = None,
              error_code: str | None = None):
    record = {
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'sensor_uuid': sensor_uuid,
        'status': status,
    }
    if task_id is not None:
        record['task_id'] = task_id
    if task_type is not None:
        record['task_type'] = task_type
    if error_code is not None:
        record['error_code'] = error_code
    logger.info(json.dumps(record, sort_keys=True, separators=(',', ':')))


def _result_payload(task, result):
    if task.task_type == 'DISCOVER_NETWORK':
        if len(result.hosts) > 254:
            raise RemoteSensorError('Host result exceeds the supported bound.')
        observations = [{key: getattr(host, key) for key in ('ip_address', 'mac_address', 'hostname', 'vendor')}
                        for host in result.hosts]
        return {'task_type': task.task_type, 'observations': observations}
    if task.task_type == 'DISCOVER_SERVICES':
        if len(result.ports) > 21 or len(result.services) > 21:
            raise RemoteSensorError('Service result exceeds the supported bound.')
        ports = [{'port': item.port} for item in result.ports]
        services = [{key: getattr(item, key) for key in
                     ('port', 'service_name', 'product', 'version', 'extra_info')}
                    for item in result.services]
        return {'task_type': task.task_type, 'ports': ports, 'services': services}
    raise RemoteSensorError('Unsupported task type.')


class SensorRuntime:
    def __init__(self, config: SensorConfig, grants: dict[int, LocalExecutorGrant],
                 client: CoreClient, executor: RemoteSensorExecutor, *,
                 stop_event: Event | None = None, sleep=None, monotonic=None,
                 logger: logging.Logger | None = None):
        self.config = config
        self.grants = grants
        self.client = client
        self.executor = executor
        self.stop_event = stop_event or Event()
        self._sleep = sleep or self.stop_event.wait
        self._monotonic = monotonic or time.monotonic
        self.logger = logger or logging.getLogger('sentinelip.sensor')
        self._heartbeat_due = 0.0
        self._backoff_index = 0

    def _heartbeat_if_due(self):
        now = self._monotonic()
        if now >= self._heartbeat_due:
            self.client.heartbeat()
            self._backoff_index = 0
            self._heartbeat_due = self._monotonic() + self.config.heartbeat_interval
            _json_log(self.logger, sensor_uuid=self.config.sensor_uuid, status='HEARTBEAT_OK')

    def _handle_claim(self, raw_task):
        task_id = raw_task.get('id') if isinstance(raw_task, dict) else None
        try:
            safe_task_id = str(UUID(str(task_id)))
        except (ValueError, TypeError, AttributeError):
            safe_task_id = None
        task_type = raw_task.get('task_type') if isinstance(raw_task, dict) else None
        if task_type not in {'DISCOVER_NETWORK', 'DISCOVER_SERVICES'}:
            task_type = None
        try:
            task = task_context_from_claim(raw_task)
            canonical_task_id = str(UUID(task.task_id))
            if canonical_task_id != task.task_id:
                raise RemoteSensorError('Task UUID is not canonical.')
            if task.sensor_uuid != self.config.sensor_uuid:
                raise RemoteSensorError('Task identity does not match this sensor.')
            grant = self.grants.get(task.scope_id)
            if grant is None:
                raise RemoteSensorError('Task scope has no local grant.')
            required = ('HOST_DISCOVERY' if task.task_type == 'DISCOVER_NETWORK'
                        else 'SERVICE_DISCOVERY')
            if required not in self.config.capabilities:
                raise RemoteSensorError('Task capability is not enabled in this runtime.')
            validate_remote_task(task, grant)
        except (RemoteSensorError, ValueError, TypeError, KeyError):
            try:
                if safe_task_id is not None:
                    self.client.fail(safe_task_id, 'INVALID_RESULT')
                    self._backoff_index = 0
            except (ValueError, SensorClientError):
                pass
            _json_log(self.logger, sensor_uuid=self.config.sensor_uuid,
                      task_id=safe_task_id, task_type=task_type,
                      status='TASK_REJECTED', error_code='INVALID_RESULT')
            return
        if self.stop_event.is_set():
            _json_log(self.logger, sensor_uuid=self.config.sensor_uuid,
                      task_id=task.task_id, task_type=task.task_type, status='STOPPED_BEFORE_START')
            return
        try:
            self.client.start(task.task_id)
            self._backoff_index = 0
            if task.task_type == 'DISCOVER_NETWORK':
                result = self.executor.discover_network(task, grant)
            elif task.task_type == 'DISCOVER_SERVICES':
                result = self.executor.discover_services(task, grant)
            else:
                # validate_remote_task rejects this before start; keep dispatch closed as well.
                raise RemoteSensorError('Unsupported task type.')
            self.client.result(task.task_id, _result_payload(task, result))
            self._backoff_index = 0
            _json_log(self.logger, sensor_uuid=self.config.sensor_uuid, task_id=task.task_id,
                      task_type=task.task_type, status='TASK_COMPLETED')
        except ScannerTimeoutError:
            self.client.fail(task.task_id, 'SCANNER_TIMEOUT')
            self._backoff_index = 0
            _json_log(self.logger, sensor_uuid=self.config.sensor_uuid, task_id=task.task_id,
                      task_type=task.task_type, status='TASK_FAILED', error_code='SCANNER_TIMEOUT')
        except (RemoteSensorError, ValueError, TypeError):
            self.client.fail(task.task_id, 'INVALID_RESULT')
            self._backoff_index = 0
            _json_log(self.logger, sensor_uuid=self.config.sensor_uuid, task_id=task.task_id,
                      task_type=task.task_type, status='TASK_FAILED', error_code='INVALID_RESULT')
        except Exception:
            # Never log exception text: scanner and HTTP internals may include sensitive data.
            try:
                self.client.fail(task.task_id, 'SCANNER_FAILED')
                self._backoff_index = 0
            except SensorClientError:
                raise
            _json_log(self.logger, sensor_uuid=self.config.sensor_uuid, task_id=task.task_id,
                      task_type=task.task_type, status='TASK_FAILED', error_code='SCANNER_FAILED')

    def run_once(self) -> int:
        self._heartbeat_if_due()
        if self.stop_event.is_set():
            return 0
        task = self.client.claim()
        self._backoff_index = 0
        if task is None:
            _json_log(self.logger, sensor_uuid=self.config.sensor_uuid, status='POLL_IDLE')
            return self.config.poll_interval
        self._handle_claim(task)
        return self.config.poll_interval

    def run(self):
        while not self.stop_event.is_set():
            try:
                delay = self.run_once()
                self._backoff_index = 0
            except SensorClientError as exc:
                _json_log(self.logger, sensor_uuid=self.config.sensor_uuid,
                          status='CORE_UNAVAILABLE', error_code=exc.code)
                delay = BACKOFF_SECONDS[min(self._backoff_index, len(BACKOFF_SECONDS) - 1)]
                self._backoff_index = min(self._backoff_index + 1, len(BACKOFF_SECONDS) - 1)
            except Exception:
                _json_log(self.logger, sensor_uuid=self.config.sensor_uuid,
                          status='RUNTIME_ERROR', error_code='SCANNER_FAILED')
                delay = BACKOFF_SECONDS[min(self._backoff_index, len(BACKOFF_SECONDS) - 1)]
                self._backoff_index = min(self._backoff_index + 1, len(BACKOFF_SECONDS) - 1)
            if delay and not self.stop_event.is_set():
                self._sleep(delay)
