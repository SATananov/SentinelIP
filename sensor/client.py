"""Small HTTPS client exposing only the sensor machine endpoints."""
from contextlib import closing
import json
import ssl
from typing import Mapping
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin
from urllib.request import HTTPSHandler, HTTPHandler, HTTPRedirectHandler, Request, build_opener
from uuid import UUID

from services.sensor_transport import authenticated_sensor_headers
from .config import SensorConfig, _validate_core_url


class SensorClientError(RuntimeError):
    def __init__(self, code: str, *, status: int | None = None):
        super().__init__(code)
        self.code = code
        self.status = status


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        return None


class CoreClient:
    """Machine API client; methods map to a fixed endpoint allowlist."""
    def __init__(self, config: SensorConfig, *, opener=None, clock=None, nonce_factory=None):
        self.config = config
        self._clock = clock
        self._nonce_factory = nonce_factory
        self._opener = opener or build_opener(
            HTTPSHandler(context=ssl.create_default_context()), HTTPHandler(), _NoRedirect())

    def close(self):
        close = getattr(self._opener, 'close', None)
        if close is not None:
            close()

    def _call(self, method: str, path: str, body: Mapping | None = None):
        url = urljoin(self.config.core_url.rstrip('/') + '/', path.lstrip('/'))
        headers = authenticated_sensor_headers(
            self.config.sensor_uuid, self.config.sensor_credential, now=self._clock,
            nonce=self._nonce_factory() if self._nonce_factory else None)
        payload = None if body is None else json.dumps(body, separators=(',', ':')).encode('utf-8')
        if payload is not None and len(payload) > 16 * 1024:
            raise ValueError('Sensor request exceeds the supported payload bound.')
        headers['Accept'] = 'application/json'
        if payload is not None:
            headers['Content-Type'] = 'application/json'
        request = Request(url, data=payload, headers=headers, method=method)
        try:
            response = self._opener.open(request, timeout=self.config.request_timeout)
            with closing(response):
                status = getattr(response, 'status', response.getcode())
                response_data = response.read(16 * 1024 + 1)
        except HTTPError as exc:
            status = exc.code
            # Do not parse or log a Core error body; it may echo untrusted input.
            exc.close()
            raise SensorClientError('CORE_AUTH_FAILED' if status == 401 else 'CORE_HTTP_ERROR',
                                    status=status) from None
        except (TimeoutError, URLError, OSError) as exc:
            reason = getattr(exc, 'reason', None)
            code = 'CORE_TIMEOUT' if isinstance(exc, TimeoutError) or isinstance(reason, TimeoutError) else 'CORE_UNAVAILABLE'
            raise SensorClientError(code) from None
        if not 200 <= status < 300 or len(response_data) > 16 * 1024:
            raise SensorClientError('CORE_HTTP_ERROR' if status >= 300 else 'INVALID_RESPONSE', status=status)
        if not response_data:
            raise SensorClientError('INVALID_RESPONSE', status=status)
        try:
            result = json.loads(response_data)
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise SensorClientError('INVALID_RESPONSE', status=status) from None
        if not isinstance(result, dict):
            raise SensorClientError('INVALID_RESPONSE', status=status)
        return result

    @staticmethod
    def _task_path(task_id: str, action: str) -> str:
        try:
            canonical_id = str(UUID(task_id))
        except (ValueError, TypeError, AttributeError):
            raise ValueError('A valid task UUID is required.') from None
        if action not in {'start', 'fail', 'result'}:
            raise ValueError('Unsupported task action.')
        return f'/sensor/tasks/{canonical_id}/{action}'

    def get_self(self) -> dict:
        return self._call('GET', '/sensor/self')

    def get_grant(self) -> dict:
        return self._call('GET', '/sensor/grant')

    def heartbeat(self) -> dict:
        return self._call('POST', '/sensor/heartbeat', {
            'platform': self.config.platform_name,
            'version': self.config.version,
            'capabilities': list(self.config.capabilities),
        })

    def claim(self) -> dict | None:
        response = self._call('POST', '/sensor/tasks/claim', {})
        task = response.get('task')
        if task is not None and not isinstance(task, dict):
            raise SensorClientError('INVALID_RESPONSE')
        return task

    def start(self, task_id: str) -> dict:
        return self._call('POST', self._task_path(task_id, 'start'), {})

    def result(self, task_id: str, payload: Mapping) -> dict:
        if not isinstance(payload, Mapping):
            raise ValueError('A structured result object is required.')
        task_type = payload.get('task_type')
        if task_type == 'DISCOVER_NETWORK':
            if set(payload) != {'task_type', 'observations'}:
                raise ValueError('Network results contain unsupported fields.')
            observations = payload['observations']
            fields = {'ip_address', 'mac_address', 'hostname', 'vendor'}
            if (not isinstance(observations, list) or len(observations) > 254
                    or any(not isinstance(item, dict) or set(item) != fields
                           or not isinstance(item['ip_address'], str) or len(item['ip_address']) > 15
                           or any(item[key] is not None and (not isinstance(item[key], str)
                                  or len(item[key]) > maximum)
                                  for key, maximum in (('mac_address', 17), ('hostname', 253), ('vendor', 128)))
                           for item in observations)):
                raise ValueError('Network result exceeds its structured bounds.')
        elif task_type == 'DISCOVER_SERVICES':
            if set(payload) != {'task_type', 'ports', 'services'}:
                raise ValueError('Service results contain unsupported fields.')
            ports, services = payload['ports'], payload['services']
            if (not isinstance(ports, list) or len(ports) > 21
                    or any(not isinstance(item, dict) or set(item) != {'port'}
                           or type(item['port']) is not int or not 1 <= item['port'] <= 65535
                           for item in ports)
                    or not isinstance(services, list) or len(services) > 21
                    or any(not isinstance(item, dict)
                           or set(item) != {'port', 'service_name', 'product', 'version', 'extra_info'}
                           or type(item['port']) is not int or not 1 <= item['port'] <= 65535
                           or any(item[key] is not None and (not isinstance(item[key], str)
                                  or len(item[key]) > 128)
                                  for key in ('service_name', 'product', 'version', 'extra_info'))
                           for item in services)):
                raise ValueError('Service result exceeds its structured bounds.')
        else:
            raise ValueError('Unsupported result type.')
        return self._call('POST', self._task_path(task_id, 'result'), payload)

    def fail(self, task_id: str, error_code: str) -> dict:
        if error_code not in {'SCANNER_TIMEOUT', 'SCANNER_FAILED', 'INVALID_RESULT'}:
            raise ValueError('Unsupported task failure code.')
        return self._call('POST', self._task_path(task_id, 'fail'), {'error_code': error_code})


class EnrollmentClient:
    """One-purpose unauthenticated client for the one-time registration endpoint."""
    def __init__(self, core_url: str, *, development_mode=False, timeout=15, opener=None):
        self.core_url = _validate_core_url(core_url, development_mode=development_mode)
        if type(timeout) is not int or not 1 <= timeout <= 60:
            raise ValueError('Request timeout must be between 1 and 60 seconds.')
        self.timeout = timeout
        self._opener = opener or build_opener(
            HTTPSHandler(context=ssl.create_default_context()), HTTPHandler(), _NoRedirect())

    def close(self):
        close = getattr(self._opener, 'close', None)
        if close is not None:
            close()

    def register(self, *, enrollment_token: str, sensor_uuid: str, sensor_name: str,
                 platform: str, version: str, capabilities: list[str]) -> dict:
        from urllib.parse import urljoin
        payload = json.dumps({
            'enrollment_token': enrollment_token, 'sensor_uuid': sensor_uuid,
            'sensor_name': sensor_name, 'platform': platform, 'version': version,
            'capabilities': capabilities,
        }, separators=(',', ':')).encode()
        if len(payload) > 16 * 1024:
            raise ValueError('Registration request exceeds its supported bound.')
        request = Request(urljoin(self.core_url.rstrip('/') + '/', 'sensor-enrollment/register'),
                          data=payload, headers={'Accept': 'application/json',
                          'Content-Type': 'application/json'}, method='POST')
        try:
            response = self._opener.open(request, timeout=self.timeout)
            with closing(response):
                status = getattr(response, 'status', response.getcode())
                data = response.read(16 * 1024 + 1)
        except HTTPError as exc:
            status = exc.code
            exc.close()
            raise SensorClientError('ENROLLMENT_REJECTED', status=status) from None
        except (TimeoutError, URLError, OSError) as exc:
            reason = getattr(exc, 'reason', None)
            code = 'CORE_TIMEOUT' if isinstance(exc, TimeoutError) or isinstance(reason, TimeoutError) else 'CORE_UNAVAILABLE'
            raise SensorClientError(code) from None
        if status != 201 or len(data) > 16 * 1024:
            raise SensorClientError('INVALID_REGISTRATION_RESPONSE', status=status)
        try:
            result = json.loads(data)
            returned_uuid = str(UUID(str(result['sensor_uuid'])))
            credential = result['credential']
        except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError, ValueError, AttributeError):
            raise SensorClientError('INVALID_REGISTRATION_RESPONSE', status=status) from None
        if (returned_uuid != sensor_uuid or not isinstance(credential, str)
                or not 40 <= len(credential) <= 128):
            raise SensorClientError('INVALID_REGISTRATION_RESPONSE', status=status)
        return result
