import json
import logging
from datetime import datetime
from io import BytesIO
from pathlib import Path
import ssl
from threading import Event
from urllib.error import HTTPError
from urllib.request import HTTPSHandler
import uuid

import pytest

from sensor.client import CoreClient, SensorClientError
from sensor.config import SensorConfig, load_config
from sensor.runtime import SensorRuntime
from sensor.state import load_grants
from services.remote_sensor_executor import LinuxRemoteSensorExecutor
from services.remote_sensor_models import (
    LocalExecutorGrant, RemoteSensorError,
)
from services.scanner_adapters.nmap_adapter import ScannerTimeoutError

SENSOR_UUID = 'dd03f49d-37d7-41b1-8c06-95b74c5d935a'
SECRET = 'c' * 43
TASK_ID = '1b945ca3-8d28-4c21-b18a-821c5a1a52cd'


def write_json(path: Path, value, mode=0o600):
    path.write_text(json.dumps(value), encoding='utf-8')
    path.chmod(mode)
    return path


def make_config(tmp_path, **overrides):
    grants = write_json(tmp_path / 'grants.json', {
        'sensor_uuid': SENSOR_UUID,
        'grants': [{'scope_id': 7, 'scope_type': 'PRIVATE_NETWORK',
                    'cidr': '192.168.1.0/24',
                    'capabilities': ['HOST_DISCOVERY', 'SERVICE_DISCOVERY']}],
    })
    config_path = tmp_path / 'config.json'
    raw = {'core_url': 'https://core.example.test', 'sensor_uuid': SENSOR_UUID,
           'sensor_credential': SECRET, 'grant_file': str(grants)}
    raw.update(overrides)
    write_json(config_path, raw)
    return load_config(config_path, environ={}), grants, config_path


class FakeResponse:
    def __init__(self, value, status=200):
        self.status = status
        self._data = json.dumps(value).encode()
        self.closed = False

    def read(self, amount=-1):
        return self._data[:amount]

    def getcode(self):
        return self.status

    def close(self):
        self.closed = True


class FakeOpener:
    def __init__(self, responses):
        self.responses = list(responses)
        self.requests = []

    def open(self, request, timeout):
        self.requests.append((request, timeout))
        value = self.responses.pop(0)
        if isinstance(value, Exception):
            raise value
        return value


def make_client(tmp_path, responses=None, **config_overrides):
    config, _, _ = make_config(tmp_path, **config_overrides)
    opener = FakeOpener(responses or [FakeResponse({'sensor_uuid': SENSOR_UUID})])
    nonces = iter(['A' * 43, 'B' * 43, 'C' * 43, 'D' * 43, 'E' * 43, 'F' * 43])
    client = CoreClient(config, opener=opener, nonce_factory=lambda: next(nonces))
    return config, client, opener


def test_config_loads_and_never_repr_exposes_credential(tmp_path):
    config, _, _ = make_config(tmp_path)
    assert config.poll_interval == 10
    assert config.heartbeat_interval == 45
    assert config.capabilities == ('HOST_DISCOVERY', 'SERVICE_DISCOVERY')
    assert SECRET not in repr(config)


def test_config_credentials_environment_override_and_missing_rejected(tmp_path):
    config, _, path = make_config(tmp_path)
    assert load_config(path, environ={'SENTINEL_SENSOR_CREDENTIAL': 'd' * 43}).sensor_credential == 'd' * 43
    raw = json.loads(path.read_text())
    raw.pop('sensor_credential')
    write_json(path, raw)
    with pytest.raises(RemoteSensorError, match='credential'):
        load_config(path, environ={})


@pytest.mark.parametrize('url', ['http://core.example.test', 'ftp://core.example.test',
                                  'https://user:pass@core.example.test', 'https://core.example.test/?x=1'])
def test_config_rejects_remote_plaintext_and_invalid_urls(tmp_path, url):
    with pytest.raises(RemoteSensorError):
        make_config(tmp_path, core_url=url, development_mode=True)


@pytest.mark.parametrize('url', ['http://127.0.0.1:8000', 'http://[::1]:8000', 'http://localhost:8000'])
def test_config_allows_http_loopback_only_in_explicit_development_mode(tmp_path, url):
    with pytest.raises(RemoteSensorError):
        make_config(tmp_path, core_url=url)
    config, _, _ = make_config(tmp_path, core_url=url, development_mode=True)
    assert config.core_url == url


def test_config_rejects_insecure_permissions_unknown_fields_and_bounds(tmp_path):
    config, _, path = make_config(tmp_path)
    path.chmod(0o644)
    with pytest.raises(RemoteSensorError, match='permissions'):
        load_config(path, environ={})
    write_json(path, {'core_url': config.core_url, 'sensor_uuid': SENSOR_UUID,
                      'sensor_credential': SECRET, 'grant_file': str(config.grant_file),
                      'command': 'bad'})
    with pytest.raises(RemoteSensorError, match='unsupported'):
        load_config(path, environ={})
    write_json(path, {'core_url': config.core_url, 'sensor_uuid': SENSOR_UUID,
                      'sensor_credential': SECRET, 'grant_file': str(config.grant_file),
                      'poll_interval': 1})
    with pytest.raises(RemoteSensorError, match='poll_interval'):
        load_config(path, environ={})
    write_json(path, {'core_url': config.core_url, 'sensor_uuid': SENSOR_UUID,
                      'sensor_credential': SECRET, 'grant_file': None})
    with pytest.raises(RemoteSensorError, match='grant_file'):
        load_config(path, environ={})


def test_grants_are_private_typed_and_bound_to_sensor(tmp_path):
    config, client, _ = make_client(tmp_path)
    client.close()
    grants = load_grants(config.grant_file, SENSOR_UUID, config.capabilities)
    assert grants[7].cidr == '192.168.1.0/24'
    path = config.grant_file
    raw = json.loads(path.read_text())
    raw['grants'][0]['cidr'] = '8.8.8.0/24'
    write_json(path, raw)
    with pytest.raises(RemoteSensorError):
        load_grants(path, SENSOR_UUID, config.capabilities)
    raw['grants'][0]['cidr'] = '192.168.1.0/24'
    write_json(path, raw)
    with pytest.raises(RemoteSensorError, match='identity'):
        load_grants(path, str(uuid.uuid4()), config.capabilities)


def test_client_calls_only_machine_routes_with_fresh_transport_headers(tmp_path):
    task = {'task': {'id': TASK_ID}}
    responses = [FakeResponse({'sensor_uuid': SENSOR_UUID}), FakeResponse({'ok': True}),
                 FakeResponse(task), FakeResponse({'status': 'RUNNING'}),
                 FakeResponse({'status': 'COMPLETED'}), FakeResponse({'status': 'FAILED'})]
    _, client, opener = make_client(tmp_path, responses)
    assert client.get_self()['sensor_uuid'] == SENSOR_UUID
    client.heartbeat()
    assert client.claim()['id'] == TASK_ID
    client.start(TASK_ID)
    client.result(TASK_ID, {'task_type': 'DISCOVER_NETWORK', 'observations': []})
    client.fail(TASK_ID, 'SCANNER_FAILED')
    expected = [('/sensor/self', 'GET'), ('/sensor/heartbeat', 'POST'),
                ('/sensor/tasks/claim', 'POST'), (f'/sensor/tasks/{TASK_ID}/start', 'POST'),
                (f'/sensor/tasks/{TASK_ID}/result', 'POST'), (f'/sensor/tasks/{TASK_ID}/fail', 'POST')]
    assert [(request.full_url.removeprefix('https://core.example.test'), request.get_method())
            for request, _ in opener.requests] == expected
    nonces = []
    for request, timeout in opener.requests:
        assert timeout == 15
        assert request.get_header('X-sensor-uuid') == SENSOR_UUID
        assert request.get_header('X-sentinel-timestamp').isdigit()
        nonces.append(request.get_header('X-sentinel-nonce'))
        assert request.get_header('Authorization') == f'Bearer {SECRET}'
    assert len(set(nonces)) == len(nonces)
    assert hasattr(client, 'get_self') and not hasattr(client, 'request')


def test_client_rejects_unbounded_or_arbitrary_result_fields_before_network(tmp_path):
    _, client, opener = make_client(tmp_path)
    with pytest.raises(ValueError):
        client.result(TASK_ID, {'task_type': 'DISCOVER_NETWORK', 'observations': [], 'command': 'bad'})
    with pytest.raises(ValueError):
        client.result(TASK_ID, {'task_type': 'DISCOVER_NETWORK',
                                'observations': [{'ip_address': '192.168.1.1', 'mac_address': None,
                                                  'hostname': None, 'vendor': None}] * 255})
    assert opener.requests == []


def test_client_sanitizes_transport_errors_and_does_not_follow_redirects(tmp_path):
    _, client, _ = make_client(tmp_path, [SensorClientError('CORE_UNAVAILABLE')])
    with pytest.raises(SensorClientError) as exc:
        client.get_self()
    assert SECRET not in str(exc.value)
    from sensor.client import _NoRedirect
    assert _NoRedirect().redirect_request(None, None, 302, 'Found', {}, 'http://evil.test/') is None


def test_default_http_client_verifies_tls_certificates(tmp_path):
    config, _, _ = make_config(tmp_path)
    client = CoreClient(config)
    https = next(handler for handler in client._opener.handlers if isinstance(handler, HTTPSHandler))
    assert https._context.verify_mode == ssl.CERT_REQUIRED
    assert https._context.check_hostname is True
    client.close()


class FakeClient:
    def __init__(self, task=None):
        self.task = task
        self.calls = []
        self.heartbeat_error = None

    def heartbeat(self):
        self.calls.append(('heartbeat',))
        if self.heartbeat_error:
            error, self.heartbeat_error = self.heartbeat_error, None
            raise error

    def claim(self):
        self.calls.append(('claim',))
        task, self.task = self.task, None
        return task

    def start(self, task_id): self.calls.append(('start', task_id)); return {}
    def result(self, task_id, result): self.calls.append(('result', task_id, result)); return {}
    def fail(self, task_id, code): self.calls.append(('fail', task_id, code)); return {}


class FakeExecutor:
    def __init__(self, result=None, error=None):
        self.result = result
        self.error = error
        self.calls = []

    def discover_network(self, task, grant):
        self.calls.append(('DISCOVER_NETWORK', task, grant))
        if self.error: raise self.error
        return self.result

    def discover_services(self, task, grant):
        self.calls.append(('DISCOVER_SERVICES', task, grant))
        if self.error: raise self.error
        return self.result


def runtime_components(tmp_path, client, executor, *, capabilities=('HOST_DISCOVERY', 'SERVICE_DISCOVERY')):
    config, _, _ = make_config(tmp_path, capabilities=list(capabilities))
    grant = LocalExecutorGrant(SENSOR_UUID, 7, '192.168.1.0/24', frozenset(capabilities))
    return config, {7: grant}, SensorRuntime(config, {7: grant}, client, executor)


def network_task(**overrides):
    value = {'id': TASK_ID, 'sensor_uuid': SENSOR_UUID, 'scope_id': 7,
             'scope_type': 'PRIVATE_NETWORK', 'task_type': 'DISCOVER_NETWORK',
             'scope_cidr': '192.168.1.0/24', 'target_ip': None,
             'network_id': 2, 'target_device_id': None, 'status': 'CLAIMED',
             'expires_at': '2026-10-13T00:15:00+00:00', 'claimed_at': '2026-10-13T00:00:00+00:00',
             'started_at': None, 'attempt_count': 1}
    value.update(overrides)
    return value


def test_poll_idle_heartbeats_and_sleeps_without_busy_loop(tmp_path):
    client, executor = FakeClient(), FakeExecutor()
    _, _, runtime = runtime_components(tmp_path, client, executor)
    assert runtime.run_once() == 10
    assert [call[0] for call in client.calls] == ['heartbeat', 'claim']
    assert executor.calls == []


def test_poll_validates_then_starts_executes_and_submits_one_task(tmp_path):
    from datetime import datetime
    from services.scan_models import HostDiscoveryResult, ScanResult
    result = ScanResult('192.168.1.0/24', 'nmap', datetime.now(), datetime.now(),
                        (HostDiscoveryResult('192.168.1.20', discovered_at=datetime.now()),))
    client, executor = FakeClient(network_task()), FakeExecutor(result)
    _, grants, runtime = runtime_components(tmp_path, client, executor)
    runtime.run_once()
    assert [call[0] for call in client.calls] == ['heartbeat', 'claim', 'start', 'result']
    assert client.calls[-1][2] == {'task_type': 'DISCOVER_NETWORK', 'observations': [
        {'ip_address': '192.168.1.20', 'mac_address': None, 'hostname': None, 'vendor': None}]}
    assert len(executor.calls) == 1 and executor.calls[0][2] == grants[7]


@pytest.mark.parametrize('changes', [
    {'sensor_uuid': str(uuid.uuid4())},
    {'scope_id': 9},
    {'scope_cidr': '192.168.2.0/24'},
    {'scope_type': 'PUBLIC_CIDR'},
    {'task_type': 'EXEC'},
    {'target_ip': '8.8.8.8'},
    {'command': 'whoami'},
])
def test_local_validation_rejects_malformed_or_unauthorized_claim_before_start(tmp_path, changes):
    client, executor = FakeClient(network_task(**changes)), FakeExecutor()
    _, _, runtime = runtime_components(tmp_path, client, executor)
    runtime.run_once()
    assert not any(call[0] == 'start' for call in client.calls)
    assert not executor.calls
    assert ('fail', TASK_ID, 'INVALID_RESULT') in client.calls


def test_service_task_rejects_outside_ip_before_start(tmp_path):
    task = network_task(task_type='DISCOVER_SERVICES', target_ip='8.8.8.8',
                        target_device_id=18)
    client, executor = FakeClient(task), FakeExecutor()
    _, _, runtime = runtime_components(tmp_path, client, executor)
    runtime.run_once()
    assert not any(call[0] == 'start' for call in client.calls)
    assert not executor.calls
    assert ('fail', TASK_ID, 'INVALID_RESULT') in client.calls


def test_runtime_rejects_task_capability_disabled_in_local_config(tmp_path):
    task = network_task(task_type='DISCOVER_SERVICES', target_ip='192.168.1.20',
                        target_device_id=18)
    client, executor = FakeClient(task), FakeExecutor()
    _, _, runtime = runtime_components(tmp_path, client, executor, capabilities=('HOST_DISCOVERY',))
    runtime.run_once()
    assert not any(call[0] == 'start' for call in client.calls)
    assert not executor.calls


def test_runtime_fails_task_when_scanner_times_out(tmp_path):
    client = FakeClient(network_task())
    executor = FakeExecutor(error=ScannerTimeoutError('internal timeout detail'))
    _, _, runtime = runtime_components(tmp_path, client, executor)
    runtime.run_once()
    assert ('fail', TASK_ID, 'SCANNER_TIMEOUT') in client.calls


@pytest.mark.parametrize('delivery_error', [
    SensorClientError('CORE_UNAVAILABLE'),
    SensorClientError('CORE_TIMEOUT'),
    SensorClientError('CORE_HTTP_ERROR', status=500),
    SensorClientError('CORE_HTTP_ERROR', status=503),
    SensorClientError('CORE_HTTP_ERROR', status=429),
])
def test_result_delivery_retry_preserves_payload_and_does_not_reexecute(tmp_path, delivery_error):
    from services.scan_models import HostDiscoveryResult, ScanResult
    from sensor.runtime import _ResultDeliveryRetry

    result = ScanResult(
        '192.168.1.0/24', 'nmap', datetime.now(), datetime.now(),
        (HostDiscoveryResult('192.168.1.20', discovered_at=datetime.now()),),
    )
    client, executor = FakeClient(network_task()), FakeExecutor(result)
    original_result = client.result
    attempts = []

    def fail_once(task_id, payload):
        attempts.append((task_id, payload))
        if len(attempts) == 1:
            raise delivery_error
        return original_result(task_id, payload)

    client.result = fail_once
    _, _, runtime = runtime_components(tmp_path, client, executor)
    with pytest.raises(_ResultDeliveryRetry):
        runtime.run_once()
    pending = runtime._pending_result
    assert pending is not None
    assert ('fail', TASK_ID, 'SCANNER_FAILED') not in client.calls
    assert ('fail', TASK_ID, 'INVALID_RESULT') not in client.calls

    runtime.run_once()
    assert len(executor.calls) == 1
    assert attempts[0] == attempts[1]
    assert runtime._pending_result is None
    assert [call[0] for call in client.calls].count('result') == 1


@pytest.mark.parametrize('status', [400, 409])
def test_permanent_result_rejection_is_not_retried_or_failed_again(tmp_path, status):
    from services.scan_models import HostDiscoveryResult, ScanResult

    result = ScanResult(
        '192.168.1.0/24', 'nmap', datetime.now(), datetime.now(),
        (HostDiscoveryResult('192.168.1.20', discovered_at=datetime.now()),),
    )
    client, executor = FakeClient(network_task()), FakeExecutor(result)

    def reject(*_args):
        raise SensorClientError('CORE_HTTP_ERROR', status=status)

    client.result = reject
    _, _, runtime = runtime_components(tmp_path, client, executor)
    runtime.run_once()
    assert runtime._pending_result is None
    assert not any(call[0] == 'fail' for call in client.calls)


def test_result_retry_uses_same_body_and_fresh_request_nonce(tmp_path):
    payload = {'task_type': 'DISCOVER_NETWORK', 'observations': []}
    failed = HTTPError(
        f'https://core.example.test/sensor/tasks/{TASK_ID}/result',
        503, 'Unavailable', {}, BytesIO(b''),
    )
    _, client, opener = make_client(
        tmp_path, [failed, FakeResponse({'task_id': TASK_ID, 'status': 'COMPLETED', 'duplicate': True})]
    )
    with pytest.raises(SensorClientError) as exc:
        client.result(TASK_ID, payload)
    assert exc.value.status == 503
    assert client.result(TASK_ID, payload)['duplicate'] is True
    first, second = opener.requests
    assert first[0].data == second[0].data
    assert first[0].get_header('X-sentinel-nonce') != second[0].get_header('X-sentinel-nonce')


def test_result_retry_backoff_is_capped_and_never_fails_task(tmp_path):
    from services.scan_models import HostDiscoveryResult, ScanResult

    result = ScanResult(
        '192.168.1.0/24', 'nmap', datetime.now(), datetime.now(),
        (HostDiscoveryResult('192.168.1.20', discovered_at=datetime.now()),),
    )
    client, executor = FakeClient(network_task()), FakeExecutor(result)

    def unavailable(*_args):
        raise SensorClientError('CORE_HTTP_ERROR', status=503)

    client.result = unavailable
    _, _, runtime = runtime_components(tmp_path, client, executor)
    delays = []
    elapsed = [0.0]
    runtime._monotonic = lambda: elapsed[0]

    def stop_after_five(delay):
        delays.append(delay)
        elapsed[0] += delay
        if len(delays) == 5:
            runtime.stop_event.set()

    runtime._sleep = stop_after_five
    runtime.run()
    assert delays == [5, 10, 30, 60, 60]
    assert len(executor.calls) == 1
    assert runtime._pending_result is not None
    assert not any(call[0] == 'fail' for call in client.calls)


def test_pending_result_schedule_survives_heartbeat_failures_and_recovery(tmp_path):
    from services.scan_models import HostDiscoveryResult, ScanResult

    result = ScanResult(
        '192.168.1.0/24', 'nmap', datetime.now(), datetime.now(),
        (HostDiscoveryResult('192.168.1.20', discovered_at=datetime.now()),),
    )
    client, executor = FakeClient(network_task()), FakeExecutor(result)
    elapsed = [0.0]
    events = []
    result_attempts = []
    heartbeat_attempts = []

    def heartbeat():
        heartbeat_attempts.append(elapsed[0])
        events.append(('heartbeat', elapsed[0]))
        if len(heartbeat_attempts) == 2:
            raise SensorClientError('CORE_UNAVAILABLE')
        return {}

    def unavailable_result(task_id, payload):
        result_attempts.append((elapsed[0], task_id, payload))
        events.append(('result', elapsed[0]))
        raise SensorClientError('CORE_HTTP_ERROR', status=503)

    client.heartbeat = heartbeat
    client.result = unavailable_result
    _, _, runtime = runtime_components(tmp_path, client, executor)
    runtime._monotonic = lambda: elapsed[0]
    delays = []

    def advance(delay):
        delays.append(delay)
        elapsed[0] += delay
        if len(delays) == 5:
            runtime.stop_event.set()

    runtime._sleep = advance
    runtime.run()

    assert delays == [5, 10, 30, 60, 60]
    assert [attempt[0] for attempt in result_attempts] == [0, 5, 15, 45, 105]
    assert heartbeat_attempts == [0, 45, 105]
    assert events.index(('heartbeat', 45)) < events.index(('result', 45))
    assert events.index(('heartbeat', 105)) < events.index(('result', 105))
    assert len(executor.calls) == 1
    assert len({repr(attempt[2]) for attempt in result_attempts}) == 1
    assert sum(call[0] == 'claim' for call in client.calls) == 1
    assert runtime._pending_result is not None
    assert not any(call[0] == 'fail' for call in client.calls)


def test_successful_pending_delivery_resets_result_backoff(tmp_path):
    from services.scan_models import HostDiscoveryResult, ScanResult

    result = ScanResult(
        '192.168.1.0/24', 'nmap', datetime.now(), datetime.now(),
        (HostDiscoveryResult('192.168.1.20', discovered_at=datetime.now()),),
    )
    client, executor = FakeClient(network_task()), FakeExecutor(result)
    original_result = client.result
    attempts = []

    def fail_twice(task_id, payload):
        attempts.append((task_id, payload))
        if len(attempts) <= 2:
            raise SensorClientError('CORE_HTTP_ERROR', status=503)
        return original_result(task_id, payload)

    client.result = fail_twice
    _, _, runtime = runtime_components(tmp_path, client, executor)
    delays = []

    def stop_after_poll(delay):
        delays.append(delay)
        if len(delays) == 3:
            runtime.stop_event.set()

    runtime._sleep = stop_after_poll
    runtime.run()
    assert delays == [5, 10, runtime.config.poll_interval]
    assert len(attempts) == 3 and attempts[0] == attempts[1] == attempts[2]
    assert runtime._pending_result is None
    assert runtime._result_backoff_index == 0
    assert len(executor.calls) == 1
    assert not any(call[0] == 'fail' for call in client.calls)


def test_pending_result_is_attempted_even_when_due_heartbeat_fails(tmp_path):
    from services.scan_models import HostDiscoveryResult, ScanResult
    from sensor.runtime import _ResultDeliveryRetry

    result = ScanResult(
        '192.168.1.0/24', 'nmap', datetime.now(), datetime.now(),
        (HostDiscoveryResult('192.168.1.20', discovered_at=datetime.now()),),
    )
    client, executor = FakeClient(network_task()), FakeExecutor(result)
    original_result = client.result
    attempts = []

    def fail_once(task_id, payload):
        attempts.append((task_id, payload))
        if len(attempts) == 1:
            raise SensorClientError('CORE_HTTP_ERROR', status=503)
        return original_result(task_id, payload)

    client.result = fail_once
    _, _, runtime = runtime_components(tmp_path, client, executor)
    with pytest.raises(_ResultDeliveryRetry):
        runtime.run_once()
    runtime._heartbeat_due = 0

    def heartbeat_failure():
        raise SensorClientError('CORE_UNAVAILABLE')

    client.heartbeat = heartbeat_failure
    runtime.run_once()
    assert len(attempts) == 2 and attempts[0] == attempts[1]
    assert len(executor.calls) == 1
    assert runtime._pending_result is None
    assert not any(call[0] == 'fail' for call in client.calls)


def test_transport_backoff_is_bounded_and_resets_after_success(tmp_path):
    client = FakeClient()
    client.heartbeat_error = SensorClientError('CORE_UNAVAILABLE')
    _, _, runtime = runtime_components(tmp_path, client, FakeExecutor())
    sleeps = []
    original_claim = client.claim
    claim_count = [0]
    def claim_with_later_outage():
        claim_count[0] += 1
        if claim_count[0] == 2:
            raise SensorClientError('CORE_UNAVAILABLE')
        return original_claim()
    client.claim = claim_with_later_outage
    def stop_after_four(delay):
        sleeps.append(delay)
        if len(sleeps) == 4:
            runtime.stop_event.set()
    runtime._sleep = stop_after_four
    runtime.run()
    assert sleeps == [5, 10, 5, 10]


def test_backoff_caps_at_sixty_seconds(tmp_path):
    client = FakeClient()
    _, _, runtime = runtime_components(tmp_path, client, FakeExecutor())
    sleeps = []
    def fail_every_heartbeat():
        raise SensorClientError('CORE_UNAVAILABLE')
    client.heartbeat = fail_every_heartbeat
    def stop_after_six(delay):
        sleeps.append(delay)
        if len(sleeps) == 6:
            runtime.stop_event.set()
    runtime._sleep = stop_after_six
    runtime.run()
    assert sleeps == [5, 10, 30, 60, 60, 60]


def test_shutdown_during_heartbeat_does_not_claim_new_work(tmp_path):
    client, executor = FakeClient(network_task()), FakeExecutor()
    _, _, runtime = runtime_components(tmp_path, client, executor)
    def heartbeat():
        client.calls.append(('heartbeat',))
        runtime.stop_event.set()
    client.heartbeat = heartbeat
    runtime.run_once()
    assert [call[0] for call in client.calls] == ['heartbeat']
    assert not executor.calls


def test_self_test_checks_core_identity_without_execution(tmp_path, monkeypatch):
    from sensor.__main__ import _self_test
    class SelfClient:
        def __init__(self): self.calls = []
        def get_self(self): self.calls.append('self'); return {'sensor_uuid': SENSOR_UUID, 'enabled': True}
        def get_grant(self):
            self.calls.append('grant')
            return {'grants': [
                {'scope_id': 7, 'scope_type': 'PRIVATE_NETWORK', 'cidr': '192.168.1.0/24',
                 'capabilities': ['HOST_DISCOVERY', 'SERVICE_DISCOVERY']}]}
    config, _, _ = make_config(tmp_path)
    monkeypatch.setattr('sensor.__main__._check_dependencies', lambda config: True)
    client = SelfClient()
    _self_test(config, client, logging.getLogger('test.sensor'))
    assert client.calls == ['self', 'grant']


def test_cli_has_no_raw_scan_or_command_mode():
    from sensor.__main__ import _parser
    with pytest.raises(SystemExit):
        _parser().parse_args(['scan', '8.8.8.8'])
    with pytest.raises(SystemExit):
        _parser().parse_args(['exec', 'whoami'])


def test_logging_contains_no_credential_and_has_structured_allowed_fields(tmp_path, caplog):
    client, executor = FakeClient(), FakeExecutor()
    _, _, runtime = runtime_components(tmp_path, client, executor)
    with caplog.at_level(logging.INFO, logger='sentinelip.sensor'):
        runtime.run_once()
    output = '\n'.join(record.message for record in caplog.records)
    assert SECRET not in output
    record = json.loads(caplog.records[-1].message)
    assert set(record) == {'timestamp', 'sensor_uuid', 'status'}


def test_linux_executor_only_is_typed_runtime_executor():
    assert callable(LinuxRemoteSensorExecutor.discover_network)
    assert callable(LinuxRemoteSensorExecutor.discover_services)
    assert not hasattr(LinuxRemoteSensorExecutor, 'execute')
    assert not hasattr(LinuxRemoteSensorExecutor, 'run_shell')

