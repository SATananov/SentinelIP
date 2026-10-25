import asyncio
import ipaddress
import json
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.routing import APIRoute, Match

from api.remote_tasks import NetworkResult, ServicesResult, register_remote_task_routes
from api.remote_tasks import TaskFailure
from api.sensor_enrollment import (
    MAX_SENSOR_BODY_BYTES,
    TASK_RESULT_BODY_MAX_BYTES,
    SensorBodyLimitMiddleware,
    _is_task_result_request,
)
from sensor.client import (
    CoreClient,
    DEFAULT_SENSOR_REQUEST_MAX_BYTES,
    DEFAULT_SENSOR_RESPONSE_MAX_BYTES,
    SensorClientError,
    RequestBodyTooLargeError,
    TASK_RESULT_REQUEST_MAX_BYTES,
)
from sensor.config import SensorConfig


TASK_ID = '1b945ca3-8d28-4c21-b18a-821c5a1a52cd'


class _Response:
    status = 200

    def read(self, amount=-1):
        return b'{"ok":true}'[:amount]

    def getcode(self):
        return self.status

    def close(self):
        pass


class _Opener:
    def __init__(self):
        self.requests = []

    def open(self, request, timeout):
        self.requests.append(request)
        return _Response()


class _LargeResponse(_Response):
    def read(self, amount=-1):
        return b' ' * (DEFAULT_SENSOR_RESPONSE_MAX_BYTES + 1)


def _client():
    opener = _Opener()
    config = SensorConfig(
        'https://core.example.test',
        'dd03f49d-37d7-41b1-8c06-95b74c5d935a',
        'c' * 43,
        Path('/tmp/sentinelip-test-grants.json'),
    )
    client = CoreClient(config, opener=opener, nonce_factory=lambda: 'A' * 43)
    return client, opener


def _host_result(*, mac=False, hostname=None, vendor=None, maximum=False):
    ips = [str(ip) for ip in ipaddress.ip_network('192.168.255.0/24').hosts()]
    rows = []
    for index, ip in enumerate(ips):
        rows.append({
            'ip_address': ip,
            'mac_address': 'aa:bb:cc:dd:ee:ff' if mac or maximum else None,
            'hostname': ('😀' * 253 if maximum else
                         (f'host-{index:03d}.example.test' if hostname else None)),
            'vendor': ('😀' * 128 if maximum else ('Example Vendor' if vendor else None)),
        })
    return {'task_type': 'DISCOVER_NETWORK', 'observations': rows}


def _service_result(*, maximum=False):
    ports = [{'port': port} for port in range(1, 22)]
    services = []
    for port in range(1, 22):
        value = '😀' * 128 if maximum else 'x' * 128
        services.append({
            'port': port,
            'service_name': value,
            'product': value,
            'version': value,
            'extra_info': value,
        })
    return {'task_type': 'DISCOVER_SERVICES', 'ports': ports, 'services': services}


@pytest.mark.parametrize(
    ('payload', 'expected_bytes'),
    [
        (_host_result(), 20_769),
        (_host_result(mac=True), 24_579),
        (_host_result(hostname=True), 25_595),
        (_host_result(mac=True, hostname=True, vendor=True), 32_453),
        (_host_result(maximum=True), 1_184_851),
        (_service_result(maximum=True), 130_826),
    ],
)
def test_production_client_serializes_and_sends_valid_bounded_results(payload, expected_bytes):
    client, opener = _client()
    if payload['task_type'] == 'DISCOVER_NETWORK':
        NetworkResult.model_validate(payload)
    else:
        ServicesResult.model_validate(payload)

    assert client.result(TASK_ID, payload) == {'ok': True}
    assert len(opener.requests) == 1
    assert len(opener.requests[0].data) == expected_bytes
    assert expected_bytes <= TASK_RESULT_REQUEST_MAX_BYTES


def test_result_caps_match_and_other_client_requests_keep_default_limit():
    assert TASK_RESULT_REQUEST_MAX_BYTES == TASK_RESULT_BODY_MAX_BYTES == 1_310_720
    assert DEFAULT_SENSOR_REQUEST_MAX_BYTES == MAX_SENSOR_BODY_BYTES == 16_384
    assert DEFAULT_SENSOR_RESPONSE_MAX_BYTES == 16_384

    client, opener = _client()
    exact_default = {'x': 'a' * (DEFAULT_SENSOR_REQUEST_MAX_BYTES - 8)}
    assert len(json.dumps(exact_default, separators=(',', ':')).encode()) == DEFAULT_SENSOR_REQUEST_MAX_BYTES
    client._call('POST', '/sensor/heartbeat', exact_default)
    assert len(opener.requests) == 1

    over_default = {'x': 'a' * (DEFAULT_SENSOR_REQUEST_MAX_BYTES - 7)}
    with pytest.raises(ValueError, match='16385 bytes; limit is 16384 bytes'):
        client._call('POST', '/sensor/heartbeat', over_default)
    assert len(opener.requests) == 1


def test_astral_unicode_is_the_largest_ensure_ascii_expansion_per_character():
    encoded_sizes = {
        'astral': len(json.dumps('😀').encode('utf-8')),
        'control': len(json.dumps('\x01').encode('utf-8')),
        'quote': len(json.dumps('"').encode('utf-8')),
        'backslash': len(json.dumps('\\').encode('utf-8')),
        'line_separator': len(json.dumps('\u2028').encode('utf-8')),
        'lone_surrogate': len(json.dumps('\ud800').encode('utf-8')),
    }
    assert encoded_sizes == {
        'astral': 14,
        'control': 8,
        'quote': 4,
        'backslash': 4,
        'line_separator': 8,
        'lone_surrogate': 8,
    }
    assert encoded_sizes['astral'] == max(encoded_sizes.values())
    control_payload = _host_result()
    control_payload['observations'][0]['hostname'] = '\x01' * 253
    NetworkResult.model_validate(control_payload)


def test_result_client_exact_cap_accepted_and_cap_plus_one_rejected_before_send():
    client, opener = _client()
    exact = {'x': 'a' * (TASK_RESULT_REQUEST_MAX_BYTES - 8)}
    client._call('POST', f'/sensor/tasks/{TASK_ID}/result', exact,
                 request_max_bytes=TASK_RESULT_REQUEST_MAX_BYTES)
    assert len(opener.requests[-1].data) == TASK_RESULT_REQUEST_MAX_BYTES

    over = {'x': 'a' * (TASK_RESULT_REQUEST_MAX_BYTES - 7)}
    sent = len(opener.requests)
    with pytest.raises(RequestBodyTooLargeError, match='1310721 bytes; limit is 1310720 bytes') as exc:
        client._call('POST', f'/sensor/tasks/{TASK_ID}/result', over,
                     request_max_bytes=TASK_RESULT_REQUEST_MAX_BYTES)
    assert exc.value.actual_bytes == TASK_RESULT_REQUEST_MAX_BYTES + 1
    assert exc.value.allowed_bytes == TASK_RESULT_REQUEST_MAX_BYTES
    assert len(opener.requests) == sent


def test_result_too_large_failure_code_is_valid_and_persisted_without_migration(tmp_path):
    from datetime import datetime, timezone

    from database.networks import create_network
    from database.remote_sensors import RemoteSensorStore
    from database.remote_tasks import RemoteTaskStore
    from database.scopes import get_scope_for_network
    from services.remote_sensor_models import Capability

    db_path = tmp_path / 'result-too-large.db'
    store = RemoteSensorStore(db_path, clock=lambda: datetime.now(timezone.utc))
    site = store.create_site('Test')
    enrollment = store.create_enrollment(site['id'])
    issued = store.consume_enrollment(
        enrollment.secret, name='Test sensor', platform='linux', version='1',
        reported_capabilities=[Capability.HOST_DISCOVERY.value],
    )
    network = create_network('192.168.1.0/24', 'Test LAN', '', True, True, db_path)
    scope = get_scope_for_network(network['id'], db_path)
    store.assign_scope(issued.record['id'], scope['id'])
    task_store = RemoteTaskStore(store)
    task = task_store.create_task(issued.record['id'], scope['id'], 'DISCOVER_NETWORK')
    claimed = task_store.claim_next(issued.record['id'])
    assert claimed['id'] == task['id']
    task_store.transition(issued.record['id'], task['id'], 'start')

    failure = TaskFailure.model_validate({'error_code': 'RESULT_TOO_LARGE'})
    assert task_store.fail(issued.record['id'], task['id'], failure.error_code)
    history = task_store.list_task_history(sensor_id=issued.record['id'])['items'][0]

    assert history['status'] == 'FAILED'
    assert history['failure_code'] == 'RESULT_TOO_LARGE'
    assert history['failure_message_safe'] == (
        'Sensor result exceeded the supported transport limit.'
    )


def test_result_acknowledgement_response_cap_remains_16k():
    client, opener = _client()
    opener.open = lambda request, timeout: _LargeResponse()
    with pytest.raises(SensorClientError, match='INVALID_RESPONSE'):
        client._call('POST', f'/sensor/tasks/{TASK_ID}/result', {'x': 'ok'},
                     request_max_bytes=TASK_RESULT_REQUEST_MAX_BYTES)


async def _run_middleware(path, *, method='POST', headers=(), chunks=((b'', False),),
                          root_path='', query_string=b''):
    downstream = []
    sent = []
    index = 0

    async def app(scope, receive, send):
        while True:
            message = await receive()
            downstream.append(message)
            if not message.get('more_body', False):
                break

    async def receive():
        nonlocal index
        await asyncio.sleep(0)
        body, more = chunks[index]
        index += 1
        return {'type': 'http.request', 'body': body, 'more_body': more}

    async def send(message):
        sent.append(message)

    scope = {
        'type': 'http', 'method': method, 'path': path, 'headers': list(headers),
        'root_path': root_path, 'query_string': query_string,
    }
    await SensorBodyLimitMiddleware(app)(scope, receive, send)
    return downstream, sent, index


def _chunks(data, sizes):
    result = []
    offset = 0
    for size in sizes:
        result.append(data[offset:offset + size])
        offset += size
    if offset < len(data):
        result.append(data[offset:])
    return [(part, index < len(result) - 1) for index, part in enumerate(result)]


def test_result_route_accepts_above_default_limit_and_replays_body_intact():
    body = b'R' * 20_769
    downstream, sent, _ = asyncio.run(_run_middleware(
        f'/sensor/tasks/{TASK_ID}/result', chunks=_chunks(body, [1024, 8192, 4096]),
    ))
    assert not sent
    assert b''.join(message['body'] for message in downstream) == body


def test_empty_result_body_passes_size_layer_to_normal_route_validation():
    downstream, sent, _ = asyncio.run(_run_middleware(
        f'/sensor/tasks/{TASK_ID}/result', chunks=[(b'', False)],
    ))
    assert downstream == [{'type': 'http.request', 'body': b'', 'more_body': False}]
    assert not sent


def test_disconnect_while_buffering_does_not_forward_partial_body():
    called = False
    sent = []

    async def app(scope, receive, send):
        nonlocal called
        called = True

    async def receive():
        return {'type': 'http.disconnect'}

    async def send(message):
        sent.append(message)

    asyncio.run(SensorBodyLimitMiddleware(app)(
        {'type': 'http', 'method': 'POST', 'path': f'/sensor/tasks/{TASK_ID}/result', 'headers': []},
        receive, send,
    ))
    assert not called and not sent


def test_non_http_scope_without_path_is_forwarded_without_route_matching():
    called = False

    async def app(scope, receive, send):
        nonlocal called
        called = True

    async def receive():
        return {'type': 'lifespan.startup'}

    async def send(message):
        pass

    asyncio.run(SensorBodyLimitMiddleware(app)(
        {'type': 'lifespan'}, receive, send,
    ))
    assert called


@pytest.mark.parametrize('payload', [
    _host_result(maximum=True),
    _service_result(maximum=True),
])
def test_server_middleware_accepts_maximum_valid_host_and_service_bodies(payload):
    if payload['task_type'] == 'DISCOVER_NETWORK':
        NetworkResult.model_validate(payload)
    else:
        ServicesResult.model_validate(payload)
    body = json.dumps(payload, separators=(',', ':')).encode('utf-8')
    assert len(body) <= TASK_RESULT_BODY_MAX_BYTES
    downstream, sent, _ = asyncio.run(_run_middleware(
        f'/sensor/tasks/{TASK_ID}/result', chunks=[(body, False)],
    ))
    assert not sent
    assert b''.join(message['body'] for message in downstream) == body


def test_result_route_accepts_exact_limit_and_rejects_cap_plus_one():
    exact = b'x' * TASK_RESULT_BODY_MAX_BYTES
    downstream, sent, _ = asyncio.run(_run_middleware(
        f'/sensor/tasks/{TASK_ID}/result',
        chunks=_chunks(exact, [300_000, 400_000, 500_000]),
    ))
    assert not sent
    assert b''.join(message['body'] for message in downstream) == exact

    with_length, sent, _ = asyncio.run(_run_middleware(
        f'/sensor/tasks/{TASK_ID}/result',
        headers=[(b'content-length', str(TASK_RESULT_BODY_MAX_BYTES).encode())],
        chunks=[(exact, False)],
    ))
    assert not sent
    assert b''.join(message['body'] for message in with_length) == exact

    over = b'x' * (TASK_RESULT_BODY_MAX_BYTES + 1)
    downstream, sent, received = asyncio.run(_run_middleware(
        f'/sensor/tasks/{TASK_ID}/result', chunks=_chunks(over, [500_000, 500_000, 400_000]),
    ))
    assert not downstream
    assert received == 3
    assert sent[0]['status'] == 413


@pytest.mark.parametrize('headers', [
    [(b'content-length', b'1310721')],
    [(b'content-length', b'1')],
    [(b'content-length', b'1310721'), (b'content-length', b'1')],
    [(b'content-length', b'not-a-number')],
    [(b'content-length', b'-1')],
    [],
])
def test_result_route_uses_declared_and_streamed_size_checks(headers):
    body = b'x' * (TASK_RESULT_BODY_MAX_BYTES + 1)
    chunks = _chunks(body, [600_000, 600_000])
    downstream, sent, received = asyncio.run(_run_middleware(
        f'/sensor/tasks/{TASK_ID}/result', headers=headers, chunks=chunks,
    ))
    assert not downstream
    assert sent[0]['status'] == 413
    if len(headers) == 1 and headers[0][1] == b'1310721':
        assert received == 0


@pytest.mark.parametrize('path,method', [
    (f'/sensor/tasks/{TASK_ID}/start', 'POST'),
    (f'/sensor/tasks/{TASK_ID}/fail', 'POST'),
    (f'/sensor/tasks/{TASK_ID}/failure', 'POST'),
    ('/sensor/tasks/result', 'POST'),
    ('/sensor/foo/result', 'POST'),
    (f'/sensor/tasks/{TASK_ID}/result-extra', 'POST'),
    (f'/sensor/tasks/{TASK_ID}/result/extra', 'POST'),
    (f'/sensor/tasks/{TASK_ID}/result', 'GET'),
    (f'/sensor/tasks/{TASK_ID}/result', 'PUT'),
    (f'/sensor/tasks/{TASK_ID}/result', 'PATCH'),
    (f'/sensor/tasks/{TASK_ID}/result', 'DELETE'),
    ('/sensor/heartbeat', 'POST'),
    ('/sensor/perimeter-events', 'POST'),
    ('/sensor-enrollment/register', 'POST'),
])
def test_only_canonical_post_task_result_gets_larger_limit(path, method):
    body = b'x' * (MAX_SENSOR_BODY_BYTES + 1)
    downstream, sent, _ = asyncio.run(_run_middleware(
        path, method=method, chunks=[(body, False)],
    ))
    assert not downstream
    assert sent[0]['status'] == 413


@pytest.mark.parametrize('task_id', [
    TASK_ID,
    TASK_ID.upper(),
    TASK_ID[:8] + '-' + TASK_ID[9:13].upper() + TASK_ID[13:],
    '{' + TASK_ID + '}',
    TASK_ID.replace('-', ''),
    'x',
])
def test_result_matcher_matches_fastapi_string_path_parameter_forms(task_id):
    app = FastAPI()
    register_remote_task_routes(app, lambda: None)
    route = next(r for r in app.routes if isinstance(r, APIRoute)
                 and r.path == '/sensor/tasks/{task_id}/result')
    assert route.param_convertors['task_id'].regex == '[^/]+'
    path = f'/sensor/tasks/{task_id}/result'
    scope = {'type': 'http', 'method': 'POST', 'path': path, 'root_path': ''}
    match, _ = route.matches(scope)
    assert match is Match.FULL
    assert _is_task_result_request(scope)

    downstream, sent, _ = asyncio.run(_run_middleware(
        path, chunks=[(b'x' * (MAX_SENSOR_BODY_BYTES + 1), False)],
    ))
    assert downstream and not sent


def test_result_matcher_handles_root_path_query_and_fastapi_trailing_slash_redirect():
    canonical = f'/sensor/tasks/{TASK_ID}/result'
    for slash_path in (canonical + '/', canonical + '///'):
        downstream, sent, _ = asyncio.run(_run_middleware(
            f'/prefix{slash_path}', root_path='/prefix', query_string=b'view=1',
            chunks=[(b'x' * (MAX_SENSOR_BODY_BYTES + 1), False)],
        ))
        # FastAPI strips trailing slashes before redirecting to this POST route;
        # middleware must not reject a result body before that redirect.
        assert downstream and not sent

    encoded_slash_path = f'/sensor/tasks/{TASK_ID}/extra/result'
    downstream, sent, _ = asyncio.run(_run_middleware(
        encoded_slash_path, chunks=[(b'x' * (MAX_SENSOR_BODY_BYTES + 1), False)],
    ))
    assert not downstream and sent[0]['status'] == 413


def test_unrelated_sensor_and_enrollment_keep_16k_while_result_accepts_same_body():
    body = b'x' * 20_769
    result_downstream, result_sent, _ = asyncio.run(_run_middleware(
        f'/sensor/tasks/{TASK_ID}/result', chunks=[(body, False)],
    ))
    assert result_downstream and not result_sent

    for path in ('/sensor/heartbeat', '/sensor-enrollment/register'):
        downstream, sent, _ = asyncio.run(_run_middleware(path, chunks=[(body, False)]))
        assert not downstream and sent[0]['status'] == 413


@pytest.mark.parametrize(('path', 'cap'), [
    ('/telemetry/web', 65_536),
    ('/telemetry/dns', 16_384),
])
def test_telemetry_body_limits_are_unchanged(path, cap):
    exact, sent, _ = asyncio.run(_run_middleware(path, chunks=[(b't' * cap, False)]))
    assert exact and not sent
    downstream, sent, _ = asyncio.run(_run_middleware(path, chunks=[(b't' * (cap + 1), False)]))
    assert not downstream and sent[0]['status'] == 413


def test_middleware_accepts_four_concurrent_maximum_sized_result_bodies():
    async def run_all():
        async def run_one():
            body = bytes(bytearray(b'z' * TASK_RESULT_BODY_MAX_BYTES))
            downstream, sent, _ = await _run_middleware(
                f'/sensor/tasks/{TASK_ID}/result', chunks=[(body, False)],
            )
            assert not sent
            assert sum(len(item['body']) for item in downstream) == TASK_RESULT_BODY_MAX_BYTES

        await asyncio.gather(*(run_one() for _ in range(4)))

    asyncio.run(run_all())
