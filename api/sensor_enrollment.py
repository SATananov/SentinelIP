"""Bounded machine registration and identity routes; no execution transport."""
import ipaddress
import json
import re
from collections.abc import Callable
from uuid import UUID

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.routing import APIRoute
from pydantic import BaseModel, ConfigDict, Field, SecretStr
from starlette.routing import get_route_path

from database.remote_sensors import RemoteSensorStore
from services.remote_sensor_models import (
    Capability, RemoteSensorAuthError, RemoteSensorCapacityError,
    RemoteSensorConflictError, RemoteSensorError, RemoteSensorRateLimitError,
    RemoteSensorReplayError,
)

MAX_SENSOR_BODY_BYTES = 16 * 1024
# Derived from the maximum valid task-result model; reconcile model maxima before reducing.
TASK_RESULT_BODY_MAX_BYTES = 1_310_720
MAX_WEB_TELEMETRY_BODY_BYTES = 65_536
MAX_DNS_TELEMETRY_BODY_BYTES = 16_384
TELEMETRY_BODY_LIMITS = {
    '/telemetry/web': MAX_WEB_TELEMETRY_BODY_BYTES,
    '/telemetry/dns': MAX_DNS_TELEMETRY_BODY_BYTES,
}
TELEMETRY_BODY_TOO_LARGE_DETAIL = 'Telemetry request exceeds the allowed size.'
TASK_RESULT_BODY_TOO_LARGE_DETAIL = 'Task result request body exceeds 1310720 bytes.'
_TIMESTAMP_PATTERN = re.compile(r'^[0-9]{10}$')


def _is_task_result_request(scope) -> bool:
    """Match the task-result route shape without narrowing its string path parameter."""
    if scope.get('method') != 'POST':
        return False
    path = get_route_path(scope)
    # Starlette strips trailing slashes before redirecting to this route; apply
    # the same body bound before that redirect so a valid result is not rejected.
    path = path.rstrip('/') or '/'
    parts = path.split('/')
    if len(parts) != 5 or parts[1:3] != ['sensor', 'tasks'] or parts[4] != 'result':
        return False
    return bool(parts[3])


class MachineMetadata(BaseModel):
    model_config = ConfigDict(extra='forbid')
    platform: str = Field(min_length=1, max_length=64)
    version: str = Field(min_length=1, max_length=64)
    capabilities: list[Capability] = Field(default_factory=list, max_length=4)


class Registration(MachineMetadata):
    enrollment_token: SecretStr = Field(min_length=40, max_length=128)
    sensor_uuid: UUID
    sensor_name: str = Field(min_length=1, max_length=128)


class MachineRoute(APIRoute):
    def get_route_handler(self):
        handler = super().get_route_handler()

        async def protected(request: Request):
            try:
                response = await handler(request)
            except RequestValidationError:
                # Validation errors must never echo a credential or raw request body.
                response = JSONResponse({'detail': 'Invalid machine request.'}, status_code=422)
            except HTTPException as exc:
                response = JSONResponse({'detail': exc.detail}, status_code=exc.status_code, headers=exc.headers)
            response.headers['Cache-Control'] = 'no-store'
            return response
        return protected


class SensorBodyLimitMiddleware:
    """Bound machine request bodies before JSON validation or credential work."""
    def __init__(self, app, max_bytes=MAX_SENSOR_BODY_BYTES):
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope, receive, send):
        if scope['type'] != 'http':
            await self.app(scope, receive, send)
            return
        path = get_route_path(scope)
        telemetry_limit = TELEMETRY_BODY_LIMITS.get(path)
        if telemetry_limit is not None:
            max_bytes = telemetry_limit
            too_large_detail = TELEMETRY_BODY_TOO_LARGE_DETAIL
        elif _is_task_result_request(scope):
            max_bytes = TASK_RESULT_BODY_MAX_BYTES
            too_large_detail = TASK_RESULT_BODY_TOO_LARGE_DETAIL
        elif path.startswith('/sensor/') or path == '/sensor-enrollment/register':
            max_bytes = self.max_bytes
            # Preserve the existing /sensor/* response contract exactly.
            too_large_detail = 'Sensor request body exceeds 16384 bytes.'
        else:
            await self.app(scope, receive, send)
            return
        headers = dict(scope.get('headers', ()))
        raw_length = headers.get(b'content-length')
        if raw_length is not None:
            try:
                if int(raw_length) > max_bytes or int(raw_length) < 0:
                    await self._too_large(send, too_large_detail)
                    return
            except ValueError:
                await self._too_large(send, too_large_detail)
                return
        request_messages = []
        size = 0
        while True:
            message = await receive()
            if message['type'] == 'http.disconnect':
                return
            chunk = message.get('body', b'')
            size += len(chunk)
            if size > max_bytes:
                await self._too_large(send, too_large_detail)
                return
            request_messages.append(dict(message))
            if not message.get('more_body', False):
                break
        replay_index = 0
        async def replay_receive():
            nonlocal replay_index
            if replay_index >= len(request_messages):
                return {'type': 'http.request', 'body': b'', 'more_body': False}
            message = request_messages[replay_index]
            replay_index += 1
            return message
        await self.app(scope, replay_receive, send)

    @staticmethod
    async def _too_large(send, detail):
        body = json.dumps({'detail': detail}).encode()
        await send({'type': 'http.response.start', 'status': 413, 'headers': [
            (b'content-type', b'application/json'), (b'content-length', str(len(body)).encode()),
            (b'cache-control', b'no-store'),
        ]})
        await send({'type': 'http.response.body', 'body': body})


def machine_transport(request: Request):
    try:
        loopback = request.client is not None and ipaddress.ip_address(request.client.host).is_loopback
    except ValueError:
        loopback = False
    if (request.headers.get('origin') is not None
            or any(h in request.headers for h in ('forwarded', 'x-forwarded-for', 'x-forwarded-host', 'x-forwarded-proto'))
            or (request.url.scheme != 'https' and not (
                loopback and request.url.hostname in {'localhost', '127.0.0.1', '::1'}))):
        raise HTTPException(403, 'Machine endpoints require HTTPS or direct loopback access.')
    if request.query_params:
        raise HTTPException(400, 'Machine endpoints do not accept query parameters.')


def public_identity(sensor):
    return {key: sensor[key] for key in (
        'id', 'sensor_uuid', 'site_id', 'name', 'platform', 'version', 'enabled',
        'capabilities', 'registered_at', 'last_seen_at', 'status',
    )}


def authenticate_sensor_request(request: Request, store_provider: Callable[[], RemoteSensorStore]):
    authorization = request.headers.get('authorization', '')
    scheme, _, credential = authorization.partition(' ')
    sensor_uuid = request.headers.get('x-sensor-uuid', '')
    if (scheme.lower() != 'bearer' or not 40 <= len(credential) <= 128
            or len(request.headers.getlist('authorization')) != 1
            or len(request.headers.getlist('x-sensor-uuid')) != 1):
        raise HTTPException(401, 'Sensor credential rejected.', headers={'WWW-Authenticate': 'Bearer'})
    timestamp_values = request.headers.getlist('x-sentinel-timestamp')
    nonce_values = request.headers.getlist('x-sentinel-nonce')
    if len(timestamp_values) != 1 or len(nonce_values) != 1:
        raise HTTPException(400, 'X-Sentinel-Timestamp and X-Sentinel-Nonce are required exactly once.')
    if not _TIMESTAMP_PATTERN.fullmatch(timestamp_values[0]):
        raise HTTPException(400, 'X-Sentinel-Timestamp must be a 10-digit Unix timestamp in seconds.')
    store = store_provider()
    try:
        sensor = store.authorize_transport_request(sensor_uuid, credential,
                                                   int(timestamp_values[0]), nonce_values[0])
    except RemoteSensorAuthError as exc:
        raise HTTPException(401, 'Sensor credential rejected.', headers={'WWW-Authenticate': 'Bearer'}) from exc
    except RemoteSensorReplayError as exc:
        raise HTTPException(409, 'Sensor request rejected.') from exc
    except RemoteSensorRateLimitError as exc:
        raise HTTPException(429, 'Sensor request rate limit exceeded.', headers={'Retry-After': '60'}) from exc
    except RemoteSensorCapacityError as exc:
        raise HTTPException(503, 'Sensor transport capacity is temporarily exhausted.') from exc
    except RemoteSensorError as exc:
        message = str(exc)
        status = 408 if 'outside the allowed window' in message else 400
        raise HTTPException(status, message) from exc
    return store, sensor, credential


def sensor_auth_dependency(store_provider: Callable[[], RemoteSensorStore]):
    def dependency(request: Request):
        return authenticate_sensor_request(request, store_provider)
    return dependency


def register_machine_routes(app: FastAPI, store_provider: Callable[[], RemoteSensorStore]):
    def route(path, method, status_code=200):
        def register(endpoint):
            app.router.add_api_route(
                path, endpoint, methods=[method], status_code=status_code,
                tags=['sensor-enrollment'], dependencies=[Depends(machine_transport)],
                route_class_override=MachineRoute,
            )
            return endpoint
        return register

    authenticate = sensor_auth_dependency(store_provider)

    @route('/sensor-enrollment/register', 'POST', 201)
    def register(body: Registration):
        try:
            issued = store_provider().consume_enrollment(
                body.enrollment_token.get_secret_value(), sensor_uuid=str(body.sensor_uuid),
                name=body.sensor_name, platform=body.platform, version=body.version,
                reported_capabilities=body.capabilities,
            )
        except RemoteSensorConflictError as exc:
            raise HTTPException(409, str(exc)) from exc
        except RemoteSensorError as exc:
            raise HTTPException(400, 'Registration rejected.') from exc
        return {**public_identity(issued.record), 'credential': issued.secret}

    @route('/sensor/self', 'GET')
    def self_identity(auth=Depends(authenticate)):
        _, sensor, _ = auth
        return public_identity(sensor)

    @route('/sensor/grant', 'GET')
    def current_grants(auth=Depends(authenticate)):
        store, sensor, _ = auth
        try:
            return {'grants': store.get_sensor_grants(sensor['id'])}
        except RemoteSensorAuthError as exc:
            raise HTTPException(401, 'Sensor credential rejected.', headers={'WWW-Authenticate': 'Bearer'}) from exc
        except RemoteSensorError as exc:
            raise HTTPException(409, 'Current sensor grants are unavailable.') from exc

    @route('/sensor/heartbeat', 'POST')
    def heartbeat(body: MachineMetadata, auth=Depends(authenticate)):
        store, sensor, credential = auth
        try:
            # Reauthenticate inside the write transaction to honor intervening revocation.
            updated = store.heartbeat(sensor['id'], credential, platform=body.platform,
                                      version=body.version, reported_capabilities=body.capabilities)
        except RemoteSensorAuthError as exc:
            raise HTTPException(401, 'Sensor credential rejected.', headers={'WWW-Authenticate': 'Bearer'}) from exc
        except RemoteSensorError as exc:
            raise HTTPException(400, 'Invalid heartbeat metadata.') from exc
        return public_identity(updated)
