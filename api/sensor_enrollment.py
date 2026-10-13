"""Bounded machine registration and identity routes; no execution transport."""
import ipaddress
from collections.abc import Callable
from uuid import UUID

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.routing import APIRoute
from pydantic import BaseModel, ConfigDict, Field, SecretStr

from database.remote_sensors import RemoteSensorStore
from services.remote_sensor_models import (
    Capability, RemoteSensorAuthError, RemoteSensorConflictError, RemoteSensorError,
)


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

    def authenticate(request: Request):
        authorization = request.headers.get('authorization', '')
        scheme, _, credential = authorization.partition(' ')
        sensor_uuid = request.headers.get('x-sensor-uuid', '')
        if (scheme.lower() != 'bearer' or not 40 <= len(credential) <= 128
                or len(request.headers.getlist('authorization')) != 1
                or len(request.headers.getlist('x-sensor-uuid')) != 1):
            raise HTTPException(401, 'Sensor credential rejected.', headers={'WWW-Authenticate': 'Bearer'})
        store = store_provider()
        try:
            sensor = store.authenticate_sensor(sensor_uuid, credential)
        except RemoteSensorAuthError as exc:
            raise HTTPException(401, 'Sensor credential rejected.', headers={'WWW-Authenticate': 'Bearer'}) from exc
        return store, sensor, credential

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
