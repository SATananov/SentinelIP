"""Direct-loopback management, separate from machine enrollment/authentication."""
import ipaddress
from collections.abc import Callable
from typing import Literal

from fastapi import FastAPI, Depends, HTTPException, Query, Request, Response
from pydantic import BaseModel, ConfigDict, Field, StrictBool

from database.remote_sensors import RemoteSensorStore
from database.remote_tasks import RemoteTaskError, RemoteTaskStore
from services.remote_sensor_models import RemoteSensorError


class SiteCreate(BaseModel):
    model_config = ConfigDict(extra='forbid')
    name: str = Field(min_length=1, max_length=128)
    description: str = Field(default='', max_length=1000)
    enabled: StrictBool = True


class EnabledUpdate(BaseModel):
    model_config = ConfigDict(extra='forbid')
    enabled: StrictBool


class EnrollmentCreate(BaseModel):
    model_config = ConfigDict(extra='forbid')
    ttl_seconds: int = Field(default=900, ge=60, le=3600, strict=True)


class AssignmentCreate(BaseModel):
    model_config = ConfigDict(extra='forbid')
    scope_id: int = Field(gt=0, strict=True)


def local_management(request: Request, response: Response):
    """Local operator boundary, not user authentication. Never trust proxy headers."""
    response.headers['Cache-Control'] = 'no-store'
    try:
        local = request.client is not None and ipaddress.ip_address(request.client.host).is_loopback
    except ValueError:
        local = False
    if (request.headers.get('authorization') is not None
            or request.headers.get('x-sensor-uuid') is not None
            or request.headers.get('x-sentinelip-sensor-id') is not None
            or request.headers.get('x-sentinelip-sensor-token') is not None
            or not local or request.url.hostname not in {'localhost', '127.0.0.1', '::1'}
            or any(h in request.headers for h in ('forwarded', 'x-forwarded-for', 'x-forwarded-host'))
            or request.headers.get('origin') not in (None, 'http://localhost:5173', 'http://127.0.0.1:5173')):
        raise HTTPException(403, 'Remote sensor management requires direct local operator access.')


def register_remote_routes(app: FastAPI, store_provider: Callable[[], RemoteSensorStore]):
    # Register flat routes, matching the existing app's route-inspection contract.
    def route(path, *, method, status_code=200):
        return app.api_route(
            path, methods=[method], status_code=status_code,
            tags=['remote-sensor-foundation'], dependencies=[Depends(local_management)],
        )

    def call(method, *args, **kwargs):
        try:
            return getattr(store_provider(), method)(*args, **kwargs)
        except RemoteSensorError as exc:
            raise HTTPException(400, str(exc)) from exc

    def create_task(sensor_id, scope_id, task_type, device_id=None):
        try:
            return RemoteTaskStore(store_provider()).create_task(
                sensor_id, scope_id, task_type, device_id=device_id
            )
        except RemoteTaskError as exc:
            raise HTTPException(exc.status_code, {'code': exc.code, 'detail': str(exc)}) from exc

    @route('/sites', method='POST', status_code=201)
    def create_site(body: SiteCreate):
        return call('create_site', **body.model_dump())

    @route('/sites', method='GET')
    def list_sites(limit: int = Query(100, ge=1, le=100), offset: int = Query(0, ge=0)):
        return call('list_sites', limit, offset)

    @route('/sites/{site_id}', method='GET')
    def get_site(site_id: int):
        return call('get_site', site_id)

    @route('/sites/{site_id}', method='PATCH')
    def update_site(site_id: int, body: EnabledUpdate):
        return call('set_site_enabled', site_id, body.enabled)

    @route('/sites/{site_id}/sensor-enrollments', method='POST', status_code=201)
    def create_enrollment(site_id: int, body: EnrollmentCreate):
        issued = call('create_enrollment', site_id, body.ttl_seconds)
        return {**issued.record, 'token': issued.secret}

    @route('/sites/{site_id}/sensor-enrollments', method='GET')
    def list_enrollments(site_id: int, limit: int = Query(100, ge=1, le=100), offset: int = Query(0, ge=0)):
        return call('list_enrollments', site_id, limit, offset)

    @route('/sensor-enrollments/{enrollment_id}', method='DELETE')
    def revoke_enrollment(enrollment_id: int):
        return call('revoke_enrollment', enrollment_id)

    @route('/sites/{site_id}/sensors', method='GET')
    def list_sensors(site_id: int, limit: int = Query(100, ge=1, le=100), offset: int = Query(0, ge=0)):
        return call('list_sensors', site_id, limit, offset)

    @route('/sites/{site_id}/eligible-sensor-scopes', method='GET')
    def eligible_sensor_scopes(
        site_id: int,
        sensor_id: int = Query(gt=0),
        limit: int = Query(100, ge=1, le=100),
        offset: int = Query(0, ge=0, le=100000),
    ):
        try:
            return store_provider().list_eligible_assignment_scopes(
                site_id, sensor_id, limit=limit, offset=offset,
            )
        except LookupError as exc:
            raise HTTPException(404, str(exc)) from exc
        except RemoteSensorError as exc:
            raise HTTPException(400, str(exc)) from exc

    @route('/sensors', method='GET')
    def list_fleet_sensors(
        limit: int = Query(100, ge=1, le=100),
        offset: int = Query(0, ge=0, le=100000),
        site_id: int | None = Query(default=None, ge=1),
        status: Literal['REVOKED', 'DISABLED', 'PENDING', 'ONLINE', 'OFFLINE', 'UNKNOWN'] | None = None,
        platform: str | None = Query(default=None, min_length=1, max_length=64),
        enabled: Literal['true', 'false'] | None = None,
    ):
        try:
            return store_provider().list_fleet_sensors(
                limit=limit, offset=offset, site_id=site_id, status=status,
                platform=platform, enabled=None if enabled is None else enabled == 'true',
            )
        except LookupError as exc:
            raise HTTPException(404, str(exc)) from exc
        except RemoteSensorError as exc:
            raise HTTPException(400, str(exc)) from exc

    @route('/sensors/{sensor_id}', method='GET')
    def get_sensor(sensor_id: int):
        return call('get_sensor', sensor_id)

    @route('/sensors/{sensor_id}', method='PATCH')
    def update_sensor(sensor_id: int, body: EnabledUpdate):
        return call('set_sensor_enabled', sensor_id, body.enabled)

    @route('/sensors/{sensor_id}/credential', method='DELETE')
    def revoke_sensor(sensor_id: int):
        return call('revoke_sensor', sensor_id)

    @route('/sensors/{sensor_id}/scope-assignments', method='POST')
    def assign(sensor_id: int, body: AssignmentCreate):
        return call('assign_scope', sensor_id, body.scope_id)

    @route('/sensors/{sensor_id}/scope-assignments', method='GET')
    def assignments(sensor_id: int, limit: int = Query(100, ge=1, le=100), offset: int = Query(0, ge=0)):
        return call('list_assignments', sensor_id, limit, offset)

    @route('/sensors/{sensor_id}/scope-assignments/{scope_id}', method='DELETE', status_code=204)
    def unassign(sensor_id: int, scope_id: int):
        call('remove_assignment', sensor_id, scope_id)
        return Response(status_code=204, headers={'Cache-Control': 'no-store'})

    class NetworkTaskCreate(BaseModel):
        model_config = ConfigDict(extra='forbid')
        scope_id: int = Field(gt=0, strict=True)

    class ServiceTaskCreate(BaseModel):
        model_config = ConfigDict(extra='forbid')
        scope_id: int = Field(gt=0, strict=True)
        device_id: int = Field(gt=0, strict=True)

    @route('/sensors/{sensor_id}/tasks/discover-network', method='POST', status_code=201)
    def create_network_task(sensor_id: int, body: NetworkTaskCreate):
        return create_task(sensor_id, body.scope_id, 'DISCOVER_NETWORK')

    @route('/sensors/{sensor_id}/tasks/discover-services', method='POST', status_code=201)
    def create_service_task(sensor_id: int, body: ServiceTaskCreate):
        return create_task(sensor_id, body.scope_id, 'DISCOVER_SERVICES', body.device_id)

