"""Typed remote task APIs. No user-supplied command or scan target is accepted."""
from datetime import datetime, timezone
from hashlib import sha256
import ipaddress
import json
from typing import Annotated, Literal

from fastapi import Depends, FastAPI, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field, StrictStr

from api.sensor_enrollment import (
    MachineRoute, authenticate_sensor_request, machine_transport,
)
from database.remote_tasks import RemoteTaskError, RemoteTaskStore
from database.remote_sensors import RemoteSensorStore
from services.device_inventory import DeviceInventoryService
from services.remote_sensor_models import RemoteSensorError
from services.scan_models import HostDiscoveryResult, ScanResult
from services.service_inventory import ServiceInventoryService
from services.service_models import (
    PortObservation, ServiceDiscoveryResult, ServiceObservation,
)
from services.scanner_adapters.nmap_adapter import _service_confidence


class TaskInput(BaseModel):
    model_config = ConfigDict(extra='forbid')


class HostResultInput(TaskInput):
    ip_address: StrictStr = Field(min_length=7, max_length=15)
    mac_address: StrictStr | None = Field(default=None, max_length=17)
    hostname: StrictStr | None = Field(default=None, max_length=253)
    vendor: StrictStr | None = Field(default=None, max_length=128)


class NetworkResult(TaskInput):
    task_type: Literal['DISCOVER_NETWORK']
    observations: list[HostResultInput] = Field(max_length=254)


class PortResultInput(TaskInput):
    port: int = Field(ge=1, le=65535, strict=True)


class ServiceResultInput(TaskInput):
    port: int = Field(ge=1, le=65535, strict=True)
    service_name: StrictStr | None = Field(default=None, max_length=128)
    product: StrictStr | None = Field(default=None, max_length=128)
    version: StrictStr | None = Field(default=None, max_length=128)
    extra_info: StrictStr | None = Field(default=None, max_length=128)


class ServicesResult(TaskInput):
    task_type: Literal['DISCOVER_SERVICES']
    ports: list[PortResultInput] = Field(max_length=21)
    services: list[ServiceResultInput] = Field(max_length=21)


class TaskFailure(TaskInput):
    error_code: Literal['SCANNER_TIMEOUT', 'SCANNER_FAILED', 'INVALID_RESULT']


ResultInput = Annotated[NetworkResult | ServicesResult, Field(discriminator='task_type')]


def _raise_task_error(exc: RemoteTaskError):
    raise HTTPException(exc.status_code, {'code': exc.code, 'detail': str(exc)}) from exc


def _task_store(sensor_store):
    return RemoteTaskStore(sensor_store)


def _machine_task(task):
    if task is None:
        return None
    return {key: task[key] for key in (
        'id', 'sensor_uuid', 'scope_id', 'scope_type', 'task_type', 'status',
        'scope_cidr', 'target_ip', 'network_id', 'target_device_id', 'expires_at',
        'claimed_at', 'started_at', 'attempt_count',
    ) if key in task}


def register_remote_task_routes(app: FastAPI, store_provider):
    def route(path, method, status_code=200):
        def register(endpoint):
            app.router.add_api_route(path, endpoint, methods=[method], status_code=status_code,
                                     tags=['remote-sensor-tasks'], dependencies=[Depends(machine_transport)],
                                     route_class_override=MachineRoute)
            return endpoint
        return register

    def auth(request: Request):
        return authenticate_sensor_request(request, store_provider)

    @route('/sensor/tasks/claim', 'POST')
    def claim(authenticated=Depends(auth)):
        store, sensor, _ = authenticated
        try:
            task = _task_store(store).claim_next(sensor['id'])
        except RemoteTaskError as exc:
            _raise_task_error(exc)
        return {'task': _machine_task(task)}

    @route('/sensor/tasks/{task_id}/start', 'POST')
    def start(task_id: str, authenticated=Depends(auth)):
        store, sensor, _ = authenticated
        try:
            return _machine_task(_task_store(store).transition(sensor['id'], task_id, 'start'))
        except RemoteTaskError as exc:
            _raise_task_error(exc)

    @route('/sensor/tasks/{task_id}/fail', 'POST')
    def fail(task_id: str, body: TaskFailure, authenticated=Depends(auth)):
        store, sensor, _ = authenticated
        try:
            return _machine_task(_task_store(store).fail(sensor['id'], task_id, body.error_code))
        except RemoteTaskError as exc:
            _raise_task_error(exc)

    @route('/sensor/tasks/{task_id}/result', 'POST')
    def submit_result(task_id: str, body: ResultInput, authenticated=Depends(auth)):
        store, sensor, _ = authenticated
        canonical = json.dumps(body.model_dump(mode='json'), sort_keys=True, separators=(',', ':'))
        digest = sha256(canonical.encode()).hexdigest()
        task_store = _task_store(store)
        try:
            task = task_store.begin_result(sensor['id'], task_id, body.task_type, digest)
        except RemoteTaskError as exc:
            _raise_task_error(exc)
        now = store._now()
        provenance = f"remote-sensor:{task['sensor_uuid']}:task:{task['id']}"
        try:
            if isinstance(body, NetworkResult):
                cidr = ipaddress.IPv4Network(task['scope_cidr'], strict=True)
                seen = set()
                hosts = []
                for item in body.observations:
                    try:
                        address = ipaddress.IPv4Address(item.ip_address)
                    except ValueError as exc:
                        raise RemoteTaskError('RESULT_OUTSIDE_SCOPE', 'Observation is outside the assigned network.', 400) from exc
                    if (str(address) != item.ip_address or address not in cidr
                            or address in {cidr.network_address, cidr.broadcast_address}
                            or item.ip_address in seen):
                        raise RemoteTaskError('RESULT_OUTSIDE_SCOPE', 'Observation is outside the assigned network.', 400)
                    seen.add(item.ip_address)
                    hosts.append(HostDiscoveryResult(
                        ip_address=item.ip_address, mac_address=item.mac_address,
                        hostname=item.hostname, vendor=item.vendor, discovered_at=now,
                        source=provenance,
                    ))
                scan = ScanResult(target_network=task['scope_cidr'], scanner='remote-sensor',
                                  started_at=datetime.fromisoformat(task['started_at']), completed_at=now,
                                  hosts=tuple(hosts))
                devices = DeviceInventoryService(store.db_path).process_scan(task['network'], scan)
                result_summary = {'device_count': len(devices)}
            else:
                target_ip = task['target_ip']
                ports_seen = set()
                ports = []
                for item in body.ports:
                    if item.port in ports_seen:
                        raise RemoteTaskError('INVALID_RESULT', 'Duplicate port result.', 400)
                    ports_seen.add(item.port)
                    ports.append(PortObservation(target_ip, item.port, 'tcp', 'open', now, provenance))
                service_ports = set()
                services = []
                for item in body.services:
                    if item.port not in ports_seen or item.port in service_ports:
                        raise RemoteTaskError('INVALID_RESULT', 'Service evidence must match one observed port.', 400)
                    service_ports.add(item.port)
                    confidence = _service_confidence(item.service_name, item.product, item.version, item.extra_info)
                    services.append(ServiceObservation(
                        target_ip, item.port, 'tcp', item.service_name, item.product, item.version,
                        item.extra_info, confidence, now, provenance,
                    ))
                service_result = ServiceDiscoveryResult(
                    target_ip=target_ip, scanner='remote-sensor',
                    started_at=datetime.fromisoformat(task['started_at']), completed_at=now,
                    ports=tuple(ports), services=tuple(services),
                )
                persisted = ServiceInventoryService(store.db_path).process_result(
                    task['network'], task['device'], service_result)
                result_summary = {'port_count': len(persisted['ports']), 'service_count': len(persisted['services'])}
            task_store.finish_result(task_id, digest)
            return {'task_id': task_id, 'status': 'COMPLETED', **result_summary}
        except RemoteTaskError as exc:
            task_store.finish_result(task_id, digest, error_code=exc.code)
            _raise_task_error(exc)
        except (ValueError, TypeError, RemoteSensorError) as exc:
            task_store.finish_result(task_id, digest, error_code='INVALID_RESULT')
            raise HTTPException(400, {'code': 'INVALID_RESULT', 'detail': 'Result could not be safely ingested.'}) from exc
        except Exception as exc:
            task_store.finish_result(task_id, digest, error_code='INVALID_RESULT')
            raise HTTPException(400, {'code': 'INVALID_RESULT', 'detail': 'Result could not be safely ingested.'}) from exc
