"""Typed remote task APIs. No user-supplied command or scan target is accepted."""
from datetime import datetime, timezone
from hashlib import sha256
import ipaddress
import json
import logging
import sqlite3
from typing import Annotated, Literal

from fastapi import Depends, FastAPI, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field, StrictStr

from api.sensor_enrollment import (
    MachineRoute, authenticate_sensor_request, machine_transport,
)
from database.remote_tasks import RemoteTaskError, RemoteTaskStore
from database.remote_sensors import RemoteSensorStore
from database.db import get_connection, initialize_database
from services.device_inventory import DeviceInventoryService
from services.remote_sensor_models import RemoteSensorError
from services.scan_models import HostDiscoveryResult, ScanResult
from services.service_inventory import ServiceInventoryService
from services.service_models import (
    PortObservation, ServiceDiscoveryResult, ServiceObservation,
)
from services.scanner_adapters.nmap_adapter import _service_confidence

logger = logging.getLogger(__name__)


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
    error_code: Literal['SCANNER_TIMEOUT', 'SCANNER_FAILED', 'INVALID_RESULT', 'RESULT_TOO_LARGE']


ResultInput = Annotated[NetworkResult | ServicesResult, Field(discriminator='task_type')]


def _raise_task_error(exc: RemoteTaskError):
    raise HTTPException(exc.status_code, {'code': exc.code, 'detail': str(exc)}) from exc


def _task_store(sensor_store):
    return RemoteTaskStore(sensor_store)


def _build_inventory_input(task, body, now, provenance):
    if isinstance(body, NetworkResult):
        cidr = ipaddress.IPv4Network(task['scope_cidr'], strict=True)
        seen = set()
        hosts = []
        for item in body.observations:
            try:
                address = ipaddress.IPv4Address(item.ip_address)
            except ValueError as exc:
                raise RemoteTaskError(
                    'RESULT_OUTSIDE_SCOPE', 'Observation is outside the assigned network.', 400
                ) from exc
            if (str(address) != item.ip_address or address not in cidr
                    or address in {cidr.network_address, cidr.broadcast_address}
                    or item.ip_address in seen):
                raise RemoteTaskError(
                    'RESULT_OUTSIDE_SCOPE', 'Observation is outside the assigned network.', 400
                )
            seen.add(item.ip_address)
            hosts.append(HostDiscoveryResult(
                ip_address=item.ip_address, mac_address=item.mac_address,
                hostname=item.hostname, vendor=item.vendor, discovered_at=now,
                source=provenance,
            ))
        scan = ScanResult(
            target_network=task['scope_cidr'], scanner='remote-sensor',
            started_at=datetime.fromisoformat(task['started_at']), completed_at=now,
            hosts=tuple(hosts),
        )
        return ('device', scan)

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
            raise RemoteTaskError(
                'INVALID_RESULT', 'Service evidence must match one observed port.', 400
            )
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
    return ('service', service_result)


def _result_conflict(exc):
    return exc.code in {
        'TASK_NOT_FOUND', 'INVALID_TRANSITION', 'RESULT_CONFLICT',
        'RESULT_STATE_AMBIGUOUS',
    }


def _close_result_connection(connection, task_id):
    try:
        connection.close()
    except Exception:
        logger.error("Could not close task result connection task_id=%s", task_id)


def _rollback_result_transaction(connection, task_id):
    try:
        if connection.in_transaction:
            connection.rollback()
    except Exception:
        logger.error("Could not roll back task result transaction task_id=%s", task_id)
        _close_result_connection(connection, task_id)


def _process_task_result(store, task_store, sensor_id, task_id, body):
    canonical = json.dumps(body.model_dump(mode='json'), sort_keys=True, separators=(',', ':'))
    digest = sha256(canonical.encode()).hexdigest()
    initialize_database(store.db_path)
    connection = get_connection(store.db_path)
    connection.row_factory = sqlite3.Row
    commit_started = False
    summary = None
    task = None
    try:
        connection.execute('BEGIN IMMEDIATE')
        prepared = task_store.prepare_result_in_transaction(
            connection, sensor_id, task_id, body.task_type, digest
        )
        task = prepared['task']
        if prepared.get('expired'):
            commit_started = True
            connection.commit()
            raise HTTPException(409, {'code': 'TASK_EXPIRED', 'detail': 'Task expired.'})
        if prepared['duplicate']:
            connection.rollback()
            logger.info("Acknowledged duplicate completed task result task_id=%s", task_id)
            return {'task_id': task_id, 'status': 'COMPLETED', 'duplicate': True}

        now = store._now()
        provenance = f"remote-sensor:{task['sensor_uuid']}:task:{task['id']}"
        try:
            kind, inventory_input = _build_inventory_input(task, body, now, provenance)
        except RemoteTaskError:
            raise
        except (ValueError, TypeError, RemoteSensorError) as exc:
            raise RemoteTaskError(
                'INVALID_RESULT', 'Result could not be safely ingested.', 400
            ) from exc

        task_store.reserve_result_in_transaction(connection, task_id, digest)
        if kind == 'device':
            devices = DeviceInventoryService(store.db_path).process_scan(
                task['network'], inventory_input, conn=connection
            )
            summary = {'device_count': len(devices)}
        else:
            persisted = ServiceInventoryService(store.db_path).process_result(
                task['network'], task['device'], inventory_input, conn=connection
            )
            summary = {
                'port_count': len(persisted['ports']),
                'service_count': len(persisted['services']),
            }
        task_store.complete_result_in_transaction(connection, task_id, digest)
        commit_started = True
        connection.commit()
        return {'task_id': task_id, 'status': 'COMPLETED', **summary}
    except HTTPException:
        raise
    except RemoteTaskError as exc:
        _rollback_result_transaction(connection, task_id)
        if _result_conflict(exc):
            logger.warning("Rejected conflicting task result task_id=%s code=%s", task_id, exc.code)
        if not _result_conflict(exc) and 400 <= exc.status_code < 500:
            task_store.fail_result_permanently(sensor_id, task_id, exc.code)
        raise HTTPException(exc.status_code, {'code': exc.code, 'detail': str(exc)}) from exc
    except (ValueError, TypeError, RemoteSensorError) as exc:
        _rollback_result_transaction(connection, task_id)
        task_store.fail_result_permanently(sensor_id, task_id, 'INVALID_RESULT')
        raise HTTPException(
            400, {'code': 'INVALID_RESULT', 'detail': 'Result could not be safely ingested.'}
        ) from exc
    except Exception as exc:
        _rollback_result_transaction(connection, task_id)
        logger.error("Rolled back transient task result failure task_id=%s", task_id)
        if commit_started:
            _close_result_connection(connection, task_id)
            try:
                with task_store.sensors._connection() as fresh:
                    row = fresh.execute(
                        'SELECT status,result_digest FROM remote_sensor_tasks WHERE id=? AND sensor_id=?',
                        (task_id, sensor_id),
                    ).fetchone()
            except Exception:
                row = None
            if row is not None and row['status'] == 'COMPLETED' and row['result_digest'] == digest:
                return {'task_id': task_id, 'status': 'COMPLETED', **(summary or {}), 'duplicate': True}
            if row is not None and row['status'] == 'RUNNING' and row['result_digest'] is None:
                raise HTTPException(
                    503, {'code': 'RESULT_RETRYABLE', 'detail': 'Result was not committed; retry it.'}
                ) from exc
            raise HTTPException(
                503, {'code': 'RESULT_STATE_AMBIGUOUS', 'detail': 'Result commit state could not be confirmed.'}
            ) from exc
        raise HTTPException(
            503, {'code': 'RESULT_RETRYABLE', 'detail': 'Result processing failed; retry it.'}
        ) from exc
    finally:
        _close_result_connection(connection, task_id)


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
        task_store = _task_store(store)
        try:
            return _process_task_result(store, task_store, sensor['id'], task_id, body)
        except RemoteTaskError as exc:
            _raise_task_error(exc)
