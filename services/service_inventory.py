from collections.abc import Mapping
import sqlite3

from database import services as services_db
from database import scopes as scopes_db
from database.db import DB_PATH, get_connection, initialize_database
from services.change_detection import (
    persist_changes,
    port_observation_changes,
    service_observation_changes,
)
from services.scan_models import normalize_ipv4
from services.service_fingerprint import has_service_evidence
from services.service_models import (
    PortObservation,
    ServiceDiscoveryResult,
    ServiceObservation,
)
from services.scope_authorization import ScopeAuthorizationError, require_public_ipv4_scope
from services.scope_authorization import require_hostname_scope
from services.target_policy import validate_cidr
from services.external_exposure_service import ExternalExposureService


class ServiceInventoryError(ValueError):
    """Raised when service observations cannot be persisted safely."""


def _public_context(scope: Mapping[str, object], device: Mapping[str, object]):
    if not isinstance(scope, Mapping) or not isinstance(device, Mapping):
        raise ServiceInventoryError("A stored public scope and device are required.")
    try:
        target_ip = require_public_ipv4_scope(scope)
    except ScopeAuthorizationError as exc:
        raise ServiceInventoryError(str(exc)) from exc
    if device.get("network_id") is not None or device.get("scope_id") != scope.get("id"):
        raise ServiceInventoryError("The device does not belong to the public scope.")
    if device.get("last_ip_address") != target_ip:
        raise ServiceInventoryError("The device target does not match the scope.")
    if type(device.get("id")) is not int:
        raise ServiceInventoryError("Device ID is invalid.")
    return None, device["id"], target_ip


def _context(
    network: Mapping[str, object],
    device: Mapping[str, object],
) -> tuple[int, int, str]:
    if not isinstance(network, Mapping) or not isinstance(device, Mapping):
        raise ServiceInventoryError("Stored network and device records are required.")

    if network.get("authorized") is not True:
        raise ServiceInventoryError("The network is not authorized.")

    if network.get("enabled") is not True:
        raise ServiceInventoryError("The network is disabled.")

    network_id = network.get("id")
    device_id = device.get("id")
    device_network_id = device.get("network_id")
    cidr = network.get("cidr")
    target_ip = device.get("last_ip_address")

    if not all(
        isinstance(value, int) and not isinstance(value, bool)
        for value in (network_id, device_id, device_network_id)
    ):
        raise ServiceInventoryError("Network and device IDs are invalid.")

    if network_id != device_network_id:
        raise ServiceInventoryError("The device does not belong to the network.")

    if not isinstance(cidr, str) or not isinstance(target_ip, str):
        raise ServiceInventoryError("Network and device targets are invalid.")

    normalized_cidr = validate_cidr(cidr).cidr
    normalized_ip = normalize_ipv4(target_ip)

    return network_id, device_id, normalized_ip


class ServiceInventoryService:
    def __init__(self, db_path=DB_PATH):
        self.db_path = db_path

    def process_result(
        self,
        network: Mapping[str, object],
        device: Mapping[str, object],
        result: ServiceDiscoveryResult,
        conn: sqlite3.Connection | None = None,
    ) -> dict[str, list[dict]]:
        return self._process_result(*_context(network, device), result, conn=conn)

    def process_public_result(
        self,
        scope: Mapping[str, object],
        device: Mapping[str, object],
        result: ServiceDiscoveryResult,
    ) -> dict[str, list[dict]]:
        inventory = self._process_result(*_public_context(scope, device), result)
        inventory["external_exposures"] = ExternalExposureService(self.db_path).record_service_scan(
            scope, device, result
        )
        return inventory

    def process_cidr_result(self, scope, device, result):
        if not isinstance(scope, Mapping) or not isinstance(device, Mapping):
            raise ServiceInventoryError("A persisted CIDR scope and device are required.")
        addresses = scopes_db.require_cidr_membership(scope, self.db_path)
        if (device.get("scope_id") != scope.get("id")
            or device.get("network_id") is not None
            or type(device.get("id")) is not int
            or device["id"] <= 0
            or device.get("last_ip_address") not in addresses):
            raise ServiceInventoryError("The device is outside the authorized CIDR scope.")
        inventory = self._process_result(
            None, device["id"], device["last_ip_address"], result
        )
        inventory["external_exposures"] = ExternalExposureService(self.db_path).record_service_scan(
            scope, device, result
        )
        return inventory

    def process_hostname_result(
        self,
        scope: Mapping[str, object],
        device: Mapping[str, object],
        result: ServiceDiscoveryResult,
    ) -> dict[str, list[dict]]:
        if not isinstance(scope, Mapping) or not isinstance(device, Mapping):
            raise ServiceInventoryError("A stored hostname scope and device are required.")
        try:
            require_hostname_scope(scope)
            target_ip = normalize_ipv4(device.get("last_ip_address"))
        except (ScopeAuthorizationError, ValueError) as exc:
            raise ServiceInventoryError(str(exc)) from exc
        if device.get("network_id") is not None or device.get("scope_id") != scope.get("id"):
            raise ServiceInventoryError("The device does not belong to the hostname scope.")
        if type(device.get("id")) is not int or device["id"] <= 0 or target_ip not in scopes_db.list_hostname_addresses(
            scope["id"], self.db_path
        ):
            raise ServiceInventoryError("The device address is not approved for the hostname scope.")
        inventory = self._process_result(None, device["id"], target_ip, result)
        inventory["external_exposures"] = ExternalExposureService(self.db_path).record_service_scan(
            scope, device, result
        )
        return inventory

    def _process_result(
        self,
        network_id: int | None,
        device_id: int,
        target_ip: str,
        result: ServiceDiscoveryResult,
        conn: sqlite3.Connection | None = None,
    ) -> dict[str, list[dict]]:
        services_to_persist = self._validate_result(target_ip, result)

        if conn is not None:
            return self._apply_result(
                network_id, device_id, result, services_to_persist, conn
            )

        initialize_database(self.db_path)
        connection = get_connection(self.db_path)
        connection.row_factory = sqlite3.Row
        try:
            connection.execute("BEGIN IMMEDIATE")
            inventory = self._apply_result(
                network_id, device_id, result, services_to_persist, connection
            )
            connection.commit()
            return inventory
        except BaseException:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()

    @staticmethod
    def _validate_result(target_ip: str, result: ServiceDiscoveryResult):
        if not isinstance(result, ServiceDiscoveryResult):
            raise ServiceInventoryError("A normalized service result is required.")

        if result.target_ip != target_ip:
            raise ServiceInventoryError(
                "Service result target does not match the device."
            )

        if result.errors:
            raise ServiceInventoryError(
                "Failed service results cannot update inventory."
            )

        for port in result.ports:
            if not isinstance(port, PortObservation):
                raise ServiceInventoryError("Invalid port observation.")

            if port.ip_address != target_ip:
                raise ServiceInventoryError("Port target does not match device.")

        port_keys = {(port.port, port.transport) for port in result.ports}

        services_to_persist = []
        for service in result.services:
            if not isinstance(service, ServiceObservation):
                raise ServiceInventoryError("Invalid service observation.")

            if service.ip_address != target_ip:
                raise ServiceInventoryError("Service target does not match device.")

            if (service.port, service.transport) not in port_keys:
                raise ServiceInventoryError(
                    "Service evidence must refer to an observed port."
                )

            if has_service_evidence(service.normalized_evidence()):
                services_to_persist.append(service)

        return services_to_persist

    def _apply_result(
        self,
        network_id: int | None,
        device_id: int,
        result: ServiceDiscoveryResult,
        services_to_persist: list[ServiceObservation],
        conn: sqlite3.Connection,
    ) -> dict[str, list[dict]]:

        ports = []
        port_records = {}

        for port in result.ports:
            observed_at = port.observed_at.isoformat(timespec="seconds")
            previous = services_db.find_port(
                device_id=device_id,
                port_number=port.port,
                transport=port.transport,
                db_path=self.db_path,
                conn=conn,
            )

            if previous is None:
                record = services_db.create_port(
                    device_id=device_id,
                    port_number=port.port,
                    transport=port.transport,
                    state=port.state,
                    first_seen=observed_at,
                    last_seen=observed_at,
                    db_path=self.db_path,
                    conn=conn,
                )
            else:
                current = {
                    **previous,
                    "state": port.state.upper(),
                    "last_seen": observed_at,
                }
                if network_id is not None:
                    persist_changes(
                        port_observation_changes(
                            previous=previous,
                            current=current,
                            network_id=network_id,
                            observed_at=port.observed_at,
                        ),
                        db_path=self.db_path,
                        conn=conn,
                    )
                record = services_db.update_port(
                    port_id=previous["id"],
                    last_seen=observed_at,
                    state=port.state,
                    db_path=self.db_path,
                    conn=conn,
                )

            if previous is None:
                if network_id is not None:
                    persist_changes(
                        port_observation_changes(
                            previous=None,
                            current=record,
                            network_id=network_id,
                            observed_at=port.observed_at,
                        ),
                        db_path=self.db_path,
                        conn=conn,
                    )

            services_db.save_port_observation(
                device_id=device_id,
                port_id=record["id"],
                ip_address=port.ip_address,
                port_number=port.port,
                transport=port.transport,
                state=port.state,
                observed_at=observed_at,
                source=port.source,
                db_path=self.db_path,
                conn=conn,
            )
            port_records[(port.port, port.transport)] = record
            ports.append(record)

        services = []

        for service in services_to_persist:
            port_record = port_records[(service.port, service.transport)]
            observed_at = service.observed_at.isoformat(timespec="seconds")
            previous = services_db.find_service_by_port(
                port_id=port_record["id"],
                db_path=self.db_path,
                conn=conn,
            )

            if previous is None:
                record = services_db.create_service(
                    device_id=device_id,
                    port_id=port_record["id"],
                    service_name=service.service_name,
                    product=service.product,
                    version=service.version,
                    extra_info=service.extra_info,
                    confidence=service.confidence,
                    first_seen=observed_at,
                    last_seen=observed_at,
                    db_path=self.db_path,
                    conn=conn,
                )
            else:
                current = {
                    **previous,
                    "service_name": service.service_name or previous["service_name"],
                    "product": service.product or previous["product"],
                    "version": service.version or previous["version"],
                    "extra_info": service.extra_info or previous["extra_info"],
                    "confidence": service.confidence,
                    "last_seen": observed_at,
                }
                if network_id is not None:
                    persist_changes(
                        service_observation_changes(
                            previous=previous,
                            current=current,
                            network_id=network_id,
                            observed_at=service.observed_at,
                        ),
                        db_path=self.db_path,
                        conn=conn,
                    )
                record = services_db.update_service(
                    service_id=previous["id"],
                    service_name=service.service_name,
                    product=service.product,
                    version=service.version,
                    extra_info=service.extra_info,
                    confidence=service.confidence,
                    last_seen=observed_at,
                    db_path=self.db_path,
                    conn=conn,
                )

            if previous is None:
                if network_id is not None:
                    persist_changes(
                        service_observation_changes(
                            previous=None,
                            current=record,
                            network_id=network_id,
                            observed_at=service.observed_at,
                        ),
                        db_path=self.db_path,
                        conn=conn,
                    )

            services_db.save_service_observation(
                service_id=record["id"],
                device_id=device_id,
                port_id=port_record["id"],
                service_name=service.service_name,
                product=service.product,
                version=service.version,
                extra_info=service.extra_info,
                confidence=service.confidence,
                observed_at=observed_at,
                source=service.source,
                db_path=self.db_path,
                conn=conn,
            )
            services.append(record)

        return {"ports": ports, "services": services}
