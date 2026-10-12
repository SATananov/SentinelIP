from collections.abc import Mapping

from database import services as services_db
from database.db import DB_PATH
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
from services.target_policy import validate_cidr


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
    ) -> dict[str, list[dict]]:
        return self._process_result(*_context(network, device), result)

    def process_public_result(
        self,
        scope: Mapping[str, object],
        device: Mapping[str, object],
        result: ServiceDiscoveryResult,
    ) -> dict[str, list[dict]]:
        return self._process_result(*_public_context(scope, device), result)

    def _process_result(
        self,
        network_id: int | None,
        device_id: int,
        target_ip: str,
        result: ServiceDiscoveryResult,
    ) -> dict[str, list[dict]]:

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

        port_keys = {
            (port.port, port.transport)
            for port in result.ports
        }

        for port in result.ports:
            if not isinstance(port, PortObservation):
                raise ServiceInventoryError("Invalid port observation.")

            if port.ip_address != target_ip:
                raise ServiceInventoryError("Port target does not match device.")

        for service in result.services:
            if not isinstance(service, ServiceObservation):
                raise ServiceInventoryError("Invalid service observation.")

            if service.ip_address != target_ip:
                raise ServiceInventoryError("Service target does not match device.")

            if (service.port, service.transport) not in port_keys:
                raise ServiceInventoryError(
                    "Service evidence must refer to an observed port."
                )

        ports = []
        port_records = {}

        for port in result.ports:
            observed_at = port.observed_at.isoformat(timespec="seconds")
            previous = services_db.find_port(
                device_id=device_id,
                port_number=port.port,
                transport=port.transport,
                db_path=self.db_path,
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
                    )
                record = services_db.update_port(
                    port_id=previous["id"],
                    last_seen=observed_at,
                    state=port.state,
                    db_path=self.db_path,
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
            )
            port_records[(port.port, port.transport)] = record
            ports.append(record)

        services = []

        for service in result.services:
            evidence = service.normalized_evidence()

            if not has_service_evidence(evidence):
                continue

            port_record = port_records[(service.port, service.transport)]
            observed_at = service.observed_at.isoformat(timespec="seconds")
            previous = services_db.find_service_by_port(
                port_id=port_record["id"],
                db_path=self.db_path,
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
            )
            services.append(record)

        return {"ports": ports, "services": services}
