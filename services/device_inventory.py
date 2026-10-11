from collections.abc import Mapping
from dataclasses import dataclass

from database import inventory as inventory_db
from database.db import DB_PATH
from services.change_detection import (
    device_disappearance_change,
    device_observation_changes,
    persist_changes,
)
from services.scan_models import HostDiscoveryResult, ScanResult
from services.target_policy import validate_cidr


class DeviceInventoryError(ValueError):
    """Raised when normalized inventory input cannot be processed."""


@dataclass(frozen=True)
class DeviceIdentity:
    stable_key: str
    confidence: str


def resolve_device_identity(
    network_id: int,
    host: HostDiscoveryResult,
) -> DeviceIdentity:
    if not isinstance(network_id, int) or isinstance(network_id, bool):
        raise DeviceInventoryError("Network ID must be an integer.")

    if host.mac_address is not None:
        return DeviceIdentity(
            stable_key=(
                f"network:{network_id}:mac:{host.mac_address}"
            ),
            confidence="HIGH",
        )

    if host.hostname is not None:
        return DeviceIdentity(
            stable_key=(
                f"network:{network_id}:ip:{host.ip_address}"
                f":hostname:{host.hostname.casefold()}"
            ),
            confidence="MEDIUM",
        )

    return DeviceIdentity(
        stable_key=f"network:{network_id}:ip:{host.ip_address}",
        confidence="LOW",
    )


def _network_details(network: Mapping[str, object]) -> tuple[int, str]:
    if not isinstance(network, Mapping):
        raise DeviceInventoryError("A stored network record is required.")

    if network.get("authorized") is not True:
        raise DeviceInventoryError("The network is not authorized.")

    if network.get("enabled") is not True:
        raise DeviceInventoryError("The network is disabled.")

    network_id = network.get("id")
    cidr = network.get("cidr")

    if not isinstance(network_id, int) or isinstance(network_id, bool):
        raise DeviceInventoryError("Network record has an invalid ID.")

    if not isinstance(cidr, str):
        raise DeviceInventoryError("Network record has an invalid CIDR.")

    return network_id, validate_cidr(cidr).cidr


class DeviceInventoryService:
    def __init__(self, db_path=DB_PATH):
        self.db_path = db_path

    def process_scan(
        self,
        network: Mapping[str, object],
        scan_result: ScanResult,
    ) -> list[dict]:
        network_id, normalized_cidr = _network_details(network)

        if not isinstance(scan_result, ScanResult):
            raise DeviceInventoryError("A normalized scan result is required.")

        if scan_result.target_network != normalized_cidr:
            raise DeviceInventoryError(
                "Scan result target does not match the network record."
            )

        if scan_result.errors:
            raise DeviceInventoryError(
                "Failed scan results cannot update device inventory."
            )

        devices = []
        observed_device_ids = set()

        for host in scan_result.hosts:
            if not isinstance(host, HostDiscoveryResult):
                raise DeviceInventoryError(
                    "Scan result contains an invalid host observation."
                )

            identity = resolve_device_identity(network_id, host)
            observed_at = inventory_db.timestamp_text(host.discovered_at)
            previous = inventory_db.find_device_by_stable_key(
                identity.stable_key,
                db_path=self.db_path,
            )

            if previous is None:
                device = inventory_db.create_device(
                    stable_key=identity.stable_key,
                    network_id=network_id,
                    mac_address=host.mac_address,
                    hostname=host.hostname,
                    vendor=host.vendor,
                    first_seen=observed_at,
                    last_seen=observed_at,
                    last_ip_address=host.ip_address,
                    status="ONLINE",
                    identity_confidence=identity.confidence,
                    db_path=self.db_path,
                )
                persist_changes(
                    device_observation_changes(
                        previous=None,
                        current=device,
                        network_id=network_id,
                        observed_at=host.discovered_at,
                    ),
                    db_path=self.db_path,
                )
            else:
                current = {
                    **previous,
                    "status": "ONLINE",
                    "last_seen": observed_at,
                    "last_ip_address": host.ip_address,
                    "mac_address": host.mac_address or previous["mac_address"],
                    "hostname": host.hostname or previous["hostname"],
                    "vendor": host.vendor or previous["vendor"],
                }
                persist_changes(
                    device_observation_changes(
                        previous=previous,
                        current=current,
                        network_id=network_id,
                        observed_at=host.discovered_at,
                    ),
                    db_path=self.db_path,
                )
                device = inventory_db.update_device_state(
                    previous["id"],
                    last_seen=observed_at,
                    last_ip_address=host.ip_address,
                    status="ONLINE",
                    mac_address=host.mac_address,
                    hostname=host.hostname,
                    vendor=host.vendor,
                    db_path=self.db_path,
                )

            inventory_db.save_observation(
                device_id=device["id"],
                network_id=network_id,
                ip_address=host.ip_address,
                mac_address=host.mac_address,
                hostname=host.hostname,
                vendor=host.vendor,
                status="ONLINE",
                observed_at=observed_at,
                source=host.source,
                db_path=self.db_path,
            )
            observed_device_ids.add(device["id"])
            devices.append(device)

        for previous in inventory_db.list_devices(
            network_id=network_id,
            db_path=self.db_path,
        ):
            if (
                previous["status"] == "ONLINE"
                and previous["id"] not in observed_device_ids
            ):
                persist_changes(
                    [
                        device_disappearance_change(
                            device=previous,
                            network_id=network_id,
                            observed_at=scan_result.completed_at,
                        )
                    ],
                    db_path=self.db_path,
                )

        inventory_db.mark_devices_offline(
            network_id=network_id,
            observed_device_ids=observed_device_ids,
            observed_at=inventory_db.timestamp_text(scan_result.completed_at),
            db_path=self.db_path,
        )

        return devices


def process_scan_result(
    network: Mapping[str, object],
    scan_result: ScanResult,
    db_path=DB_PATH,
) -> list[dict]:
    return DeviceInventoryService(db_path=db_path).process_scan(
        network,
        scan_result,
    )