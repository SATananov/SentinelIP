from collections.abc import Mapping
from dataclasses import dataclass
import sqlite3

from database import inventory as inventory_db
from database.db import DB_PATH, get_connection, initialize_database
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
        conn: sqlite3.Connection | None = None,
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

        if any(not isinstance(host, HostDiscoveryResult) for host in scan_result.hosts):
            raise DeviceInventoryError(
                "Scan result contains an invalid host observation."
            )

        if conn is not None:
            return self._process_scan(network_id, normalized_cidr, scan_result, conn)

        initialize_database(self.db_path)
        connection = get_connection(self.db_path)
        connection.row_factory = sqlite3.Row
        try:
            connection.execute("BEGIN IMMEDIATE")
            devices = self._process_scan(
                network_id, normalized_cidr, scan_result, connection
            )
            connection.commit()
            return devices
        except BaseException:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()

    def _process_scan(
        self,
        network_id: int,
        normalized_cidr: str,
        scan_result: ScanResult,
        conn: sqlite3.Connection,
    ) -> list[dict]:
        stored_network = conn.execute(
            "SELECT cidr, authorized, enabled FROM networks WHERE id = ?",
            (network_id,),
        ).fetchone()
        if (
            stored_network is None
            or stored_network["authorized"] != 1
            or stored_network["enabled"] != 1
            or validate_cidr(stored_network["cidr"]).cidr != normalized_cidr
        ):
            raise DeviceInventoryError(
                "Stored network is missing, disabled, unauthorized, or changed."
            )

        devices = []
        observed_device_ids = set()

        for host in scan_result.hosts:
            identity = resolve_device_identity(network_id, host)
            observed_at = inventory_db.timestamp_text(host.discovered_at)
            previous = inventory_db.find_device_by_stable_key(
                identity.stable_key,
                db_path=self.db_path,
                conn=conn,
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
                    conn=conn,
                )
                persist_changes(
                    device_observation_changes(
                        previous=None,
                        current=device,
                        network_id=network_id,
                        observed_at=host.discovered_at,
                    ),
                    db_path=self.db_path,
                    conn=conn,
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
                    conn=conn,
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
                    conn=conn,
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
                conn=conn,
            )
            observed_device_ids.add(device["id"])
            devices.append(device)

        for previous in inventory_db.list_online_devices(
            network_id=network_id,
            db_path=self.db_path,
            conn=conn,
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
                    conn=conn,
                )

        inventory_db.mark_devices_offline(
            network_id=network_id,
            observed_device_ids=observed_device_ids,
            observed_at=inventory_db.timestamp_text(scan_result.completed_at),
            db_path=self.db_path,
            conn=conn,
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
