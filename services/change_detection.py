from datetime import datetime
import sqlite3

from database import changes as changes_db
from database.db import DB_PATH
from services.change_models import ChangeConfidence, ChangeRecord, ChangeType


def _confidence(value: str | ChangeConfidence) -> ChangeConfidence:
    return ChangeConfidence(value)


def persist_changes(
    records: list[ChangeRecord],
    db_path=DB_PATH,
    conn: sqlite3.Connection | None = None,
) -> list[dict]:
    return [changes_db.create_change(record, db_path, conn=conn) for record in records]


def device_observation_changes(
    previous: dict | None,
    current: dict,
    network_id: int,
    observed_at: datetime,
    source: str = "device-inventory",
) -> list[ChangeRecord]:
    if previous is None:
        return [
            ChangeRecord(
                change_type=ChangeType.NEW_DEVICE,
                device_id=current["id"],
                network_id=network_id,
                observed_at=observed_at,
                source=source,
                confidence=_confidence(current["identity_confidence"]),
                evidence_type="DEVICE_OBSERVATION",
                current_value={
                    "ip_address": current["last_ip_address"],
                    "stable_key": current["stable_key"],
                },
                message="Device was observed for the first time.",
            )
        ]

    records = []
    confidence = _confidence(current["identity_confidence"])

    if previous["status"] == "OFFLINE" and current["status"] == "ONLINE":
        records.append(
            ChangeRecord(
                change_type=ChangeType.DEVICE_REAPPEARED,
                device_id=current["id"],
                network_id=network_id,
                observed_at=observed_at,
                source=source,
                confidence=confidence,
                evidence_type="INVENTORY_STATE_TRANSITION",
                previous_value="OFFLINE",
                current_value="ONLINE",
                message="Device was observed again after being absent.",
            )
        )

    if previous["last_ip_address"] != current["last_ip_address"]:
        records.append(
            ChangeRecord(
                change_type=ChangeType.IP_CHANGED,
                device_id=current["id"],
                network_id=network_id,
                observed_at=observed_at,
                source=source,
                confidence=confidence,
                evidence_type="DEVICE_OBSERVATION",
                previous_value=previous["last_ip_address"],
                current_value=current["last_ip_address"],
                message=(
                    "Device IP changed from "
                    f"{previous['last_ip_address']} to "
                    f"{current['last_ip_address']}."
                ),
            )
        )

    return records


def device_disappearance_change(
    device: dict,
    network_id: int,
    observed_at: datetime,
    source: str = "device-inventory",
) -> ChangeRecord:
    return ChangeRecord(
        change_type=ChangeType.DEVICE_DISAPPEARED,
        device_id=device["id"],
        network_id=network_id,
        observed_at=observed_at,
        source=source,
        confidence=_confidence(device["identity_confidence"]),
        evidence_type="INVENTORY_STATE_TRANSITION",
        previous_value="ONLINE",
        current_value="OFFLINE",
        message=(
            "Device was not observed in the latest successful discovery cycle."
        ),
    )


def port_observation_changes(
    previous: dict | None,
    current: dict,
    network_id: int,
    observed_at: datetime,
    source: str = "service-inventory",
) -> list[ChangeRecord]:
    if previous is None:
        return [
            ChangeRecord(
                change_type=ChangeType.NEW_PORT,
                device_id=current["device_id"],
                network_id=network_id,
                port_id=current["id"],
                observed_at=observed_at,
                source=source,
                confidence=ChangeConfidence.HIGH,
                evidence_type="PORT_OBSERVATION",
                current_value={
                    "port": current["port_number"],
                    "transport": current["transport"],
                    "state": current["state"],
                },
                message=(
                    f"TCP port {current['port_number']} was observed "
                    "for the first time."
                ),
            )
        ]

    if previous["state"] == "CLOSED" and current["state"] == "OPEN":
        return [
            ChangeRecord(
                change_type=ChangeType.PORT_REOPENED,
                device_id=current["device_id"],
                network_id=network_id,
                port_id=current["id"],
                observed_at=observed_at,
                source=source,
                confidence=ChangeConfidence.HIGH,
                evidence_type="PORT_OBSERVATION",
                previous_value="CLOSED",
                current_value="OPEN",
                message=f"TCP port {current['port_number']} was observed open again.",
            )
        ]

    return []


def service_observation_changes(
    previous: dict | None,
    current: dict,
    network_id: int,
    observed_at: datetime,
    source: str = "service-inventory",
) -> list[ChangeRecord]:
    if previous is None:
        return [
            ChangeRecord(
                change_type=ChangeType.SERVICE_IDENTIFIED,
                device_id=current["device_id"],
                network_id=network_id,
                port_id=current["port_id"],
                service_id=current["id"],
                observed_at=observed_at,
                source=source,
                confidence=_confidence(current["confidence"]),
                evidence_type="SERVICE_OBSERVATION",
                current_value={
                    "service_name": current["service_name"],
                    "product": current["product"],
                    "version": current["version"],
                },
                message="Service evidence was identified for the first time.",
            )
        ]

    old_identity = (previous["service_name"], previous["product"])
    new_identity = (current["service_name"], current["product"])
    old_version = previous["version"]
    new_version = current["version"]
    confidence = _confidence(current["confidence"])

    if (
        old_version is not None
        and new_version is not None
        and old_version != new_version
        and old_identity == new_identity
    ):
        return [
            ChangeRecord(
                change_type=ChangeType.SERVICE_VERSION_CHANGED,
                device_id=current["device_id"],
                network_id=network_id,
                port_id=current["port_id"],
                service_id=current["id"],
                observed_at=observed_at,
                source=source,
                confidence=confidence,
                evidence_type="SERVICE_OBSERVATION",
                previous_value=old_version,
                current_value=new_version,
                message=(
                    f"Service version changed from {old_version} to "
                    f"{new_version}."
                ),
            )
        ]

    if old_identity != new_identity and all(
        value is not None for value in new_identity
    ):
        return [
            ChangeRecord(
                change_type=ChangeType.SERVICE_CHANGED,
                device_id=current["device_id"],
                network_id=network_id,
                port_id=current["port_id"],
                service_id=current["id"],
                observed_at=observed_at,
                source=source,
                confidence=confidence,
                evidence_type="SERVICE_OBSERVATION",
                previous_value={
                    "service_name": previous["service_name"],
                    "product": previous["product"],
                },
                current_value={
                    "service_name": current["service_name"],
                    "product": current["product"],
                },
                message="Service identity changed based on explicit evidence.",
            )
        ]

    return []
