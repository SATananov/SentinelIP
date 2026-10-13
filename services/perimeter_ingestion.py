"""Trusted perimeter ingestion helpers and bounded adapter contracts."""
from __future__ import annotations

import hashlib
import ipaddress
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Mapping

from services.perimeter_models import (
    PerimeterAction,
    PerimeterDirection,
    PerimeterEvent,
    PerimeterEventType,
    PerimeterModelError,
    PerimeterProtocol,
    PerimeterSourceType,
)


class PerimeterAdapterError(ValueError):
    """Raised when raw adapter evidence cannot be normalized safely."""


@dataclass(frozen=True)
class PerimeterObservation:
    """Site-neutral normalized record produced by a local trusted adapter."""

    external_event_id: str
    source_type: PerimeterSourceType | str
    source_key: str
    observed_at: datetime
    event_type: PerimeterEventType | str
    direction: PerimeterDirection | str
    action: PerimeterAction | str
    protocol: PerimeterProtocol | str
    source_ip: str
    destination_ip: str
    source_port: int | None = None
    destination_port: int | None = None
    interface: str | None = None
    source_reference: str | None = None
    raw_event_hash: str | None = None
    metadata: dict | None = None

    def to_event(self, *, site_id: int, sensor_id: int) -> PerimeterEvent:
        return PerimeterEvent(
            external_event_id=self.external_event_id,
            site_id=site_id,
            sensor_id=sensor_id,
            source_type=self.source_type,
            source_key=self.source_key,
            observed_at=self.observed_at,
            event_type=self.event_type,
            direction=self.direction,
            action=self.action,
            protocol=self.protocol,
            source_ip=self.source_ip,
            destination_ip=self.destination_ip,
            source_port=self.source_port,
            destination_port=self.destination_port,
            interface=self.interface,
            source_reference=self.source_reference,
            raw_event_hash=self.raw_event_hash,
            metadata=self.metadata,
        )

    def to_wire(self) -> dict:
        # Reuse the authoritative model validation with harmless placeholder IDs.
        event = self.to_event(site_id=1, sensor_id=1)
        return {
            "external_event_id": event.external_event_id,
            "source_type": event.source_type.value,
            "source_key": event.source_key,
            "observed_at": event.observed_at.isoformat(),
            "event_type": event.event_type.value,
            "direction": event.direction.value,
            "action": event.action.value,
            "protocol": event.protocol.value,
            "source_ip": event.source_ip,
            "destination_ip": event.destination_ip,
            "source_port": event.source_port,
            "destination_port": event.destination_port,
            "interface": event.interface,
            "source_reference": event.source_reference,
            "raw_event_hash": event.raw_event_hash,
            "metadata": event.metadata,
        }


_KV_RE = re.compile(r"\b([A-Z][A-Z0-9_]*)=([^\s]+)")


class NetfilterKeyValueAdapter:
    """Normalize bounded Linux netfilter-style key/value evidence.

    The log line provides network facts only. Direction and policy action are fixed
    adapter configuration because those semantics belong to the known firewall log
    stream/rule, not to heuristics over an arbitrary line.
    """

    def __init__(self, *, source_key: str, direction: str, action: str,
                 source_type: str = "FIREWALL", source_reference: str | None = None):
        # Validate configuration through the authoritative model enum classes.
        try:
            self.source_type = PerimeterSourceType(source_type)
            self.direction = PerimeterDirection(direction)
            self.action = PerimeterAction(action)
        except ValueError as exc:
            raise PerimeterAdapterError("Unsupported netfilter adapter configuration.") from exc
        if self.source_type not in {
            PerimeterSourceType.FIREWALL, PerimeterSourceType.ROUTER, PerimeterSourceType.GATEWAY
        }:
            raise PerimeterAdapterError("Netfilter adapters require a perimeter source type.")
        if not isinstance(source_key, str) or not source_key.strip() or len(source_key.strip()) > 128:
            raise PerimeterAdapterError("source_key is invalid.")
        if source_reference is not None and (
            not isinstance(source_reference, str) or not source_reference.strip()
            or len(source_reference.strip()) > 256
        ):
            raise PerimeterAdapterError("source_reference is invalid.")
        self.source_key = source_key.strip()
        self.source_reference = source_reference.strip() if source_reference else None

    def parse(self, raw_line: str, *, observed_at: datetime) -> PerimeterObservation:
        if not isinstance(raw_line, str) or not raw_line or len(raw_line.encode("utf-8")) > 4096:
            raise PerimeterAdapterError("Netfilter record is empty or exceeds 4096 bytes.")
        if "\x00" in raw_line or "\r" in raw_line or "\n" in raw_line:
            raise PerimeterAdapterError("Netfilter record must be exactly one text line.")
        fields = {key: value for key, value in _KV_RE.findall(raw_line)}
        required = {"SRC", "DST", "PROTO"}
        if not required.issubset(fields):
            raise PerimeterAdapterError("Netfilter record lacks required network fields.")

        try:
            source_ip = str(ipaddress.ip_address(fields["SRC"]))
            destination_ip = str(ipaddress.ip_address(fields["DST"]))
        except ValueError as exc:
            raise PerimeterAdapterError("Netfilter record contains an invalid IP address.") from exc
        if source_ip != fields["SRC"] or destination_ip != fields["DST"]:
            raise PerimeterAdapterError("Netfilter record IP addresses must be canonical.")

        protocol_value = fields["PROTO"].upper()
        protocol = protocol_value if protocol_value in {"TCP", "UDP", "ICMP"} else "OTHER"

        def port(name):
            raw = fields.get(name)
            if raw is None:
                return None
            if not raw.isdigit():
                raise PerimeterAdapterError(f"{name} must be a decimal port.")
            value = int(raw)
            if not 1 <= value <= 65535:
                raise PerimeterAdapterError(f"{name} is outside the valid port range.")
            return value

        source_port = port("SPT")
        destination_port = port("DPT")
        if protocol in {"TCP", "UDP"} and destination_port is None:
            raise PerimeterAdapterError("TCP/UDP netfilter records require DPT.")
        if protocol == "ICMP":
            source_port = destination_port = None

        interface = fields.get("IN") or fields.get("OUT")
        if interface is not None and len(interface) > 128:
            raise PerimeterAdapterError("Netfilter interface is too long.")

        digest = hashlib.sha256(raw_line.encode("utf-8")).hexdigest()
        if not isinstance(observed_at, datetime):
            raise PerimeterAdapterError("observed_at must be a datetime.")
        identity_material = f"{self.source_key}\n{observed_at.isoformat()}\n{digest}".encode("utf-8")
        external_event_id = hashlib.sha256(identity_material).hexdigest()
        metadata: dict[str, str] = {}
        if fields.get("IN"):
            metadata["in_interface"] = fields["IN"]
        if fields.get("OUT"):
            metadata["out_interface"] = fields["OUT"]

        observation = PerimeterObservation(
            external_event_id=external_event_id,
            source_type=self.source_type,
            source_key=self.source_key,
            observed_at=observed_at,
            event_type=PerimeterEventType.POLICY_DECISION,
            direction=self.direction,
            action=self.action,
            protocol=protocol,
            source_ip=source_ip,
            destination_ip=destination_ip,
            source_port=source_port,
            destination_port=destination_port,
            interface=interface,
            source_reference=self.source_reference,
            raw_event_hash=digest,
            metadata=metadata or None,
        )
        try:
            observation.to_wire()
        except PerimeterModelError as exc:
            raise PerimeterAdapterError(str(exc)) from exc
        return observation


def observation_from_mapping(value: Mapping) -> PerimeterObservation:
    """Build a shared observation from a strict already-normalized mapping."""
    if not isinstance(value, Mapping):
        raise PerimeterAdapterError("A normalized perimeter mapping is required.")
    allowed = {
        "external_event_id", "source_type", "source_key", "observed_at", "event_type",
        "direction", "action", "protocol", "source_ip", "destination_ip", "source_port",
        "destination_port", "interface", "source_reference", "raw_event_hash", "metadata",
    }
    if set(value) != allowed:
        raise PerimeterAdapterError("Normalized perimeter mapping has unsupported or missing fields.")
    return PerimeterObservation(**dict(value))
