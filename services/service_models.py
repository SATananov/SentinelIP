from dataclasses import dataclass
from datetime import datetime

from services.scan_models import ScanModelError, normalize_ipv4
from services.service_fingerprint import (
    NormalizedServiceEvidence,
    ServiceEvidenceError,
    normalize_service_evidence,
)


def _normalize_port(port: int) -> int:
    if type(port) is not int or not 1 <= port <= 65535:
        raise ScanModelError("Port must be an integer from 1 through 65535.")

    return port


def _normalize_transport(transport: str) -> str:
    if not isinstance(transport, str) or transport.strip().lower() != "tcp":
        raise ScanModelError("Only TCP transport is supported.")

    return "tcp"


def _normalize_state(state: str) -> str:
    if not isinstance(state, str) or state.strip().lower() != "open":
        raise ScanModelError("Only open port state is supported.")

    return "open"


def _normalize_source(source: str) -> str:
    if not isinstance(source, str) or not source.strip():
        raise ScanModelError("Observation source is required.")

    return source.strip()


@dataclass(frozen=True)
class PortObservation:
    ip_address: str
    port: int
    transport: str
    state: str
    observed_at: datetime | None
    source: str

    def __post_init__(self):
        if self.observed_at is None:
            raise ScanModelError("Port observation timestamp is required.")

        object.__setattr__(self, "ip_address", normalize_ipv4(self.ip_address))
        object.__setattr__(self, "port", _normalize_port(self.port))
        object.__setattr__(self, "transport", _normalize_transport(self.transport))
        object.__setattr__(self, "state", _normalize_state(self.state))
        object.__setattr__(self, "source", _normalize_source(self.source))


@dataclass(frozen=True)
class ServiceObservation:
    ip_address: str
    port: int
    transport: str
    service_name: str | None
    product: str | None
    version: str | None
    extra_info: str | None
    confidence: str
    observed_at: datetime | None
    source: str

    def __post_init__(self):
        if self.observed_at is None:
            raise ScanModelError("Service observation timestamp is required.")

        object.__setattr__(self, "ip_address", normalize_ipv4(self.ip_address))
        object.__setattr__(self, "port", _normalize_port(self.port))
        object.__setattr__(self, "transport", _normalize_transport(self.transport))
        object.__setattr__(self, "source", _normalize_source(self.source))

        try:
            evidence = normalize_service_evidence(
                service_name=self.service_name,
                product=self.product,
                version=self.version,
                extra_info=self.extra_info,
                confidence=self.confidence,
            )
        except ServiceEvidenceError as exc:
            raise ScanModelError(str(exc)) from exc

        for field in (
            "service_name",
            "product",
            "version",
            "extra_info",
            "confidence",
        ):
            object.__setattr__(self, field, getattr(evidence, field))

    def normalized_evidence(self) -> NormalizedServiceEvidence:
        return NormalizedServiceEvidence(
            service_name=self.service_name,
            product=self.product,
            version=self.version,
            extra_info=self.extra_info,
            confidence=self.confidence,
        )


@dataclass(frozen=True)
class ServiceDiscoveryResult:
    target_ip: str
    scanner: str
    started_at: datetime
    completed_at: datetime
    ports: tuple[PortObservation, ...] = ()
    services: tuple[ServiceObservation, ...] = ()
    warnings: tuple[str, ...] = ()
    errors: tuple[str, ...] = ()

    def __post_init__(self):
        normalized_target = normalize_ipv4(self.target_ip)

        if not isinstance(self.scanner, str) or not self.scanner.strip():
            raise ScanModelError("Scanner name is required.")

        normalized_ports = tuple(self.ports)
        normalized_services = tuple(self.services)

        if any(port.ip_address != normalized_target for port in normalized_ports):
            raise ScanModelError("Port observation target does not match result.")

        if any(
            service.ip_address != normalized_target
            for service in normalized_services
        ):
            raise ScanModelError("Service observation target does not match result.")

        object.__setattr__(self, "target_ip", normalized_target)
        object.__setattr__(self, "scanner", self.scanner.strip())
        object.__setattr__(self, "ports", normalized_ports)
        object.__setattr__(self, "services", normalized_services)
        object.__setattr__(self, "warnings", tuple(self.warnings))
        object.__setattr__(self, "errors", tuple(self.errors))