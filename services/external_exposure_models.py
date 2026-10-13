from dataclasses import dataclass
from datetime import datetime

from services.public_target_policy import normalize_public_ipv4
from services.scan_models import ScanModelError, normalize_optional_text
from services.service_fingerprint import normalize_service_evidence


PUBLIC_SCOPE_TYPES = frozenset({"PUBLIC_IPV4", "PUBLIC_CIDR", "HOSTNAME"})


class ExternalExposureModelError(ValueError):
    """Raised when external exposure evidence is not normalized safely."""


def _positive_id(value, label: str) -> int:
    if type(value) is not int or value <= 0:
        raise ExternalExposureModelError(f"{label} must be a positive integer.")
    return value


def _port(value) -> int:
    if type(value) is not int or not 1 <= value <= 65535:
        raise ExternalExposureModelError("Exposure port must be from 1 through 65535.")
    return value


@dataclass(frozen=True)
class ExternalExposureObservation:
    scope_id: int
    scope_type: str
    canonical_target: str
    device_id: int
    target_ip: str
    port_number: int
    transport: str
    observed_at: datetime
    source: str
    scanner: str
    service_name: str | None = None
    product: str | None = None
    version: str | None = None
    extra_info: str | None = None
    service_confidence: str | None = None

    def __post_init__(self):
        _positive_id(self.scope_id, "Scope ID")
        _positive_id(self.device_id, "Device ID")
        if self.scope_type not in PUBLIC_SCOPE_TYPES:
            raise ExternalExposureModelError("External exposures require an authorized public scope type.")
        if not isinstance(self.canonical_target, str) or not self.canonical_target.strip():
            raise ExternalExposureModelError("Canonical scope target is required.")
        try:
            target_ip = normalize_public_ipv4(self.target_ip)
        except ValueError as exc:
            raise ExternalExposureModelError("External exposure target must be public IPv4.") from exc
        if self.transport.strip().lower() != "tcp":
            raise ExternalExposureModelError("Only TCP external exposures are supported.")
        if not isinstance(self.observed_at, datetime):
            raise ExternalExposureModelError("Exposure observation timestamp is required.")
        if not isinstance(self.source, str) or not self.source.strip():
            raise ExternalExposureModelError("Exposure evidence source is required.")
        if not isinstance(self.scanner, str) or not self.scanner.strip():
            raise ExternalExposureModelError("Exposure scanner is required.")

        service_values = (self.service_name, self.product, self.version, self.extra_info)
        has_service = any(value is not None and str(value).strip() for value in service_values)
        if has_service:
            if self.service_confidence is None:
                raise ExternalExposureModelError("Service confidence is required when fingerprint evidence exists.")
            normalized = normalize_service_evidence(
                self.service_name, self.product, self.version, self.extra_info, self.service_confidence
            )
            for field in ("service_name", "product", "version", "extra_info", "confidence"):
                target_field = "service_confidence" if field == "confidence" else field
                object.__setattr__(self, target_field, getattr(normalized, field))
        elif self.service_confidence is not None:
            raise ExternalExposureModelError("Service confidence requires fingerprint evidence.")
        else:
            for field in ("service_name", "product", "version", "extra_info"):
                object.__setattr__(self, field, normalize_optional_text(getattr(self, field)))

        object.__setattr__(self, "target_ip", target_ip)
        object.__setattr__(self, "port_number", _port(self.port_number))
        object.__setattr__(self, "transport", "tcp")
        object.__setattr__(self, "canonical_target", self.canonical_target.strip())
        object.__setattr__(self, "source", self.source.strip())
        object.__setattr__(self, "scanner", self.scanner.strip())

    @property
    def stable_key(self) -> str:
        return f"scope:{self.scope_id}:ipv4:{self.target_ip}:tcp:{self.port_number}"
