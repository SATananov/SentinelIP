import re
from dataclasses import dataclass
from datetime import datetime
from enum import Enum


class CveModelError(ValueError):
    """Raised when a local CVE record or match is invalid."""


class CveMatchStatus(str, Enum):
    POSSIBLE_MATCH = "POSSIBLE_MATCH"
    REVIEW = "REVIEW"
    NOT_AFFECTED = "NOT_AFFECTED"
    CONFIRMED_ISSUE = "CONFIRMED_ISSUE"


class CveMatchConfidence(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


CVE_PATTERN = re.compile(r"^CVE-(\d{4})-(\d{4,})$", re.IGNORECASE)
NUMERIC_VERSION_PATTERN = re.compile(r"^\d+(?:\.\d+)*$")


def normalize_cve_id(cve_id: str) -> str:
    if not isinstance(cve_id, str):
        raise CveModelError("CVE ID is required.")

    normalized = cve_id.strip().upper()
    if CVE_PATTERN.fullmatch(normalized) is None:
        raise CveModelError("CVE ID format is invalid.")

    return normalized


def normalize_product(product: str) -> str:
    if not isinstance(product, str) or not product.strip():
        raise CveModelError("CVE product is required.")

    return " ".join(product.strip().casefold().split())


def parse_numeric_version(version: str) -> tuple[int, ...] | None:
    if not isinstance(version, str):
        return None

    normalized = version.strip()
    if NUMERIC_VERSION_PATTERN.fullmatch(normalized) is None:
        return None

    return tuple(int(part) for part in normalized.split("."))


def compare_numeric_versions(left: str, right: str) -> int | None:
    left_parts = parse_numeric_version(left)
    right_parts = parse_numeric_version(right)

    if left_parts is None or right_parts is None:
        return None

    length = max(len(left_parts), len(right_parts))
    left_padded = left_parts + (0,) * (length - len(left_parts))
    right_padded = right_parts + (0,) * (length - len(right_parts))

    if left_padded < right_padded:
        return -1
    if left_padded > right_padded:
        return 1
    return 0


@dataclass(frozen=True)
class VersionConstraint:
    expression: str

    def __post_init__(self):
        if not isinstance(self.expression, str) or not self.expression.strip():
            raise CveModelError("Version expression is required.")
        object.__setattr__(self, "expression", self.expression.strip())


@dataclass(frozen=True)
class CveRecord:
    cve_id: str
    source: str
    product: str
    affected_version_expression: str
    record_id: int | None = None
    source_reference: str | None = None
    published_at: datetime | None = None
    modified_at: datetime | None = None
    vendor: str | None = None
    description: str | None = None
    severity: str | None = None
    cvss_score: float | None = None
    metadata: object | None = None

    def __post_init__(self):
        if self.record_id is not None and (type(self.record_id) is not int or self.record_id <= 0):
            raise CveModelError("record_id must be positive when supplied.")
        if not isinstance(self.source, str) or not self.source.strip():
            raise CveModelError("CVE source is required.")

        object.__setattr__(self, "cve_id", normalize_cve_id(self.cve_id))
        object.__setattr__(self, "product", normalize_product(self.product))
        object.__setattr__(self, "source", self.source.strip())
        object.__setattr__(
            self,
            "affected_version_expression",
            VersionConstraint(self.affected_version_expression).expression,
        )

        for field_name in (
            "source_reference",
            "vendor",
            "description",
            "severity",
        ):
            value = getattr(self, field_name)
            if value is not None and not isinstance(value, str):
                raise CveModelError(f"{field_name} must be text when supplied.")
            if isinstance(value, str):
                object.__setattr__(self, field_name, value.strip())

        if self.cvss_score is not None:
            if not isinstance(self.cvss_score, (int, float)) or not 0 <= self.cvss_score <= 10:
                raise CveModelError("CVSS score must be between 0 and 10.")


@dataclass(frozen=True)
class CveServiceEvidence:
    service_id: int
    device_id: int
    port_id: int | None
    product: str | None
    version: str | None
    confidence: str
    source: str
    observed_at: datetime

    def __post_init__(self):
        for field_name, value in (
            ("service_id", self.service_id),
            ("device_id", self.device_id),
        ):
            if type(value) is not int or value <= 0:
                raise CveModelError(f"{field_name} must be positive.")

        if self.port_id is not None and (type(self.port_id) is not int or self.port_id <= 0):
            raise CveModelError("port_id must be positive when supplied.")
        if self.product is not None:
            object.__setattr__(self, "product", normalize_product(self.product))
        if self.version is not None:
            if not isinstance(self.version, str) or not self.version.strip():
                raise CveModelError("Version must be non-empty when supplied.")
            object.__setattr__(self, "version", self.version.strip())
        if not isinstance(self.confidence, str) or self.confidence.strip().upper() not in {"LOW", "MEDIUM", "HIGH"}:
            raise CveModelError("Service evidence confidence is invalid.")
        if not isinstance(self.source, str) or not self.source.strip():
            raise CveModelError("Service evidence source is required.")
        if not isinstance(self.observed_at, datetime):
            raise CveModelError("Service evidence timestamp is required.")


@dataclass(frozen=True)
class CveMatch:
    cve_record_id: int
    cve_id: str
    device_id: int
    service_id: int
    port_id: int | None
    status: CveMatchStatus | str
    confidence: CveMatchConfidence | str
    observed_product: str | None
    observed_version: str | None
    evidence_source: str
    evidence_observed_at: datetime
    match_reason: str
    stable_key: str
    first_seen: datetime
    last_seen: datetime
    finding_id: int | None = None
    metadata: object | None = None

    def __post_init__(self):
        try:
            status = CveMatchStatus(
                self.status.value
                if isinstance(self.status, CveMatchStatus)
                else str(self.status).strip().upper()
            )
            confidence = CveMatchConfidence(
                self.confidence.value
                if isinstance(self.confidence, CveMatchConfidence)
                else str(self.confidence).strip().upper()
            )
        except ValueError as exc:
            raise CveModelError("CVE match status or confidence is invalid.") from exc

        for field_name, value in (
            ("cve_record_id", self.cve_record_id),
            ("device_id", self.device_id),
            ("service_id", self.service_id),
        ):
            if type(value) is not int or value <= 0:
                raise CveModelError(f"{field_name} must be positive.")

        if self.port_id is not None and (type(self.port_id) is not int or self.port_id <= 0):
            raise CveModelError("port_id must be positive when supplied.")
        if self.finding_id is not None and (type(self.finding_id) is not int or self.finding_id <= 0):
            raise CveModelError("finding_id must be positive when supplied.")

        for field_name, value in (
            ("cve_id", self.cve_id),
            ("evidence_source", self.evidence_source),
            ("match_reason", self.match_reason),
            ("stable_key", self.stable_key),
        ):
            if not isinstance(value, str) or not value.strip():
                raise CveModelError(f"{field_name} is required.")

        for field_name in ("evidence_observed_at", "first_seen", "last_seen"):
            if not isinstance(getattr(self, field_name), datetime):
                raise CveModelError(f"{field_name} is required.")

        object.__setattr__(self, "cve_id", normalize_cve_id(self.cve_id))
        object.__setattr__(self, "status", status)
        object.__setattr__(self, "confidence", confidence)