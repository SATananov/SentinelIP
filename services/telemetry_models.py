import ipaddress
import json
import math
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from urllib.parse import urlsplit


class TelemetryModelError(ValueError):
    """Raised when telemetry cannot be normalized safely."""


class SensorType(str, Enum):
    BROWSER = "BROWSER"
    DNS = "DNS"


class PrivacyMode(str, Enum):
    DOMAIN_ONLY = "DOMAIN_ONLY"
    STANDARD = "STANDARD"


class WebEventType(str, Enum):
    NAVIGATION = "NAVIGATION"
    REDIRECT = "REDIRECT"
    FORM_SIGNAL = "FORM_SIGNAL"
    DOWNLOAD_SIGNAL = "DOWNLOAD_SIGNAL"


class DnsQueryType(str, Enum):
    A = "A"
    AAAA = "AAAA"
    CNAME = "CNAME"
    MX = "MX"
    TXT = "TXT"
    PTR = "PTR"
    OTHER = "OTHER"


class DnsResponseStatus(str, Enum):
    NOERROR = "NOERROR"
    NXDOMAIN = "NXDOMAIN"
    SERVFAIL = "SERVFAIL"
    REFUSED = "REFUSED"
    OTHER = "OTHER"


DOMAIN_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$")
FORBIDDEN_KEYS = frozenset(
    {
        "password", "password_value", "form_values", "keystrokes",
        "page_text", "page_html", "cookies", "authorization_header",
        "local_storage", "session_storage", "screenshot",
    }
)
MAX_METADATA_BYTES = 8_192
MAX_METADATA_DEPTH = 4
MAX_METADATA_KEYS_PER_OBJECT = 64
MAX_METADATA_ITEMS_PER_LIST = 256
MAX_METADATA_NODES = 1_024
MAX_METADATA_KEY_BYTES = 64
MAX_METADATA_STRING_BYTES = 4_096


def validate_utf8_text(value, field_name, maximum_bytes, *, allow_none=False):
    """Validate a raw string by its strict UTF-8 byte representation."""
    if value is None and allow_none:
        return value
    if not isinstance(value, str):
        return value
    try:
        byte_length = len(value.encode("utf-8", errors="strict"))
    except UnicodeEncodeError as exc:
        raise TelemetryModelError(f"{field_name} is not valid UTF-8 text.") from exc
    if byte_length > maximum_bytes:
        raise TelemetryModelError(f"{field_name} exceeds its byte limit.")
    return value


def normalize_timestamp(value: datetime, now: datetime | None = None) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise TelemetryModelError("Telemetry timestamps must be timezone-aware.")

    normalized = value.astimezone(timezone.utc)
    current = now or datetime.now(timezone.utc)
    if normalized > current + timedelta(minutes=5):
        raise TelemetryModelError("Telemetry timestamp is too far in the future.")
    return normalized


def normalize_domain(value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise TelemetryModelError("Domain is required.")

    value = value.strip().rstrip(".").lower()
    if ":" in value or "/" in value or "@" in value:
        raise TelemetryModelError("Domain must be a hostname, not a URL.")

    try:
        value = value.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise TelemetryModelError("Domain IDN normalization failed.") from exc

    if DOMAIN_PATTERN.fullmatch(value) is None:
        raise TelemetryModelError("Domain hostname is invalid.")
    return value


def _normalize_telemetry_domain(value: str) -> str:
    validate_utf8_text(value, "Domain", 1_024)
    normalized = normalize_domain(value)
    if len(normalized.encode("ascii")) > 253:
        raise TelemetryModelError("Domain exceeds the hostname byte limit.")
    return normalized


def _validate_metadata(value):
    if value is None:
        return None
    if not isinstance(value, dict):
        raise TelemetryModelError("Telemetry metadata must be an object.")

    pending = [(value, 1)]
    node_count = 0
    metadata_keys = []
    while pending:
        item, depth = pending.pop()
        node_count += 1
        if node_count > MAX_METADATA_NODES:
            raise TelemetryModelError("Telemetry metadata has too many values.")
        if depth > MAX_METADATA_DEPTH:
            raise TelemetryModelError("Telemetry metadata is nested too deeply.")
        if isinstance(item, dict):
            if len(item) > MAX_METADATA_KEYS_PER_OBJECT:
                raise TelemetryModelError("Telemetry metadata object has too many keys.")
            for key, child in item.items():
                if not isinstance(key, str):
                    raise TelemetryModelError("Telemetry metadata keys must be strings.")
                validate_utf8_text(key, "Telemetry metadata key", MAX_METADATA_KEY_BYTES)
                metadata_keys.append(key)
                child_depth = depth + 1 if isinstance(child, (dict, list)) else depth
                pending.append((child, child_depth))
        elif isinstance(item, list):
            if len(item) > MAX_METADATA_ITEMS_PER_LIST:
                raise TelemetryModelError("Telemetry metadata list has too many items.")
            for child in item:
                child_depth = depth + 1 if isinstance(child, (dict, list)) else depth
                pending.append((child, child_depth))
        elif isinstance(item, str):
            validate_utf8_text(item, "Telemetry metadata string", MAX_METADATA_STRING_BYTES)
        elif item is None or type(item) in (bool, int):
            pass
        elif type(item) is float:
            if not math.isfinite(item):
                raise TelemetryModelError("Telemetry metadata numbers must be finite.")
        else:
            raise TelemetryModelError("Telemetry metadata contains a non-JSON value.")

    for key in metadata_keys:
        if key.casefold() in FORBIDDEN_KEYS:
            raise TelemetryModelError("Sensitive telemetry fields are not allowed.")

    try:
        # Match database.telemetry._metadata storage serialization exactly.
        serialized = json.dumps(value, sort_keys=True, separators=(",", ":"))
        serialized_bytes = len(serialized.encode("utf-8", errors="strict"))
    except (TypeError, ValueError, UnicodeEncodeError, RecursionError) as exc:
        raise TelemetryModelError("Telemetry metadata cannot be serialized safely.") from exc
    if serialized_bytes > MAX_METADATA_BYTES:
        raise TelemetryModelError("Telemetry metadata exceeds its byte limit.")
    return value


def normalize_url(url: str, privacy_mode: PrivacyMode) -> tuple[str, str, str | None]:
    if not isinstance(url, str) or not url.strip():
        raise TelemetryModelError("URL is required.")
    validate_utf8_text(url, "URL", 32_768)
    parsed = urlsplit(url.strip())
    if parsed.scheme.lower() not in {"http", "https"}:
        raise TelemetryModelError("Only HTTP and HTTPS URLs are supported.")
    if parsed.username is not None or parsed.password is not None:
        raise TelemetryModelError("URL userinfo is not allowed.")
    if not parsed.hostname:
        raise TelemetryModelError("URL hostname is required.")

    hostname = _normalize_telemetry_domain(parsed.hostname)
    scheme = parsed.scheme.lower()
    path = None if privacy_mode is PrivacyMode.DOMAIN_ONLY else (parsed.path or "/")
    return scheme, hostname, path


@dataclass(frozen=True)
class TelemetrySensor:
    sensor_id: str
    name: str
    sensor_type: SensorType | str
    device_id: int | None
    enabled: bool
    privacy_mode: PrivacyMode | str
    retention_days: int
    created_at: datetime
    updated_at: datetime
    last_seen_at: datetime | None = None

    def __post_init__(self):
        try:
            sensor_type = SensorType(self.sensor_type)
            privacy_mode = PrivacyMode(self.privacy_mode)
        except ValueError as exc:
            raise TelemetryModelError("Sensor type or privacy mode is invalid.") from exc
        if not self.sensor_id.strip() or not self.name.strip():
            raise TelemetryModelError("Sensor identity is required.")
        if self.device_id is not None and (type(self.device_id) is not int or self.device_id <= 0):
            raise TelemetryModelError("Sensor device ID must be positive.")
        if type(self.retention_days) is not int or not 1 <= self.retention_days <= 365:
            raise TelemetryModelError("Retention must be between 1 and 365 days.")
        object.__setattr__(self, "sensor_type", sensor_type)
        object.__setattr__(self, "privacy_mode", privacy_mode)


@dataclass(frozen=True)
class WebObservation:
    external_event_id: str
    sensor_id: str
    observed_at: datetime
    event_type: WebEventType | str
    url: str
    privacy_mode: PrivacyMode | str
    referrer_domain: str | None = None
    redirect_from_domain: str | None = None
    redirect_to_domain: str | None = None
    browser_session_id: str | None = None
    tab_id: str | None = None
    has_login_form: bool = False
    has_password_form: bool = False
    download_detected: bool = False
    metadata: dict | None = None
    device_id: int | None = None
    received_at: datetime | None = None
    retention_until: datetime | None = None

    def __post_init__(self):
        validate_utf8_text(self.external_event_id, "External event ID", 128)
        validate_utf8_text(self.event_type, "Event type", 32)
        validate_utf8_text(self.browser_session_id, "Browser session ID", 128, allow_none=True)
        validate_utf8_text(self.tab_id, "Tab ID", 64, allow_none=True)
        if not self.external_event_id.strip():
            raise TelemetryModelError("External event ID is required.")
        try:
            event_type = WebEventType(self.event_type)
            privacy_mode = PrivacyMode(self.privacy_mode)
        except ValueError as exc:
            raise TelemetryModelError("Web event type or privacy mode is invalid.") from exc
        normalize_timestamp(self.observed_at)
        normalize_url(self.url, privacy_mode)
        for field in ("referrer_domain", "redirect_from_domain", "redirect_to_domain"):
            value = getattr(self, field)
            if value is not None:
                object.__setattr__(self, field, _normalize_telemetry_domain(value))
        if self.device_id is not None and (type(self.device_id) is not int or self.device_id <= 0):
            raise TelemetryModelError("Device ID must be positive.")
        object.__setattr__(self, "event_type", event_type)
        object.__setattr__(self, "privacy_mode", privacy_mode)
        object.__setattr__(self, "metadata", _validate_metadata(self.metadata))


@dataclass(frozen=True)
class DnsObservation:
    external_event_id: str
    sensor_id: str
    observed_at: datetime
    queried_domain: str
    query_type: DnsQueryType | str
    response_status: DnsResponseStatus | str
    resolved_addresses: tuple[str, ...] = ()
    resolver: str | None = None
    ttl: int | None = None
    metadata: dict | None = None
    device_id: int | None = None
    received_at: datetime | None = None
    retention_until: datetime | None = None

    def __post_init__(self):
        validate_utf8_text(self.external_event_id, "External event ID", 128)
        validate_utf8_text(self.query_type, "DNS query type", 32)
        validate_utf8_text(self.response_status, "DNS response status", 16)
        validate_utf8_text(self.resolver, "DNS resolver", 45, allow_none=True)
        if not self.external_event_id.strip():
            raise TelemetryModelError("External event ID is required.")
        try:
            query_type = DnsQueryType(self.query_type)
            response_status = DnsResponseStatus(self.response_status)
        except ValueError as exc:
            raise TelemetryModelError("DNS query type or response status is invalid.") from exc
        normalize_timestamp(self.observed_at)
        object.__setattr__(self, "queried_domain", _normalize_telemetry_domain(self.queried_domain))
        if len(self.resolved_addresses) > MAX_METADATA_ITEMS_PER_LIST:
            raise TelemetryModelError("DNS answer list has too many addresses.")
        addresses = []
        for address in self.resolved_addresses:
            validate_utf8_text(address, "DNS address", 45)
            try:
                addresses.append(str(ipaddress.ip_address(address)))
            except ValueError as exc:
                raise TelemetryModelError("Resolved address is invalid.") from exc
        if self.resolver is not None:
            try:
                object.__setattr__(self, "resolver", str(ipaddress.ip_address(self.resolver)))
            except ValueError as exc:
                raise TelemetryModelError("Resolver address is invalid.") from exc
        if self.ttl is not None and (
            type(self.ttl) is not int or not 0 <= self.ttl <= 2_147_483_647
        ):
            raise TelemetryModelError("TTL must be a non-negative integer.")
        if self.device_id is not None and (type(self.device_id) is not int or self.device_id <= 0):
            raise TelemetryModelError("Device ID must be positive.")
        object.__setattr__(self, "query_type", query_type)
        object.__setattr__(self, "response_status", response_status)
        object.__setattr__(self, "resolved_addresses", tuple(addresses))
        object.__setattr__(self, "metadata", _validate_metadata(self.metadata))
