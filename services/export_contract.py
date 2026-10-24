"""Shared validation and resource limits for legacy event exports."""

from dataclasses import dataclass
from datetime import datetime, timezone
import re


JSON_EXPORT_MAX_ROWS = 5_000
CSV_EXPORT_MAX_ROWS = 5_000
PDF_EXPORT_MAX_ROWS = 1_000
EXPORT_MAX_TEXT_BYTES = 64 * 1024
# Shared raw-text budget: at 1 MiB, worst-case JSON control escaping is about
# 6 MiB, CSV quote doubling about 2 MiB, and Paragraph XML escaping about
# 5 MiB. Row/layout structures are also capped at 5,000/1,000 rows; the final
# serialized bytes are measured separately against the stricter output caps.
EXPORT_MAX_AGGREGATE_TEXT_BYTES = 1024 * 1024
JSON_EXPORT_MAX_BYTES = 32 * 1024 * 1024
CSV_EXPORT_MAX_BYTES = 32 * 1024 * 1024
PDF_EXPORT_MAX_BYTES = 8 * 1024 * 1024
EXPORT_MAX_SOURCE_IP_BYTES = 255
EXPORT_MAX_TIMESTAMP_CHARS = 256
_MAX_DATE_SPAN_SECONDS = 31 * 24 * 60 * 60
_RFC3339 = re.compile(
    r"^(\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2})"
    r"(?:\.(\d+))?(Z|z|[+-]\d{2}:\d{2})$"
)
_TIME_RANGES = frozenset({"15m", "1h", "24h", "all"})
_SEVERITIES = frozenset({"INFO", "WARNING", "ALERT"})


class ExportInputError(ValueError):
    """A user-supplied export filter does not satisfy the export contract."""


class ExportTooLargeError(Exception):
    """An otherwise valid export exceeds a fixed resource limit."""


class ExportDataError(Exception):
    """Stored event data or export rendering failed validation."""


@dataclass(frozen=True)
class ParsedExportTimestamp:
    utc_base: datetime
    local_naive: datetime
    fraction: str

    @property
    def local_bound(self):
        value = self.local_naive.isoformat(timespec="seconds")
        fraction = self.fraction.rstrip("0")
        return f"{value}.{fraction}" if fraction else value


@dataclass(frozen=True)
class ExportTimeFilter:
    time_range: str | None
    since: str | None
    until: str | None
    from_value: str | None
    until_value: str | None

    @property
    def is_custom(self):
        return self.from_value is not None


def _parse_rfc3339(value: str) -> ParsedExportTimestamp:
    if len(value) > EXPORT_MAX_TIMESTAMP_CHARS:
        raise ExportInputError("invalid timestamp")
    match = _RFC3339.fullmatch(value)
    if match is None:
        raise ExportInputError("invalid timestamp")

    base, fraction, offset = match.groups()
    normalized_offset = "+00:00" if offset.lower() == "z" else offset
    try:
        parsed = datetime.fromisoformat(base + normalized_offset)
        utc_base = parsed.astimezone(timezone.utc).replace(tzinfo=None)
        # Legacy event rows are naive server-local wall-clock values. They
        # cannot distinguish the repeated local hour at a DST fall-back.
        local_naive = parsed.astimezone().replace(tzinfo=None)
    except (OverflowError, ValueError) as exc:
        raise ExportInputError("invalid timestamp") from exc

    return ParsedExportTimestamp(
        utc_base=utc_base,
        local_naive=local_naive,
        fraction=fraction or "",
    )


def _compare_fraction(left: str, right: str) -> int:
    precision = max(len(left), len(right))
    left_value = int(left.ljust(precision, "0") or "0")
    right_value = int(right.ljust(precision, "0") or "0")
    return (left_value > right_value) - (left_value < right_value)


def resolve_export_time_filter(*, time_range, from_value, until_value):
    if time_range is not None and time_range not in _TIME_RANGES:
        raise ExportInputError("invalid time range")
    has_from = from_value is not None
    has_until = until_value is not None
    has_custom = has_from or has_until

    if has_custom and time_range is not None:
        raise ExportInputError("preset and explicit range conflict")
    if has_from != has_until:
        raise ExportInputError("both custom range bounds are required")

    if not has_custom:
        return ExportTimeFilter(
            time_range=time_range or "all",
            since=None,
            until=None,
            from_value=None,
            until_value=None,
        )

    start = _parse_rfc3339(from_value)
    end = _parse_rfc3339(until_value)
    base_seconds = int((end.utc_base - start.utc_base).total_seconds())
    fraction_order = _compare_fraction(end.fraction, start.fraction)
    if base_seconds < 0 or (base_seconds == 0 and fraction_order <= 0):
        raise ExportInputError("custom range must be increasing")
    if (base_seconds > _MAX_DATE_SPAN_SECONDS
            or (base_seconds == _MAX_DATE_SPAN_SECONDS and fraction_order > 0)):
        raise ExportInputError("custom range exceeds 31 days")

    return ExportTimeFilter(
        time_range=None,
        since=start.local_bound,
        until=end.local_bound,
        from_value=from_value,
        until_value=until_value,
    )


def validate_export_source_ip(source_ip):
    if source_ip is None:
        return
    try:
        encoded_length = len(source_ip.encode("utf-8", errors="strict"))
    except UnicodeEncodeError as exc:
        raise ExportInputError("invalid source_ip") from exc
    if encoded_length > EXPORT_MAX_SOURCE_IP_BYTES:
        raise ExportInputError("source_ip is too long")


def validate_export_severity(severity):
    if severity is not None and severity not in _SEVERITIES:
        raise ExportInputError("invalid severity")
