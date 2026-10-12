"""Conservative normalization; no network access."""
import ipaddress
import re
from datetime import datetime, timedelta, timezone


class EvidenceError(ValueError):
    """Invalid evidence; messages never contain source values."""


def domain(value):
    if not isinstance(value, str):
        raise EvidenceError("Invalid domain.")
    value = value.strip().lower()
    if value.endswith("."):
        value = value[:-1]
    try:
        value = value.encode("idna").decode("ascii")
        # Validate supplied A-labels as well as Unicode input.
        for label in value.split("."):
            if label.startswith("xn--"):
                label.encode("ascii").decode("idna")
    except UnicodeError:
        raise EvidenceError("Invalid domain.") from None
    if len(value) > 253 or not re.fullmatch(
        r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*", value
    ):
        raise EvidenceError("Invalid domain.")
    return value


def address(value):
    if not isinstance(value, str) or "%" in value:
        raise EvidenceError("Invalid address.")
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        raise EvidenceError("Invalid address.") from None


def addresses(value):
    if not isinstance(value, list) or len(value) > 256:
        raise EvidenceError("Invalid answer list.")
    return tuple(dict.fromkeys(address(item) for item in value))


def query_type(value):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9]{1,32}", value.strip()):
        raise EvidenceError("Query type is required.")
    value = value.strip().upper()
    return value if value in {"A", "AAAA", "CNAME", "MX", "TXT", "PTR", "OTHER"} else "OTHER"


def response_status(value):
    if not isinstance(value, str) or value.strip().upper() not in {
        "NOERROR", "NXDOMAIN", "SERVFAIL", "REFUSED", "OTHER"
    }:
        raise EvidenceError("Unsupported or missing response status.")
    return value.strip().upper()


def timestamp(value):
    try:
        parsed = datetime.fromisoformat(value) if isinstance(value, str) else None
        if parsed is None or parsed.tzinfo is None or parsed.utcoffset() is None:
            raise ValueError
        parsed = parsed.astimezone(timezone.utc)
        if parsed > datetime.now(timezone.utc) + timedelta(minutes=5):
            raise ValueError
        return parsed
    except (ValueError, OverflowError):
        raise EvidenceError("Invalid observation timestamp.") from None


def ttl(value):
    if value is not None and (type(value) is not int or not 0 <= value <= 2147483647):
        raise EvidenceError("Invalid TTL.")
    return value
