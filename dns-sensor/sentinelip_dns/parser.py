import json
from uuid import uuid4

from . import normalize
from .models import DnsEvent

MAX_LINE = 65536
SOURCES = frozenset({"stdin-jsonl", "file-jsonl", "fixture-jsonl"})
FIELDS = frozenset({"observed_at", "queried_domain", "query_type", "response_status",
                    "resolved_addresses", "resolver", "ttl"})


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise normalize.EvidenceError("Duplicate evidence field.")
        result[key] = value
    return result


def parse(line, source):
    if source not in SOURCES or not isinstance(line, str) or len(line) > MAX_LINE:
        raise normalize.EvidenceError("Invalid source record.")
    try:
        data = json.loads(line, object_pairs_hook=_object)
    except (ValueError, RecursionError):
        raise normalize.EvidenceError("Invalid JSON record.") from None
    if not isinstance(data, dict) or data.keys() - FIELDS:
        raise normalize.EvidenceError("Unsupported evidence fields.")
    return DnsEvent(
        external_event_id=str(uuid4()),
        observed_at=normalize.timestamp(data.get("observed_at")),
        queried_domain=normalize.domain(data.get("queried_domain")),
        query_type=normalize.query_type(data.get("query_type")),
        response_status=normalize.response_status(data.get("response_status")),
        resolved_addresses=normalize.addresses(data.get("resolved_addresses", [])),
        resolver=normalize.address(data["resolver"]) if data.get("resolver") is not None else None,
        ttl=normalize.ttl(data.get("ttl")),
        source=source,
    )
