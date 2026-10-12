import json
from dataclasses import FrozenInstanceError
from uuid import UUID
import pytest
from sentinelip_dns.parser import parse
from sentinelip_dns.normalize import EvidenceError


@pytest.mark.parametrize("kind", ["A", "AAAA", "CNAME", "MX", "TXT", "PTR", "OTHER", "HTTPS"])
def test_types(record, kind):
    record["query_type"] = kind
    event = parse(json.dumps(record), "fixture-jsonl")
    assert event.query_type == ("OTHER" if kind == "HTTPS" else kind)


@pytest.mark.parametrize("status", ["NOERROR", "NXDOMAIN", "SERVFAIL", "REFUSED", "OTHER"])
def test_status(record, status):
    record.update(response_status=status, resolved_addresses=[])
    event = parse(json.dumps(record), "fixture-jsonl")
    assert event.response_status == status
    assert event.resolved_addresses == ()
    assert event.ttl is None and event.resolver is None


def test_answers_and_identity(record):
    record.update(query_type="AAAA", resolved_addresses=["2001:0db8::1", "192.0.2.10", "2001:db8::1"], resolver="127.0.0.53", ttl=60)
    first = parse(json.dumps(record), "fixture-jsonl")
    assert first.resolved_addresses == ("2001:db8::1", "192.0.2.10")
    assert first.resolver == "127.0.0.53" and first.ttl == 60
    assert UUID(first.external_event_id).version == 4
    assert first.external_event_id != parse(json.dumps(record), "fixture-jsonl").external_event_id
    with pytest.raises(FrozenInstanceError):
        first.ttl = 2


@pytest.mark.parametrize("field,value", [("queried_domain", "bad/domain"), ("resolved_addresses", ["bad"]),
    ("resolved_addresses", "192.0.2.1"), ("resolved_addresses", [123]), ("query_type", None),
    ("response_status", None), ("response_status", "TIMEOUT"), ("response_status", "ERROR"),
    ("observed_at", "2026-01-01"), ("observed_at", "9999-01-01T00:00:00Z"),
    ("device_id", 1), ("metadata", {"cookie": "secret"}), ("resolver", "http://resolver.test")])
def test_bad_evidence(record, field, value):
    record[field] = value
    with pytest.raises(EvidenceError):
        parse(json.dumps(record), "fixture-jsonl")


@pytest.mark.parametrize("line", ["{", "[]", "null", "{}", '{"x":1,"x":2}', "x"*65537])
def test_malformed(line):
    with pytest.raises(EvidenceError):
        parse(line, "fixture-jsonl")
