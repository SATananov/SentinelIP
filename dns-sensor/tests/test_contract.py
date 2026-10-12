"""Deterministic contract check against the unchanged repository backend."""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from api.schemas import DnsTelemetryCreate
from database.telemetry import provision_sensor, list_dns_observations
from services.telemetry_ingestion import ingest_dns
from sentinelip_dns.parser import parse


def test_payload_ingestion_and_replay(record, tmp_path):
    path = tmp_path / "contract.db"
    sensor, token = provision_sensor("fixture", "Fixture DNS", "DNS", None, "DOMAIN_ONLY", 30, path)
    event = parse(json.dumps(record), "fixture-jsonl")
    payload = DnsTelemetryCreate.model_validate(event.payload()).model_dump()
    assert "device_id" not in payload and "sensor_token" not in payload and "source" not in payload
    first = ingest_dns(sensor["id"], token, payload, path)
    replay = ingest_dns(sensor["id"], token, payload, path)
    assert first["id"] == replay["id"] and replay["idempotent"]
    rows = list_dns_observations(sensor["id"], path)
    assert len(rows) == 1
    assert rows[0]["source"] == "dns"
    assert json.loads(rows[0]["metadata_json"]) == {"source": "fixture-jsonl"}
    assert rows[0]["queried_domain"] == "login.example.test"
    assert rows[0]["device_id"] is None
    assert rows[0]["retention_until"]
