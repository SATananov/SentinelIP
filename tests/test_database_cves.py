import sqlite3
from datetime import datetime

import pytest

from database.cves import (
    create_cve_match,
    create_cve_record,
    get_cve_match_by_stable_key,
    list_cve_matches,
    list_cve_records,
)
from database.db import initialize_database
from database.inventory import create_device
from database.networks import create_network
from database.services import create_port, create_service
from services.cve_models import CveMatch, CveRecord


def setup_context(db_path):
    network = create_network("192.168.1.0/24", "LAN", "", True, True, db_path)
    device = create_device("network:1:mac:aa:bb:cc:dd:ee:ff", 1, "aa:bb:cc:dd:ee:ff", "server", "Vendor", "2026-10-11T11:59:00", "2026-10-11T11:59:00", "192.168.1.20", "ONLINE", "HIGH", db_path)
    port = create_port(device["id"], 22, "tcp", "open", "2026-10-11T12:00:00", "2026-10-11T12:00:00", db_path)
    service = create_service(device["id"], port["id"], "ssh", "OpenSSH", "9.6", None, "HIGH", "2026-10-11T12:00:00", "2026-10-11T12:00:00", db_path)
    return network, device, port, service


def test_cve_migrations_are_idempotent(tmp_path):
    db_path = tmp_path / "test.db"
    initialize_database(db_path)
    initialize_database(db_path)
    with sqlite3.connect(db_path) as connection:
        tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
    assert {"cve_records", "cve_matches"} <= tables


def test_cve_record_and_match_persistence(tmp_path):
    db_path = tmp_path / "test.db"
    _, device, port, service = setup_context(db_path)
    record = create_cve_record(CveRecord("CVE-2099-0001", "local-test-feed", "openssh", ">=9.0,<9.7"), db_path)
    match = create_cve_match(
        CveMatch(
            cve_record_id=record["id"], cve_id=record["cve_id"], device_id=device["id"], service_id=service["id"], port_id=port["id"], status="REVIEW", confidence="HIGH", observed_product="openssh", observed_version="9.6", evidence_source="nmap", evidence_observed_at=datetime(2026, 10, 11, 12, 0, 0), match_reason="Range match.", stable_key="service:1:cve:1:version:9.6", first_seen=datetime(2026, 10, 11, 12, 0, 0), last_seen=datetime(2026, 10, 11, 12, 0, 0),
        ),
        db_path,
    )
    assert len(list_cve_records(db_path)) == 1
    assert get_cve_match_by_stable_key(match["stable_key"], db_path)["id"] == match["id"]
    assert len(list_cve_matches(db_path)) == 1


def test_cve_match_stable_key_is_unique(tmp_path):
    db_path = tmp_path / "test.db"
    _, device, port, service = setup_context(db_path)
    record = create_cve_record(CveRecord("CVE-2099-0001", "local-test-feed", "openssh", "9.6"), db_path)
    values = dict(cve_record_id=record["id"], cve_id=record["cve_id"], device_id=device["id"], service_id=service["id"], port_id=port["id"], status="REVIEW", confidence="HIGH", observed_product="openssh", observed_version="9.6", evidence_source="nmap", evidence_observed_at=datetime(2026, 10, 11, 12, 0, 0), match_reason="Exact match.", stable_key="same", first_seen=datetime(2026, 10, 11, 12, 0, 0), last_seen=datetime(2026, 10, 11, 12, 0, 0))
    create_cve_match(CveMatch(**values), db_path)
    with pytest.raises(sqlite3.IntegrityError):
        create_cve_match(CveMatch(**values), db_path)