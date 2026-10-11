import sqlite3
from datetime import datetime

import pytest

from database.changes import create_change
from database.db import initialize_database
from database.findings import (
    create_finding,
    get_finding,
    get_finding_by_stable_key,
    list_device_findings,
    list_findings,
    list_findings_by_status,
    list_findings_by_type,
    list_network_findings,
    touch_finding,
    update_finding_status,
)
from database.inventory import create_device
from database.networks import create_network
from services.change_models import ChangeRecord
from services.finding_models import FindingRecord


def setup_context(db_path):
    network = create_network(
        "192.168.1.0/24", "Test LAN", "", True, True, db_path
    )
    device = create_device(
        "network:1:mac:aa:bb:cc:dd:ee:ff",
        network["id"],
        "aa:bb:cc:dd:ee:ff",
        "server",
        "Vendor",
        "2026-10-11T11:59:00",
        "2026-10-11T11:59:00",
        "192.168.1.20",
        "ONLINE",
        "HIGH",
        db_path,
    )
    return network, device


def make_finding(device_id=1, network_id=1, stable_key="finding:1"):
    return FindingRecord(
        finding_type="DATABASE_SERVICE_EXPOSED",
        device_id=device_id,
        network_id=network_id,
        severity="MEDIUM",
        confidence="HIGH",
        status="OPEN",
        title="Database service exposure",
        reason="An explicit database service was observed.",
        recommendation="Review network exposure and access controls.",
        evidence_type="SERVICE_OBSERVATION",
        source="risk-engine",
        rule_id="risk.database.mysql",
        rule_version="1",
        stable_key=stable_key,
        first_seen=datetime(2026, 10, 11, 12, 0, 0),
        last_seen=datetime(2026, 10, 11, 12, 0, 0),
        metadata={"product": "MySQL"},
    )


def test_findings_migration_is_idempotent_and_indexed(tmp_path):
    db_path = tmp_path / "test.db"
    initialize_database(db_path)
    initialize_database(db_path)

    with sqlite3.connect(db_path) as connection:
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
        indexes = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'index'"
            )
        }

    assert "findings" in tables
    assert "idx_findings_device_status" in indexes
    assert "idx_findings_last_seen" in indexes
    assert "idx_findings_service" in indexes


def test_finding_crud_filters_and_status_updates(tmp_path):
    db_path = tmp_path / "test.db"
    network, device = setup_context(db_path)
    first = create_finding(
        make_finding(device["id"], network["id"], "finding:first"),
        db_path,
    )

    assert get_finding(first["id"], db_path)["metadata"] == {"product": "MySQL"}
    assert get_finding_by_stable_key("finding:first", db_path)["id"] == first["id"]
    assert len(list_findings(db_path)) == 1
    assert len(list_device_findings(device["id"], db_path)) == 1
    assert len(list_network_findings(network["id"], db_path)) == 1
    assert len(list_findings_by_status("OPEN", db_path)) == 1
    assert len(list_findings_by_type("DATABASE_SERVICE_EXPOSED", db_path)) == 1

    touched = touch_finding(
        first["id"], datetime(2026, 10, 11, 12, 5, 0), db_path
    )
    assert touched["first_seen"] == first["first_seen"]
    assert touched["last_seen"] == "2026-10-11T12:05:00"

    acknowledged = update_finding_status(first["id"], "ACKNOWLEDGED", db_path=db_path)
    assert acknowledged["status"] == "ACKNOWLEDGED"


def test_stable_key_is_unique(tmp_path):
    db_path = tmp_path / "test.db"
    network, device = setup_context(db_path)
    create_finding(make_finding(device["id"], network["id"], "finding:same"), db_path)

    with pytest.raises(sqlite3.IntegrityError):
        create_finding(make_finding(device["id"], network["id"], "finding:same"), db_path)