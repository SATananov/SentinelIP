import base64
import struct
import zlib

import pytest
from fastapi import HTTPException

import api.main as api_main
from api.recon_evidence import EvidenceCreate, verify_authorized_device_scope
from database.db import get_connection, initialize_database
from database.inventory import create_device
from database.networks import create_network
from database.scopes import get_scope_for_network


def _chunk(name, data):
    return struct.pack(">I", len(data)) + name + data + struct.pack(">I", zlib.crc32(name + data) & 0xFFFFFFFF)


def _png():
    return (b"\x89PNG\r\n\x1a\n" + _chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0))
            + _chunk(b"IDAT", zlib.compress(b"\x00\x00\x80\x00")) + _chunk(b"IEND", b""))


@pytest.fixture
def capture_db(monkeypatch, tmp_path):
    path = tmp_path / "evidence-capture.sqlite3"
    initialize_database(path)
    monkeypatch.setattr(api_main, "DB_PATH", path)
    network = create_network("192.168.88.0/24", "Capture lab", "", True, True, path)
    scope = get_scope_for_network(network["id"], path)
    device = create_device(
        stable_key=f"network:{network['id']}:ip:192.168.88.5", network_id=network["id"],
        mac_address=None, hostname="capture-host", vendor="Lab", first_seen="2026-11-10",
        last_seen="2026-11-10", last_ip_address="192.168.88.5", status="ONLINE",
        identity_confidence="HIGH", db_path=path,
    )
    return path, scope, network, device


def _endpoint(path, method):
    for route in api_main.app.routes:
        if getattr(route, "path", None) == path and method in (getattr(route, "methods", None) or set()):
            return route.endpoint
    raise AssertionError(f"Missing route: {method} {path}")


def test_existing_evidence_api_persists_capture_and_finding_link(capture_db):
    path, _, network, device = capture_db
    with get_connection(path) as connection:
        cursor = connection.execute(
            """INSERT INTO findings (finding_type,device_id,network_id,severity,confidence,status,title,reason,
               recommendation,evidence_type,source,rule_id,rule_version,stable_key,first_seen,last_seen,created_at,updated_at)
               VALUES ('SERVICE',?,?, 'MEDIUM','HIGH','OPEN','Recorded finding','Observed evidence',
               'Review the service','SERVICE','fixture','fixture.rule','1','capture-finding',
               '2026-11-10','2026-11-10','2026-11-10','2026-11-10')""",
            (device["id"], network["id"]),
        )
        finding_id = cursor.lastrowid
    png = _png()
    payload = EvidenceCreate(filename="sentinelip-device-1-finding-1.png", description="Capture description",
                             image_base64=base64.b64encode(png).decode(), finding_id=finding_id)
    created = _endpoint("/recon/devices/{device_id}/evidence", "POST")(device["id"], payload)
    assert created["finding_id"] == finding_id
    rows = _endpoint("/recon/devices/{device_id}/evidence", "GET")(device["id"])
    assert rows[0]["id"] == created["id"]
    image = _endpoint("/recon/devices/{device_id}/evidence/{evidence_id}", "GET")(device["id"], created["id"])
    assert base64.b64decode(image["image_base64"]) == png
    assert verify_authorized_device_scope(device["id"], path)["id"] == device["id"]


def test_evidence_scope_recheck_blocks_disabled_target(capture_db):
    path, scope, _, device = capture_db
    with get_connection(path) as connection:
        connection.execute("UPDATE authorized_scopes SET enabled=0 WHERE id=?", (scope["id"],))
    with pytest.raises(HTTPException) as rejected:
        verify_authorized_device_scope(device["id"], path)
    assert rejected.value.status_code == 403


def test_evidence_api_rejects_cross_device_finding_association(capture_db):
    path, _, network, device = capture_db
    other = create_device(
        stable_key=f"network:{network['id']}:ip:192.168.88.6", network_id=network["id"],
        mac_address=None, hostname=None, vendor=None, first_seen="2026-11-10",
        last_seen="2026-11-10", last_ip_address="192.168.88.6", status="ONLINE",
        identity_confidence="LOW", db_path=path,
    )
    with get_connection(path) as connection:
        cursor = connection.execute(
            """INSERT INTO findings (finding_type,device_id,network_id,severity,confidence,status,title,reason,
               recommendation,evidence_type,source,rule_id,rule_version,stable_key,first_seen,last_seen,created_at,updated_at)
               VALUES ('SERVICE',?,?, 'LOW','LOW','OPEN','Other finding','Other evidence',
               'Review','SERVICE','fixture','fixture.rule','1','other-finding',
               '2026-11-10','2026-11-10','2026-11-10','2026-11-10')""",
            (other["id"], network["id"]),
        )
        finding_id = cursor.lastrowid
    body = EvidenceCreate(filename="capture.png", description="Capture", image_base64=base64.b64encode(_png()).decode(), finding_id=finding_id)
    with pytest.raises(HTTPException) as rejected:
        _endpoint("/recon/devices/{device_id}/evidence", "POST")(device["id"], body)
    assert rejected.value.status_code == 422
