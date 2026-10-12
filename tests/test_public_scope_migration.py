from datetime import datetime

import database.migrations as migrations
from database.cves import create_cve_record, create_cve_match, list_device_cve_matches
from database.db import get_connection, initialize_database
from database.findings import list_device_findings
from database.inventory import create_device, save_observation
from database.networks import create_network
from database.services import create_port, create_service
from services.cve_models import CveMatch, CveRecord


def test_device_and_finding_rebuild_preserves_all_existing_relations(
    monkeypatch, tmp_path
):
    path = tmp_path / "migration-26-to-27.db"
    all_migrations = migrations.MIGRATIONS
    monkeypatch.setattr(migrations, "MIGRATIONS", all_migrations[:26])
    network = create_network("192.168.44.0/24", "Lab", "", True, True, path)
    device = create_device(
        stable_key="network:1:ip:192.168.44.10",
        network_id=network["id"],
        mac_address="02:00:00:00:44:10",
        hostname="legacy-host",
        vendor="Fixture Vendor",
        first_seen="2026-10-12T10:00:00",
        last_seen="2026-10-12T10:00:00",
        last_ip_address="192.168.44.10",
        status="ONLINE",
        identity_confidence="LOW",
        db_path=path,
    )
    save_observation(
        device_id=device["id"],
        network_id=network["id"],
        ip_address=device["last_ip_address"],
        mac_address=device["mac_address"],
        hostname=device["hostname"],
        vendor=device["vendor"],
        status="ONLINE",
        observed_at=device["last_seen"],
        source="migration-test",
        db_path=path,
    )
    port = create_port(
        device["id"], 22, "tcp", "open", device["last_seen"], device["last_seen"], path
    )
    service = create_service(
        device["id"], port["id"], "ssh", "OpenSSH", "9.6", None,
        "HIGH", device["last_seen"], device["last_seen"], path,
    )
    finding_at = datetime.fromisoformat(device["last_seen"])
    with get_connection(path) as connection:
        cursor = connection.execute(
            """INSERT INTO findings (
                finding_type, device_id, network_id, port_id, service_id,
                change_id, severity, confidence, status, title, reason,
                recommendation, evidence_type, source, rule_id, rule_version,
                stable_key, first_seen, last_seen, resolved_at, metadata_json,
                created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, ?, ?)""",
            (
                "CVE_REVIEW", device["id"], network["id"], port["id"], service["id"],
                "LOW", "MEDIUM", "OPEN", "Legacy review", "Migration fixture",
                "Review local evidence.", "CVE_CORRELATION", "test", "test.rule",
                "1", "migration-finding-key", device["last_seen"], device["last_seen"],
                device["last_seen"], device["last_seen"],
            ),
        )
        finding_id = cursor.lastrowid
    cve_record = create_cve_record(
        CveRecord(
            cve_id="CVE-2099-0099",
            source="migration-test",
            product="OpenSSH",
            affected_version_expression=">=9.0,<9.7",
        ),
        path,
    )
    create_cve_match(
        CveMatch(
            cve_record_id=cve_record["id"],
            cve_id=cve_record["cve_id"],
            device_id=device["id"],
            service_id=service["id"],
            port_id=port["id"],
            status="REVIEW",
            confidence="HIGH",
            observed_product="OpenSSH",
            observed_version="9.6",
            evidence_source="migration-test",
            evidence_observed_at=finding_at,
            match_reason="fixture evidence",
            stable_key="migration-cve-match-key",
            first_seen=finding_at,
            last_seen=finding_at,
            finding_id=finding_id,
        ),
        path,
    )

    monkeypatch.setattr(migrations, "MIGRATIONS", all_migrations)
    initialize_database(path)
    initialize_database(path)

    with get_connection(path) as connection:
        migrated_device = connection.execute(
            """SELECT id, stable_key, network_id, scope_id, mac_address, hostname,
                      vendor, first_seen, last_seen, last_ip_address, status,
                      identity_confidence, created_at, updated_at
               FROM devices WHERE id=?""",
            (device["id"],),
        ).fetchone()
        assert migrated_device == (
            device["id"],
            device["stable_key"],
            network["id"],
            None,
            "02:00:00:00:44:10",
            "legacy-host",
            "Fixture Vendor",
            "2026-10-12T10:00:00",
            "2026-10-12T10:00:00",
            "192.168.44.10",
            "ONLINE",
            "LOW",
            device["created_at"],
            device["updated_at"],
        )
        migrated_observation = connection.execute(
            """SELECT device_id, network_id, ip_address, mac_address, hostname,
                      vendor, status, observed_at, source
               FROM device_observations WHERE device_id=?""",
            (device["id"],),
        ).fetchone()
        assert migrated_observation == (
            device["id"], network["id"], "192.168.44.10", "02:00:00:00:44:10",
            "legacy-host", "Fixture Vendor", "ONLINE", "2026-10-12T10:00:00",
            "migration-test",
        )
        assert connection.execute(
            "SELECT id, cidr, name, description, authorized, enabled, created_at, updated_at FROM networks WHERE id=?",
            (network["id"],),
        ).fetchone() == (
            network["id"], "192.168.44.0/24", "Lab", "", 1, 1,
            network["created_at"], network["updated_at"],
        )
        assert connection.execute(
            "SELECT COUNT(*) FROM ports WHERE device_id=?", (device["id"],)
        ).fetchone()[0] == 1
        assert connection.execute(
            "SELECT COUNT(*) FROM services WHERE device_id=?", (device["id"],)
        ).fetchone()[0] == 1
        migrated_finding = connection.execute(
            """SELECT id, device_id, network_id, scope_id, port_id, service_id,
                      stable_key, first_seen, last_seen, created_at, updated_at
               FROM findings WHERE id=?""",
            (finding_id,),
        ).fetchone()
        assert migrated_finding == (
            finding_id, device["id"], network["id"], None, port["id"], service["id"],
            "migration-finding-key", "2026-10-12T10:00:00", "2026-10-12T10:00:00",
            "2026-10-12T10:00:00", "2026-10-12T10:00:00",
        )
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
        assert connection.execute(
            "SELECT device_id, port_id, service_id, finding_id, stable_key FROM cve_matches"
        ).fetchone() == (
            device["id"], port["id"], service["id"], finding_id,
            "migration-cve-match-key",
        )
    assert len(list_device_cve_matches(device["id"], path)) == 1
    assert len(list_device_findings(device["id"], path)) == 1
