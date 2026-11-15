import json
import sqlite3
from datetime import datetime

import pytest
from fastapi import HTTPException

import api.recon_assessment_report as report_module
from api.recon_assessment_report import build_assessment_report
from api.recon_evidence import ensure_table
from database.db import get_connection, initialize_database
from database.inventory import create_device, create_scope_device
from database.networks import create_network
from database.scopes import create_scope, get_scope_for_network
from database.services import create_port, create_service, save_port_observation


@pytest.fixture
def db_path(tmp_path):
    path = tmp_path / "assessment-report.sqlite3"
    initialize_database(path)
    return path


def _device(network, path, ip="192.168.48.8"):
    return create_device(
        stable_key=f"network:{network['id']}:ip:{ip}", network_id=network["id"],
        mac_address=None, hostname="lab-host", vendor="Example", first_seen="2026-11-01T00:00:00",
        last_seen="2026-11-01T00:00:00", last_ip_address=ip, status="ONLINE",
        identity_confidence="HIGH", db_path=path,
    )


def test_private_snapshot_contains_inventory_and_evidence_without_mutation(db_path):
    network = create_network("192.168.48.0/24", "Lab", "", True, True, db_path)
    scope = get_scope_for_network(network["id"], db_path)
    device = _device(network, db_path)
    port = create_port(device["id"], 443, "tcp", "open", "2026-11-01T00:00:00", "2026-11-01T00:00:00", db_path)
    service = create_service(device["id"], port["id"], "https", "Example HTTP", "2.1", None,
                             "HIGH", "2026-11-01T00:00:00", "2026-11-01T00:00:00", db_path)
    with get_connection(db_path) as connection:
        connection.execute(
            """INSERT INTO findings (finding_type,device_id,network_id,severity,confidence,status,title,reason,
               recommendation,evidence_type,source,rule_id,rule_version,stable_key,first_seen,last_seen,created_at,updated_at)
               VALUES ('SERVICE',?,?, 'HIGH','HIGH','OPEN','Outdated service','Version requires review',
               'Upgrade to a supported release','SERVICE','test','rule.test','1','test-finding',
               '2026-11-01','2026-11-01','2026-11-01','2026-11-01')""",
            (device["id"], network["id"]),
        )
        connection.execute(
            """INSERT INTO port_observations (device_id,port_id,ip_address,port_number,transport,state,observed_at,source)
               VALUES (?,?,?,?,?,?,?,?)""",
            (device["id"], port["id"], device["last_ip_address"], 443, "tcp", "open", "2026-11-01T00:00:00", "fixture"),
        )
        ensure_table(connection)
        connection.execute(
            """INSERT INTO recon_evidence (device_id,finding_id,filename,description,media_type,image_data,created_at)
               VALUES (?,?,?,?,?,?,?)""",
            (device["id"], None, "proof.png", "Service banner", "image/png", b"PNG", "2026-11-02T00:00:00"),
        )
        before = {table: connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                  for table in ("devices", "ports", "services", "findings", "recon_evidence")}

    report = build_assessment_report(scope["id"], db_path)
    assert report["schema_version"] == "1.0"
    assert report["report_id"]
    assert report["generated_at"].endswith("+00:00")
    assert report["snapshot_kind"] == "generated_report_snapshot"
    assert report["historical_scan_session"] is False
    assert report["devices"][0]["device"]["id"] == device["id"]
    assert report["devices"][0]["ports"][0]["port_number"] == 443
    assert report["devices"][0]["services"][0]["id"] == service["id"]
    assert "http_tls_observations" not in report["devices"][0]
    assert "http_tls_observations" not in report["devices"][0]["truncation"]
    assert report["findings"][0]["title"] == "Outdated service"
    assert report["findings"][0]["finding_status"] == "OPEN"
    assert report["findings"][0]["verification_status"] == "NOT_RECORDED"
    assert report["recommendations"] == ["Upgrade to a supported release"]
    assert report["scan_metadata"]["observations"][0]["sources"] == ["fixture"]
    evidence = report["devices"][0]["evidence"][0]
    assert evidence["filename"] == "proof.png"
    assert evidence["created_at"] == "2026-11-02T00:00:00"
    assert "image_data" not in evidence and "image_base64" not in evidence
    with get_connection(db_path) as connection:
        after = {table: connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                 for table in before}
    assert after == before


def test_public_scope_empty_and_disabled_scope_rejected(db_path):
    scope = create_scope(scope_type="PUBLIC_IPV4", canonical_target="8.8.8.8", name="Public lab",
                         authorized=True, enabled=True, authorization_confirmed_at="2026-11-01",
                         authorization_confirmation_version="fixture", authorization_source="fixture",
                         db_path=db_path)
    report = build_assessment_report(scope["id"], db_path)
    assert report["devices"] == []
    assert report["coverage"]["discovered_assets"] == 0
    with get_connection(db_path) as connection:
        connection.execute("UPDATE authorized_scopes SET enabled=0 WHERE id=?", (scope["id"],))
    with pytest.raises(HTTPException) as rejected:
        build_assessment_report(scope["id"], db_path)
    assert rejected.value.status_code == 403
    with get_connection(db_path) as connection:
        connection.execute("UPDATE authorized_scopes SET enabled=1,authorized=0 WHERE id=?", (scope["id"],))
    with pytest.raises(HTTPException) as unauthorized:
        build_assessment_report(scope["id"], db_path)
    assert unauthorized.value.status_code == 403


def test_private_scope_isolation_and_invalid_identifiers(db_path, monkeypatch):
    first = create_network("192.168.48.0/24", "First", "", True, True, db_path)
    second = create_network("192.168.49.0/24", "Second", "", True, True, db_path)
    first_scope = get_scope_for_network(first["id"], db_path)
    first_device = _device(first, db_path)
    _device(first, db_path, "192.168.48.9")
    second_device = _device(second, db_path, "192.168.49.8")
    with get_connection(db_path) as connection:
        ensure_table(connection)
        connection.execute("INSERT INTO recon_evidence (device_id,filename,description,media_type,image_data,created_at) VALUES (?,?,?,?,?,?)",
                           (second_device["id"], "secret.png", "other scope", "image/png", b"secret", "2026-11-02"))
    monkeypatch.setattr(report_module, "MAX_DEVICES", 1)
    report = build_assessment_report(first_scope["id"], db_path)
    assert len(report["devices"]) == 1
    assert report["devices"][0]["device"]["id"] == first_device["id"]
    assert report["truncation"]["devices"] is True
    assert report["coverage"]["data_incomplete"] is True
    with pytest.raises(HTTPException) as invalid:
        build_assessment_report(0, db_path)
    assert invalid.value.status_code == 422
    with pytest.raises(HTTPException) as missing:
        build_assessment_report(99999, db_path)
    assert missing.value.status_code == 404


def test_public_ip_membership_and_cve_match_stays_unverified(db_path):
    scope = create_scope(scope_type="PUBLIC_IPV4", canonical_target="8.8.8.8", name="Target",
                         authorized=True, enabled=True, authorization_confirmed_at="2026-11-01",
                         authorization_confirmation_version="fixture", authorization_source="fixture",
                         db_path=db_path)
    device = create_scope_device(scope["id"], ip_address="8.8.8.8", first_seen="2026-11-01",
                                last_seen="2026-11-01", status="ONLINE", db_path=db_path)
    port = create_port(device["id"], 443, "tcp", "open", "2026-11-01", "2026-11-01", db_path)
    service = create_service(device["id"], port["id"], "https", "Example", "1", None,
                             "HIGH", "2026-11-01", "2026-11-01", db_path)
    with get_connection(db_path) as connection:
        cursor = connection.execute(
            """INSERT INTO cve_records (cve_id,source,product,version_expression,created_at,updated_at)
               VALUES ('CVE-2026-1234','fixture','example','<2','2026-11-01','2026-11-01')"""
        )
        record_id = cursor.lastrowid
        connection.execute(
            """INSERT INTO cve_matches (cve_record_id,device_id,port_id,service_id,status,confidence,
               evidence_source,evidence_observed_at,match_reason,stable_key,first_seen,last_seen,created_at,updated_at)
               VALUES (?,?,?,?,'POSSIBLE_MATCH','LOW','fixture','2026-11-01','version match','cve-test',
               '2026-11-01','2026-11-01','2026-11-01','2026-11-01')""",
            (record_id, device["id"], port["id"], service["id"]),
        )
    report = build_assessment_report(scope["id"], db_path)
    assert report["devices"][0]["cve_matches"][0]["match_status"] == "POSSIBLE_MATCH"
    assert report["coverage"]["unverified_cve_matches"] == 1
    assert report["coverage"]["confirmed_findings"] == 0


def _insert_endpoint_observation(connection, scope, device, port, observation_id, observed_at,
                                 *, scheme="http", tls_status=None, target_ip=None):
    run_id = f"report-run-{observation_id}"
    target_ip = target_ip or device["last_ip_address"]
    run_status = "COMPLETED" if tls_status != "FAILED" else "FAILED"
    target_status = "COMPLETED" if tls_status != "FAILED" else "FAILED"
    connection.execute(
        """INSERT INTO recon_scan_runs
           (id,scope_id,profile,scanner,scanner_version,started_at,completed_at,status,error_category)
           VALUES (?,?,?,?,?,?,?,?,?)""",
        (run_id, scope["id"], "http_endpoint_fingerprint", "sentinelip-http-tls-fingerprint",
         "1.0", observed_at, observed_at, run_status,
         "untrusted_certificate" if tls_status == "FAILED" else None),
    )
    target_id = connection.execute(
        """INSERT INTO recon_scan_targets
           (run_id,target_ip,device_id,started_at,completed_at,outcome,error_category)
           VALUES (?,?,?,?,?,?,?)""",
        (run_id, target_ip, device["id"], observed_at, observed_at, target_status,
         "untrusted_certificate" if tls_status == "FAILED" else None),
    ).lastrowid
    failed = tls_status == "FAILED"
    connection.execute(
        """INSERT INTO http_endpoint_observations
           (id,scope_id,device_id,port_id,scan_target_id,scheme,target_ip,approved_hostname,
            observed_at,source,outcome,error_category,status_code,response_headers_json,
            content_type,content_length,server_identifier,redirect_location)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (observation_id, scope["id"], device["id"], port["id"], target_id, scheme, target_ip,
         None, observed_at, "https-tls-head-v1" if scheme == "https" else "http-head-v1",
         "TLS_VERIFICATION_FAILED" if failed else "RESPONSE_RECEIVED",
         "untrusted_certificate" if failed else None, None if failed else 200,
         "{}" if failed else '{"date":"Sun, 15 Nov 2026 12:30:00 GMT"}',
         None if failed else "text/plain", None if failed else 0,
         None if failed else "self-reported <Server>", None),
    )
    if tls_status:
        verified = tls_status == "VERIFIED"
        connection.execute(
            """INSERT INTO http_tls_observations
               (endpoint_observation_id,verification_status,hostname_verification,ip_address_verification,
                verification_name,protocol_version,cipher_name,cipher_protocol,cipher_bits,
                certificate_subject_json,certificate_issuer_json,not_before,not_after,
                subject_alt_names_json,sha256_fingerprint,error_category)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (observation_id, tls_status, None, "MATCHED" if verified else "NOT_COMPLETED",
             target_ip, "TLSv1.3" if verified else None,
             "TLS_AES_256_GCM_SHA384" if verified else None, "TLSv1.3" if verified else None,
             256 if verified else None,
             '[{"name":"commonName","value":"fixture.example"}]' if verified else None,
             '[{"name":"commonName","value":"fixture-ca"}]' if verified else None,
             "2026-01-01T00:00:00+00:00" if verified else None,
             "2027-01-01T00:00:00+00:00" if verified else None,
             '[{"type":"IP Address","value":"192.168.48.8"}]' if verified else None,
             "a" * 64 if verified else None,
             None if verified else "untrusted_certificate"),
        )


def test_http_tls_report_projection_is_scope_bound_and_preserves_verified_and_failed_facts(db_path):
    network = create_network("192.168.48.0/24", "Lab", "", True, True, db_path)
    scope = get_scope_for_network(network["id"], db_path)
    device = _device(network, db_path)
    port = create_port(device["id"], 443, "tcp", "open", "2026-11-01", "2026-11-01", db_path)
    save_port_observation(device_id=device["id"], port_id=port["id"], ip_address=device["last_ip_address"],
                         port_number=443, transport="tcp", state="open", observed_at="2026-11-01",
                         source="fixture", db_path=db_path)
    other_network = create_network("192.168.49.0/24", "Other", "", True, True, db_path)
    other_scope = get_scope_for_network(other_network["id"], db_path)
    other_device = _device(other_network, db_path, "192.168.49.8")
    other_port = create_port(other_device["id"], 443, "tcp", "open", "2026-11-01", "2026-11-01", db_path)
    with get_connection(db_path) as connection:
        _insert_endpoint_observation(connection, scope, device, port, 101,
                                     "2026-11-15T12:00:00+00:00", scheme="https", tls_status="VERIFIED")
        _insert_endpoint_observation(connection, scope, device, port, 102,
                                     "2026-11-15T12:00:00+00:00", scheme="https", tls_status="FAILED")
        _insert_endpoint_observation(connection, other_scope, other_device, other_port, 103,
                                     "2026-11-15T13:00:00+00:00")
    report = build_assessment_report(scope["id"], db_path)
    observations = report["devices"][0]["http_tls_observations"]
    assert [item["id"] for item in observations] == [102, 101]
    assert observations[0]["outcome"] == "TLS_VERIFICATION_FAILED"
    assert observations[0]["tls"]["verification_status"] == "FAILED"
    assert "certificate_subject" not in observations[0]["tls"]
    assert observations[1]["tls"]["certificate_subject"][0]["value"] == "fixture.example"
    assert observations[1]["server_identifier"]["confidence"] == "LOW"
    assert observations[1]["scan"]["run_id"] == "report-run-101"
    assert report["schema_version"] == "1.0"
    serialized = json.dumps(report)
    assert "report-run-103" not in serialized
    assert "Authorization" not in serialized and "Set-Cookie" not in serialized


def test_http_tls_report_caps_observations_and_marks_truncation(db_path, monkeypatch):
    network = create_network("192.168.48.0/24", "Lab", "", True, True, db_path)
    scope = get_scope_for_network(network["id"], db_path)
    device = _device(network, db_path)
    port = create_port(device["id"], 443, "tcp", "open", "2026-11-01", "2026-11-01", db_path)
    save_port_observation(device_id=device["id"], port_id=port["id"], ip_address=device["last_ip_address"],
                         port_number=443, transport="tcp", state="open", observed_at="2026-11-01",
                         source="fixture", db_path=db_path)
    monkeypatch.setattr(report_module, "MAX_HTTP_TLS_OBSERVATIONS_PER_DEVICE", 2)
    monkeypatch.setattr(report_module, "MAX_HTTP_TLS_OBSERVATIONS_PER_REPORT", 2)
    with get_connection(db_path) as connection:
        for index in range(1, 4):
            _insert_endpoint_observation(connection, scope, device, port, 200 + index,
                                         f"2026-11-15T12:00:0{index}+00:00")
    report = build_assessment_report(scope["id"], db_path)
    device_report = report["devices"][0]
    assert [item["id"] for item in device_report["http_tls_observations"]] == [203, 202]
    assert device_report["truncation"]["http_tls_observations"] is True
    assert report["coverage"]["data_incomplete"] is True
