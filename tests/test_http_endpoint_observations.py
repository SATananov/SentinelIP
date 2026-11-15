import json
import sqlite3

import pytest

from database import migrations
from database.db import get_connection, initialize_database
from database.inventory import create_device, create_scope_device
from database.networks import create_network
from database.scopes import create_hostname_scope, get_scope_for_network
from database.services import create_port, save_port_observation
from services.http_endpoint_observations import (
    HttpEndpointPersistenceError,
    MAX_HTTP_ENDPOINT_OBSERVATIONS_PER_SCOPE,
    persist_http_endpoint_observation,
)


def _query(path, sql, params=()):
    connection = sqlite3.connect(path)
    try:
        return connection.execute(sql, params).fetchall()
    finally:
        connection.close()


@pytest.fixture
def endpoint_db(tmp_path):
    path = tmp_path / "endpoint-observations.db"
    initialize_database(path)
    network = create_network("192.168.1.0/24", "Persistence tests", "", True, True, path)
    scope = get_scope_for_network(network["id"], path)
    device = create_device(
        stable_key="persistence-test-device", network_id=network["id"], mac_address=None,
        hostname=None, vendor=None, first_seen="2026-10-01T00:00:00+00:00",
        last_seen="2026-10-01T00:00:00+00:00", last_ip_address="192.168.1.20",
        status="ONLINE", identity_confidence="LOW", db_path=path,
    )
    port = create_port(device["id"], 8080, "tcp", "open", "2026-10-01T00:00:00+00:00",
                       "2026-10-01T00:00:00+00:00", path)
    save_port_observation(
        device_id=device["id"], port_id=port["id"], ip_address="192.168.1.20",
        port_number=8080, transport="tcp", state="open", observed_at="2026-10-01T00:00:00+00:00",
        source="nmap", db_path=path,
    )
    return path, scope, device, port


def _http_result(scope, device, port, **updates):
    result = {
        "scope_id": scope["id"], "device_id": device["id"], "port_id": port["id"],
        "scheme": "http", "target_ip": "192.168.1.20", "host": "192.168.1.20:8080",
        "observed_at": "2026-11-15T12:30:00+00:00", "source": "http-head-v1",
        "status_code": 200, "response_headers": {"date": "Sun, 15 Nov 2026 12:30:00 GMT"},
        "content_type": "text/plain", "content_length": 0,
        "server_identifier": {"value": "example", "confidence": "LOW", "source": "http_response_header"},
        "redirect_location": None, "outcome": "RESPONSE_RECEIVED", "error_category": None,
    }
    result.update(updates)
    return result


def _tls_result(scope, device, port, *, outcome="RESPONSE_RECEIVED", verification="VERIFIED"):
    tls = {
        "protocol_version": "TLSv1.3", "cipher": {"name": "TLS_AES_256_GCM_SHA384", "protocol": "TLSv1.3", "bits": 256},
        "certificate_subject": [{"name": "commonName", "value": "fixture"}],
        "certificate_issuer": [{"name": "commonName", "value": "fixture-ca"}],
        "not_before": "2026-01-01T00:00:00+00:00", "not_after": "2027-01-01T00:00:00+00:00",
        "subject_alt_names": [{"type": "IP Address", "value": "192.168.1.20"}],
        "sha256_fingerprint": "a" * 64, "certificate_verification": verification,
        "hostname_verification": None, "ip_address_verification": "MATCHED",
        "verification_name": "192.168.1.20", "error_category": None,
    }
    result = _http_result(
        scope, device, port, scheme="https", source="https-tls-head-v1",
        tls=tls, outcome=outcome,
        error_category=None if outcome == "RESPONSE_RECEIVED" else (
            "handshake_failure" if outcome == "TLS_HANDSHAKE_FAILED" else "untrusted_certificate"
        ),
    )
    if outcome != "RESPONSE_RECEIVED":
        result.update({"status_code": None, "response_headers": {}, "content_type": None,
                       "content_length": None, "server_identifier": None, "redirect_location": None})
    if verification != "VERIFIED":
        tls.update({
            "protocol_version": None, "cipher": None, "certificate_subject": [],
            "certificate_issuer": [], "not_before": None, "not_after": None,
            "subject_alt_names": [], "sha256_fingerprint": None,
            "ip_address_verification": "NOT_COMPLETED",
            "error_category": "untrusted_certificate",
        })
    return result


def test_migration_49_upgrade_from_48_is_additive_and_idempotent(tmp_path, monkeypatch):
    path = tmp_path / "upgrade.db"
    connection = sqlite3.connect(path)
    connection.execute("PRAGMA foreign_keys=ON")
    connection.execute("CREATE TABLE events (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL, source_ip TEXT NOT NULL, username TEXT, event_type TEXT NOT NULL, severity TEXT NOT NULL, message TEXT NOT NULL, event_count INTEGER NOT NULL)")
    all_migrations = migrations.MIGRATIONS
    monkeypatch.setattr(migrations, "MIGRATIONS", tuple(item for item in all_migrations if item[0] < 49))
    migrations.apply_migrations(connection)
    assert connection.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0] == 48
    monkeypatch.setattr(migrations, "MIGRATIONS", all_migrations)
    migrations.apply_migrations(connection)
    migrations.apply_migrations(connection)
    assert connection.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0] == 49
    assert connection.execute("SELECT COUNT(*) FROM schema_migrations WHERE version=49").fetchone()[0] == 1
    assert connection.execute("SELECT name FROM sqlite_master WHERE name='recon_scan_runs'").fetchone()
    assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
    connection.close()


def test_migration_49_preserves_preexisting_device_and_port_rows(tmp_path, monkeypatch):
    path = tmp_path / "existing-inventory.db"
    all_migrations = migrations.MIGRATIONS
    monkeypatch.setattr(migrations, "MIGRATIONS", tuple(item for item in all_migrations if item[0] < 49))
    initialize_database(path)
    network = create_network("192.168.8.0/24", "Pre-migration", "", True, True, path)
    scope = get_scope_for_network(network["id"], path)
    device = create_device(
        stable_key="pre-migration-device", network_id=network["id"], mac_address=None,
        hostname=None, vendor=None, first_seen="2026-10-01T00:00:00+00:00",
        last_seen="2026-10-01T00:00:00+00:00", last_ip_address="192.168.8.10",
        status="ONLINE", identity_confidence="LOW", db_path=path,
    )
    port = create_port(device["id"], 8080, "tcp", "open", "2026-10-01T00:00:00+00:00",
                       "2026-10-01T00:00:00+00:00", path)
    monkeypatch.setattr(migrations, "MIGRATIONS", all_migrations)
    initialize_database(path)
    assert _query(path, "SELECT id FROM devices WHERE id=?", (device["id"],)) == [(device["id"],)]
    assert _query(path, "SELECT id FROM ports WHERE id=?", (port["id"],)) == [(port["id"],)]
    assert _query(path, "SELECT id FROM authorized_scopes WHERE id=?", (scope["id"],)) == [(scope["id"],)]
    assert _query(path, "PRAGMA foreign_key_check") == []


def test_fresh_database_has_migration_49_and_existing_inventory(endpoint_db):
    path, scope, device, port = endpoint_db
    assert _query(path, "SELECT MAX(version) FROM schema_migrations")[0][0] == 49
    assert _query(path, "SELECT id FROM devices WHERE id=?", (device["id"],)) == [(device["id"],)]
    assert _query(path, "SELECT id FROM ports WHERE id=?", (port["id"],)) == [(port["id"],)]
    assert _query(path, "PRAGMA foreign_key_check") == []


def test_persists_http_result_and_completes_one_target_atomically(endpoint_db):
    path, scope, device, port = endpoint_db
    identifiers = persist_http_endpoint_observation(_http_result(scope, device, port), path)
    endpoint = _query(path, "SELECT scheme,outcome,status_code,response_headers_json,server_identifier FROM http_endpoint_observations WHERE id=?", (identifiers["observation_id"],))[0]
    run = _query(path, "SELECT profile,scanner,status FROM recon_scan_runs WHERE id=?", (identifiers["scan_run_id"],))[0]
    target = _query(path, "SELECT run_id,target_ip,device_id,outcome FROM recon_scan_targets WHERE id=?", (identifiers["scan_target_id"],))[0]
    assert endpoint[:3] == ("http", "RESPONSE_RECEIVED", 200)
    assert json.loads(endpoint[3]) == {"date": "Sun, 15 Nov 2026 12:30:00 GMT"}
    assert endpoint[4] == "example"
    assert run == ("http_endpoint_fingerprint", "sentinelip-http-tls-fingerprint", "COMPLETED")
    assert target == (identifiers["scan_run_id"], "192.168.1.20", device["id"], "COMPLETED")
    assert _query(path, "SELECT COUNT(*) FROM port_observations WHERE source='nmap'")[0][0] == 1


def test_persists_verified_https_facts_and_tls_failure_without_certificate_facts(endpoint_db):
    path, scope, device, port = endpoint_db
    result = _tls_result(scope, device, port)
    result["tls"]["not_before"] = "Jun 15 12:00:00 2026 GMT"
    verified = persist_http_endpoint_observation(result, path)
    tls = _query(path, "SELECT verification_status,sha256_fingerprint,certificate_subject_json FROM http_tls_observations WHERE endpoint_observation_id=?", (verified["observation_id"],))[0]
    assert tls[0] == "VERIFIED" and tls[1] == "a" * 64
    assert json.loads(tls[2])[0]["value"] == "fixture"
    assert _query(path, "SELECT not_before FROM http_tls_observations WHERE endpoint_observation_id=?", (verified["observation_id"],))[0][0] == "2026-06-15T12:00:00+00:00"
    failed = persist_http_endpoint_observation(
        _tls_result(scope, device, port, outcome="TLS_VERIFICATION_FAILED", verification="FAILED"), path,
    )
    tls_failed = _query(path, "SELECT verification_status,sha256_fingerprint,certificate_subject_json,error_category FROM http_tls_observations WHERE endpoint_observation_id=?", (failed["observation_id"],))[0]
    assert tls_failed == ("FAILED", None, None, "untrusted_certificate")
    assert _query(path, "SELECT status FROM recon_scan_runs WHERE id=?", (failed["scan_run_id"],))[0][0] == "FAILED"


@pytest.mark.parametrize("outcome", ["TIMEOUT", "CONNECTION_FAILED", "HEADER_LIMIT_EXCEEDED", "MALFORMED_RESPONSE", "DNS_REVALIDATION_FAILED"])
def test_failure_results_are_not_completed_runs(endpoint_db, outcome):
    path, scope, device, port = endpoint_db
    result = _http_result(scope, device, port, outcome=outcome, status_code=None,
                          response_headers={}, content_type=None, content_length=None,
                          server_identifier=None, redirect_location=None, error_category="timeout")
    identifiers = persist_http_endpoint_observation(result, path)
    assert _query(path, "SELECT status FROM recon_scan_runs WHERE id=?", (identifiers["scan_run_id"],))[0][0] == "FAILED"
    assert _query(path, "SELECT outcome FROM recon_scan_targets WHERE id=?", (identifiers["scan_target_id"],))[0][0] == "FAILED"


def test_tls_handshake_failure_is_persisted_as_incomplete_failed_run(endpoint_db):
    path, scope, device, port = endpoint_db
    result = _tls_result(scope, device, port, outcome="TLS_HANDSHAKE_FAILED", verification="NOT_COMPLETED")
    identifiers = persist_http_endpoint_observation(result, path)
    assert _query(path, "SELECT status,error_category FROM recon_scan_runs WHERE id=?", (identifiers["scan_run_id"],))[0] == ("FAILED", "handshake_failure")
    assert _query(path, "SELECT verification_status,sha256_fingerprint FROM http_tls_observations WHERE endpoint_observation_id=?", (identifiers["observation_id"],))[0] == ("NOT_COMPLETED", None)


def test_hostname_scope_persists_only_approved_hostname_and_tls_sni_name(tmp_path):
    path = tmp_path / "hostname-endpoint.db"
    initialize_database(path)
    scope = create_hostname_scope(
        canonical_hostname="authorized.example.test", approved_addresses=["8.8.8.8"],
        authorization_confirmed_at="2026-10-01T00:00:00+00:00",
        authorization_confirmation_version="hostname-v1", authorization_source="test",
        resolution_version="hostname-a-v1", db_path=path,
    )
    device = create_scope_device(scope["id"], ip_address="8.8.8.8",
                                 first_seen="2026-10-01T00:00:00+00:00",
                                 last_seen="2026-10-01T00:00:00+00:00", status="ONLINE", db_path=path)
    port = create_port(device["id"], 8080, "tcp", "open", "2026-10-01T00:00:00+00:00",
                       "2026-10-01T00:00:00+00:00", path)
    save_port_observation(device_id=device["id"], port_id=port["id"], ip_address="8.8.8.8",
                          port_number=8080, transport="tcp", state="open",
                          observed_at="2026-10-01T00:00:00+00:00", source="nmap", db_path=path)
    result = _tls_result(scope, device, port)
    result.update({"target_ip": "8.8.8.8", "host": "authorized.example.test:8080"})
    result["tls"].update({"verification_name": "authorized.example.test",
                          "hostname_verification": "MATCHED", "ip_address_verification": None,
                          "subject_alt_names": [{"type": "DNS", "value": "authorized.example.test"}]})
    identifiers = persist_http_endpoint_observation(result, path)
    stored = _query(path, "SELECT approved_hostname,target_ip FROM http_endpoint_observations WHERE id=?",
                    (identifiers["observation_id"],))[0]
    assert stored == ("authorized.example.test", "8.8.8.8")
    assert _query(path, "SELECT verification_name,hostname_verification FROM http_tls_observations WHERE endpoint_observation_id=?",
                  (identifiers["observation_id"],))[0] == ("authorized.example.test", "MATCHED")


@pytest.mark.parametrize("updates", [
    {"outcome": "CAPACITY_REJECTED"},
    {"outcome": "MADE_UP"},
    {"target_ip": "192.168.1.21"},
    {"response_headers": {"set-cookie": "secret"}},
    {"response_headers": {"date": "x" * 513}},
    {"unrecognized_secret": "token"},
])
def test_rejects_invalid_outcomes_target_and_sensitive_or_unbounded_metadata(endpoint_db, updates):
    path, scope, device, port = endpoint_db
    with pytest.raises(HttpEndpointPersistenceError):
        persist_http_endpoint_observation(_http_result(scope, device, port, **updates), path)
    assert _query(path, "SELECT COUNT(*) FROM recon_scan_runs")[0][0] == 0
    assert _query(path, "SELECT COUNT(*) FROM http_endpoint_observations")[0][0] == 0


def test_rejects_cross_scope_and_wrong_device_port(endpoint_db):
    path, scope, device, port = endpoint_db
    other = create_device(
        stable_key="other-device", network_id=device["network_id"], mac_address=None,
        hostname=None, vendor=None, first_seen="2026-10-01T00:00:00+00:00",
        last_seen="2026-10-01T00:00:00+00:00", last_ip_address="192.168.1.21",
        status="ONLINE", identity_confidence="LOW", db_path=path,
    )
    with pytest.raises(HttpEndpointPersistenceError, match="Device"):
        persist_http_endpoint_observation(_http_result(scope, other, port), path)
    with pytest.raises(HttpEndpointPersistenceError, match="authorized scope"):
        persist_http_endpoint_observation(_http_result({**scope, "id": scope["id"] + 100}, device, port), path)
    assert _query(path, "SELECT COUNT(*) FROM recon_scan_runs")[0][0] == 0


def test_rejects_unobserved_tcp_port_and_disabled_scope(endpoint_db):
    path, scope, device, port = endpoint_db
    unobserved = create_port(device["id"], 8443, "tcp", "open", "2026-10-01T00:00:00+00:00",
                             "2026-10-01T00:00:00+00:00", path)
    result = _http_result(scope, device, port, port_id=unobserved["id"], host="192.168.1.20:8443")
    with pytest.raises(HttpEndpointPersistenceError, match="observed open TCP port"):
        persist_http_endpoint_observation(result, path)
    connection = get_connection(path)
    try:
        connection.execute("UPDATE authorized_scopes SET enabled=0 WHERE id=?", (scope["id"],))
        connection.commit()
    finally:
        connection.close()
    with pytest.raises(HttpEndpointPersistenceError, match="enabled authorized scope"):
        persist_http_endpoint_observation(_http_result(scope, device, port), path)
    assert _query(path, "SELECT COUNT(*) FROM recon_scan_runs")[0][0] == 0


def test_tls_verified_state_requires_valid_fingerprint_and_failed_state_rejects_facts(endpoint_db):
    path, scope, device, port = endpoint_db
    invalid = _tls_result(scope, device, port)
    invalid["tls"]["sha256_fingerprint"] = "A" * 64
    with pytest.raises(HttpEndpointPersistenceError, match="fingerprint"):
        persist_http_endpoint_observation(invalid, path)
    invalid = _tls_result(scope, device, port, outcome="TLS_VERIFICATION_FAILED", verification="FAILED")
    invalid["tls"]["sha256_fingerprint"] = "a" * 64
    with pytest.raises(HttpEndpointPersistenceError, match="cannot include certificate facts"):
        persist_http_endpoint_observation(invalid, path)


def test_atomic_rollback_and_explicit_connection_close_on_database_failure(endpoint_db, monkeypatch):
    path, scope, device, port = endpoint_db
    connection = get_connection(path)
    connection.execute("CREATE TRIGGER reject_endpoint BEFORE INSERT ON http_endpoint_observations BEGIN SELECT RAISE(ABORT, 'fixture failure'); END")
    connection.close()
    owned = []
    original = get_connection
    def tracked(db_path):
        value = original(db_path)
        owned.append(value)
        return value
    monkeypatch.setattr("services.http_endpoint_observations.get_connection", tracked)
    with pytest.raises(sqlite3.IntegrityError) as retained:
        persist_http_endpoint_observation(_http_result(scope, device, port), path)
    with pytest.raises(sqlite3.ProgrammingError):
        owned[0].execute("SELECT 1")
    assert _query(path, "SELECT COUNT(*) FROM recon_scan_runs")[0][0] == 0
    assert retained.value.__traceback__ is not None


def test_connection_is_closed_after_success_and_retained_validation_exception(endpoint_db, monkeypatch):
    path, scope, device, port = endpoint_db
    owned = []
    original = get_connection
    def tracked(db_path):
        value = original(db_path)
        owned.append(value)
        return value
    monkeypatch.setattr("services.http_endpoint_observations.get_connection", tracked)
    persist_http_endpoint_observation(_http_result(scope, device, port), path)
    with pytest.raises(sqlite3.ProgrammingError):
        owned[-1].execute("SELECT 1")
    invalid = _http_result(scope, device, port, target_ip="192.168.1.22")
    with pytest.raises(HttpEndpointPersistenceError) as retained:
        persist_http_endpoint_observation(invalid, path)
    assert retained.value.__traceback__ is not None
    with pytest.raises(sqlite3.ProgrammingError):
        owned[-1].execute("SELECT 1")


def test_duplicate_scan_target_association_is_rejected_by_schema(endpoint_db):
    path, scope, device, port = endpoint_db
    first = persist_http_endpoint_observation(_http_result(scope, device, port), path)
    second = persist_http_endpoint_observation(_http_result(scope, device, port), path)
    connection = sqlite3.connect(path)
    try:
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute("UPDATE http_endpoint_observations SET scan_target_id=? WHERE id=?",
                               (first["scan_target_id"], second["observation_id"]))
    finally:
        connection.close()


def test_scope_deletion_cascades_run_target_endpoint_and_tls_details(endpoint_db):
    path, scope, device, port = endpoint_db
    identifiers = persist_http_endpoint_observation(_tls_result(scope, device, port), path)
    connection = sqlite3.connect(path)
    try:
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("DELETE FROM authorized_scopes WHERE id=?", (scope["id"],))
        connection.commit()
    finally:
        connection.close()
    assert _query(path, "SELECT COUNT(*) FROM recon_scan_runs WHERE id=?", (identifiers["scan_run_id"],))[0][0] == 0
    assert _query(path, "SELECT COUNT(*) FROM recon_scan_targets WHERE id=?", (identifiers["scan_target_id"],))[0][0] == 0
    assert _query(path, "SELECT COUNT(*) FROM http_endpoint_observations WHERE id=?", (identifiers["observation_id"],))[0][0] == 0
    assert _query(path, "SELECT COUNT(*) FROM http_tls_observations WHERE endpoint_observation_id=?", (identifiers["observation_id"],))[0][0] == 0


def test_port_and_device_deletion_are_restricted_while_endpoint_evidence_exists(endpoint_db):
    path, scope, device, port = endpoint_db
    persist_http_endpoint_observation(_http_result(scope, device, port), path)
    connection = get_connection(path)
    try:
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute("DELETE FROM ports WHERE id=?", (port["id"],))
        connection.rollback()
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute("DELETE FROM devices WHERE id=?", (device["id"],))
        connection.rollback()
    finally:
        connection.close()


def test_history_cap_rejects_new_record_without_deleting_existing_evidence(endpoint_db, monkeypatch):
    path, scope, device, port = endpoint_db
    persist_http_endpoint_observation(_http_result(scope, device, port), path)
    monkeypatch.setattr("services.http_endpoint_observations.MAX_HTTP_ENDPOINT_OBSERVATIONS_PER_SCOPE", 1)
    with pytest.raises(HttpEndpointPersistenceError, match="retention cap"):
        persist_http_endpoint_observation(_http_result(scope, device, port), path)
    assert _query(path, "SELECT COUNT(*) FROM http_endpoint_observations")[0][0] == 1
    assert MAX_HTTP_ENDPOINT_OBSERVATIONS_PER_SCOPE == 10_000
