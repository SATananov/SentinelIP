import sqlite3
from datetime import datetime

import pytest

from database.db import get_connection, initialize_database
from database.management_audit import record_event
from database.remote_sensors import RemoteSensorStore
from services.remote_sensor_models import RemoteSensorError
from database.migrations import MIGRATIONS
from database.networks import create_network, delete_network, update_network
from database.scopes import create_scope, get_scope_for_network
from database.external_exposure_assessments import upsert_policy, delete_policy
from database.remote_tasks import RemoteTaskStore
from database.data_lifecycle import cleanup_data_lifecycle
from database.telemetry import provision_sensor
from datetime import datetime, timezone


def test_migration_44_constraints_triggers_indexes_and_no_entity_foreign_keys(tmp_path):
    path = tmp_path / "management-audit.db"
    initialize_database(path)
    with get_connection(path) as connection:
        assert connection.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0] == 46
        assert connection.execute("PRAGMA foreign_key_list(management_audit_events)").fetchall() == []
        indexes = {row[1] for row in connection.execute("PRAGMA index_list(management_audit_events)")}
        assert indexes == {
            "idx_management_audit_events_time", "idx_management_audit_events_site_time",
            "idx_management_audit_events_entity_time", "idx_management_audit_events_type_time",
        }
        connection.execute("INSERT INTO sites(name,enabled,created_at,updated_at) VALUES('s',1,'t','t')")
        record_event(connection, event_type="SITE_CREATED", entity_type="SITE", entity_id=1,
                     site_id=1, actor_type="LOCAL_OPERATOR", new_state="ENABLED")
        occurred_at = connection.execute("SELECT occurred_at FROM management_audit_events").fetchone()[0]
        assert datetime.fromisoformat(occurred_at.replace("Z", "+00:00")).utcoffset().total_seconds() == 0
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute("UPDATE management_audit_events SET new_state='DISABLED' WHERE id=1")
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute("DELETE FROM management_audit_events WHERE id=1")
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute("INSERT INTO management_audit_events(event_type,entity_type,entity_id,actor_type,occurred_at) VALUES('BOGUS','SITE','1','LOCAL_OPERATOR','t')")
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute("INSERT INTO management_audit_events(event_type,entity_type,entity_id,actor_type,occurred_at) VALUES('SITE_CREATED','BOGUS','1','LOCAL_OPERATOR','t')")
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute("INSERT INTO management_audit_events(event_type,entity_type,entity_id,actor_type,occurred_at) VALUES('SITE_CREATED','SITE','1','UNKNOWN','t')")
        connection.execute("DELETE FROM sites WHERE id=1")
        assert connection.execute("SELECT COUNT(*) FROM management_audit_events").fetchone()[0] == 1


def test_audit_pairing_cleanup_and_port_validation(tmp_path):
    path = tmp_path / "management-audit-validation.db"
    initialize_database(path)
    with get_connection(path) as connection:
        with pytest.raises(ValueError, match="pairing"):
            record_event(connection, event_type="SITE_CREATED", entity_type="NETWORK", entity_id=1,
                         actor_type="LOCAL_OPERATOR")
        with pytest.raises(ValueError, match="counts"):
            record_event(connection, event_type="DATA_LIFECYCLE_CLEANUP_EXECUTED",
                         entity_type="DATA_LIFECYCLE", entity_id="DATA_LIFECYCLE",
                         actor_type="LOCAL_OPERATOR", cleanup_data_class="DNS_OBSERVATIONS",
                         cleanup_evaluated_at="2026-01-01T00:00:00Z", cleanup_eligible_before=-1,
                         cleanup_deleted_count=0, cleanup_protected_count=0,
                         cleanup_remaining_eligible=0, cleanup_batch_limit=100)
        with pytest.raises(ValueError, match="ports"):
            record_event(connection, event_type="EXPOSURE_POLICY_CONFIGURED",
                         entity_type="EXTERNAL_EXPOSURE_POLICY", entity_id=1, scope_id=1,
                         actor_type="API_CLIENT", new_expected_tcp_ports=[443, "80"])
        record_event(connection, event_type="EXPOSURE_POLICY_CONFIGURED",
                     entity_type="EXTERNAL_EXPOSURE_POLICY", entity_id=1, scope_id=1,
                     actor_type="API_CLIENT", previous_expected_tcp_ports=[443, 80, 443],
                     new_expected_tcp_ports=[443])
        row = connection.execute("SELECT previous_expected_tcp_ports,new_expected_tcp_ports FROM management_audit_events").fetchone()
        assert tuple(row) == ('[80,443]', '[443]')


def test_site_transition_audits_only_real_changes_and_audit_failure_rolls_back(tmp_path):
    path = tmp_path / "management-audit-site.db"
    store = RemoteSensorStore(path)
    site = store.create_site("audit site")
    store.set_site_enabled(site["id"], True)
    store.set_site_enabled(site["id"], False)
    with get_connection(path) as connection:
        assert [row[0] for row in connection.execute(
            "SELECT event_type FROM management_audit_events ORDER BY id") ] == ["SITE_CREATED", "SITE_DISABLED"]
        connection.execute("""CREATE TRIGGER test_audit_insert_failure BEFORE INSERT ON management_audit_events
            BEGIN SELECT RAISE(ABORT,'forced audit failure'); END""")
    with pytest.raises(sqlite3.IntegrityError):
        store.create_site("must roll back")
    with pytest.raises(RemoteSensorError):
        store.create_enrollment(999)
    with get_connection(path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM sites WHERE name='must roll back'").fetchone()[0] == 0
        assert connection.execute("SELECT COUNT(*) FROM management_audit_events").fetchone()[0] == 2


def test_schema_43_upgrade_preserves_existing_rows_and_is_idempotent(tmp_path):
    path = tmp_path / "management-audit-upgrade.db"
    initialize_database(path)
    with get_connection(path) as connection:
        connection.execute("INSERT INTO sites(name,enabled,created_at,updated_at) VALUES('preserved',1,'t','t')")
        connection.execute("DROP TRIGGER management_audit_events_no_update")
        connection.execute("DROP TRIGGER management_audit_events_no_delete")
        connection.execute("DROP INDEX idx_management_audit_events_time")
        connection.execute("DROP INDEX idx_management_audit_events_site_time")
        connection.execute("DROP INDEX idx_management_audit_events_entity_time")
        connection.execute("DROP INDEX idx_management_audit_events_type_time")
        connection.execute("DROP TABLE management_audit_events")
        connection.execute("DELETE FROM schema_migrations WHERE version=44")
    initialize_database(path)
    initialize_database(path)
    with get_connection(path) as connection:
        assert connection.execute("SELECT name FROM sites").fetchone()[0] == "preserved"
        assert connection.execute("SELECT COUNT(*) FROM schema_migrations WHERE version=44").fetchone()[0] == 1
        assert max(version for version, _ in MIGRATIONS) == 46
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []


def test_network_scope_and_exposure_policy_events_capture_safe_changes(tmp_path):
    path = tmp_path / "management-audit-network.db"
    network = create_network("192.168.40.0/24", "not stored", "description", True, True, path)
    update_network(network["id"], enabled=False, db_path=path)
    update_network(network["id"], enabled=False, db_path=path)
    with get_connection(path) as connection:
        connection.execute("""CREATE TRIGGER fail_network_delete BEFORE INSERT ON management_audit_events
            WHEN NEW.event_type='NETWORK_DELETED' BEGIN SELECT RAISE(ABORT,'forced'); END""")
    with pytest.raises(sqlite3.IntegrityError):
        delete_network(network["id"], path)
    with get_connection(path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM networks WHERE id=?", (network["id"],)).fetchone()[0] == 1
        connection.execute("DROP TRIGGER fail_network_delete")
    delete_network(network["id"], path)
    scope = create_scope(scope_type="PUBLIC_IPV4", canonical_target="8.8.8.8",
                         authorized=True, enabled=True, authorization_confirmed_at="now",
                         authorization_confirmation_version="test-v1",
                         authorization_source="test", db_path=path)
    upsert_policy(scope["id"], [443, 80], path)
    upsert_policy(scope["id"], [80, 443], path)
    with get_connection(path) as connection:
        connection.execute("""CREATE TRIGGER fail_policy_delete BEFORE INSERT ON management_audit_events
            WHEN NEW.event_type='EXPOSURE_POLICY_REMOVED' BEGIN SELECT RAISE(ABORT,'forced'); END""")
    with pytest.raises(sqlite3.IntegrityError):
        delete_policy(scope["id"], path)
    with get_connection(path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM external_exposure_policies WHERE scope_id=?",
                                  (scope["id"],)).fetchone()[0] == 1
        connection.execute("DROP TRIGGER fail_policy_delete")
    delete_policy(scope["id"], path)
    with get_connection(path) as connection:
        events = connection.execute(
            "SELECT event_type,entity_type,entity_id,scope_id,previous_expected_tcp_ports,new_expected_tcp_ports "
            "FROM management_audit_events ORDER BY id").fetchall()
        assert [row[0] for row in events] == [
            "NETWORK_CREATED", "NETWORK_DISABLED", "NETWORK_DELETED", "SCOPE_AUTHORIZED",
            "EXPOSURE_POLICY_CONFIGURED", "EXPOSURE_POLICY_REMOVED",
        ]
        assert events[0][3] is not None
        assert tuple(events[4][4:]) == (None, "[80,443]")
        assert tuple(events[5][4:]) == ("[80,443]", None)
        assert connection.execute("SELECT COUNT(*) FROM networks").fetchone()[0] == 0


def test_control_plane_audit_accepts_local_operator_and_keeps_api_client_default(tmp_path):
    path = tmp_path / "management-audit-actors.db"
    network = create_network("192.168.42.0/24", "local", "", True, True,
                             db_path=path, actor_type="LOCAL_OPERATOR")
    update_network(network["id"], enabled=False, db_path=path, actor_type="LOCAL_OPERATOR")
    delete_network(network["id"], db_path=path, actor_type="LOCAL_OPERATOR")
    scope = create_scope(scope_type="PUBLIC_IPV4", canonical_target="8.8.4.4",
                         authorized=True, enabled=True, authorization_confirmed_at="now",
                         authorization_confirmation_version="test-v1",
                         authorization_source="test", db_path=path,
                         actor_type="LOCAL_OPERATOR")
    upsert_policy(scope["id"], [443], path, actor_type="LOCAL_OPERATOR")
    delete_policy(scope["id"], path, actor_type="LOCAL_OPERATOR")
    with get_connection(path) as connection:
        actors = connection.execute(
            "SELECT event_type,actor_type FROM management_audit_events ORDER BY id"
        ).fetchall()
    assert [tuple(row) for row in actors] == [
        ("NETWORK_CREATED", "LOCAL_OPERATOR"),
        ("NETWORK_DISABLED", "LOCAL_OPERATOR"),
        ("NETWORK_DELETED", "LOCAL_OPERATOR"),
        ("SCOPE_AUTHORIZED", "LOCAL_OPERATOR"),
        ("EXPOSURE_POLICY_CONFIGURED", "LOCAL_OPERATOR"),
        ("EXPOSURE_POLICY_REMOVED", "LOCAL_OPERATOR"),
    ]


def test_registration_emits_two_events_without_secrets(tmp_path):
    path = tmp_path / "management-audit-registration.db"
    store = RemoteSensorStore(path)
    site = store.create_site("registration")
    enrollment = store.create_enrollment(site["id"])
    registered = store.consume_enrollment(enrollment.secret, name="sensor", platform="linux", version="1")
    with get_connection(path) as connection:
        rows = connection.execute(
            "SELECT event_type,entity_type,actor_type FROM management_audit_events ORDER BY id").fetchall()
        assert [tuple(row) for row in rows] == [
            ("SITE_CREATED", "SITE", "LOCAL_OPERATOR"),
            ("ENROLLMENT_ISSUED", "SENSOR_ENROLLMENT", "LOCAL_OPERATOR"),
            ("ENROLLMENT_CONSUMED", "SENSOR_ENROLLMENT", "SENSOR"),
            ("SENSOR_REGISTERED", "SENSOR", "SENSOR"),
        ]
        serialized = repr(connection.execute("SELECT * FROM management_audit_events").fetchall())
        assert enrollment.secret not in serialized
        assert registered.secret not in serialized
        assert "token_hash" not in {row[1] for row in connection.execute("PRAGMA table_info(management_audit_events)")}
        before_sensors = connection.execute("SELECT COUNT(*) FROM remote_sensors").fetchone()[0]
    store.set_sensor_enabled(registered.record["id"], True)
    store.revoke_sensor(registered.record["id"])
    store.revoke_sensor(registered.record["id"])
    with get_connection(path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM management_audit_events WHERE entity_type='SENSOR'").fetchone()[0] == 3
        connection.execute("CREATE TRIGGER fail_registration_audit BEFORE INSERT ON management_audit_events "
                           "WHEN NEW.event_type='SENSOR_REGISTERED' BEGIN SELECT RAISE(ABORT,'forced'); END")
    second = store.create_enrollment(site["id"])
    with pytest.raises(sqlite3.IntegrityError):
        store.consume_enrollment(second.secret, name="rollback", platform="linux", version="1")
    with get_connection(path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM remote_sensors").fetchone()[0] == before_sensors
        enrollment_row = connection.execute("SELECT consumed_at,sensor_id FROM sensor_enrollment_tokens WHERE id=?",
                                            (second.record["id"],)).fetchone()
        assert tuple(enrollment_row) == (None, None)


def test_task_cleanup_and_assignment_deletion_are_atomic_and_redacted(tmp_path):
    path = tmp_path / "management-audit-operations.db"
    store = RemoteSensorStore(path)
    site = store.create_site("ops")
    invite = store.create_enrollment(site["id"])
    sensor = store.consume_enrollment(invite.secret, name="sensor", platform="linux", version="1",
                                     reported_capabilities=["HOST_DISCOVERY"])
    network = create_network("192.168.41.0/24", "ops", "", True, True, path)
    scope = get_scope_for_network(network["id"], path)
    store.assign_scope(sensor.record["id"], scope["id"])
    store.assign_scope(sensor.record["id"], scope["id"])
    task = RemoteTaskStore(store).create_task(sensor.record["id"], scope["id"], "DISCOVER_NETWORK")
    with get_connection(path) as connection:
        task_event = connection.execute(
            "SELECT entity_id,sensor_id,site_id,scope_id,task_type,target_device_id "
            "FROM management_audit_events WHERE event_type='SENSOR_TASK_CREATED'").fetchone()
        assert tuple(task_event) == (task["id"], sensor.record["id"], site["id"], scope["id"],
                                     "DISCOVER_NETWORK", None)
        connection.execute("""CREATE TRIGGER fail_task_audit BEFORE INSERT ON management_audit_events
            WHEN NEW.event_type='SENSOR_TASK_CREATED'
            BEGIN SELECT RAISE(ABORT,'forced failure'); END""")
    with pytest.raises(sqlite3.IntegrityError):
        RemoteTaskStore(store).create_task(sensor.record["id"], scope["id"], "DISCOVER_NETWORK")
    with get_connection(path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM remote_sensor_tasks").fetchone()[0] == 1
        connection.execute("DROP TRIGGER fail_task_audit")
        connection.execute("""CREATE TRIGGER fail_unassignment BEFORE INSERT ON management_audit_events
            WHEN NEW.event_type='SENSOR_SCOPE_UNASSIGNED'
            BEGIN SELECT RAISE(ABORT,'forced failure'); END""")
    with pytest.raises(sqlite3.IntegrityError):
        store.remove_assignment(sensor.record["id"], scope["id"])
    with get_connection(path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM sensor_scope_assignments WHERE sensor_id=? AND scope_id=?",
                                  (sensor.record["id"], scope["id"])).fetchone()[0] == 1
        connection.execute("DROP TRIGGER fail_unassignment")
    store.remove_assignment(sensor.record["id"], scope["id"])
    with get_connection(path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM sensor_scope_assignments WHERE sensor_id=? AND scope_id=?",
                                  (sensor.record["id"], scope["id"])).fetchone()[0] == 0
        unassignment = connection.execute("SELECT site_id,scope_id,sensor_id FROM management_audit_events "
                                           "WHERE event_type='SENSOR_SCOPE_UNASSIGNED'").fetchone()
        assert tuple(unassignment) == (site["id"], scope["id"], sensor.record["id"])

    with get_connection(path) as connection:
        telemetry_sensor, _ = provision_sensor("audit-dns", "audit", "DNS", None, "DOMAIN_ONLY", 30, path)
        connection.execute("""INSERT INTO dns_observations (
            sensor_id,external_event_id,observed_at,received_at,queried_domain,query_type,
            response_status,resolved_addresses_json,source,retention_until
        ) VALUES (?, 'event-1','2000-01-01','2000-01-01','example.test','A','NOERROR','[]','test',
                  '2000-01-01T00:00:00+00:00')""", (telemetry_sensor["id"],))
        connection.execute("""CREATE TRIGGER fail_cleanup_audit BEFORE INSERT ON management_audit_events
            WHEN NEW.event_type='DATA_LIFECYCLE_CLEANUP_EXECUTED'
            BEGIN SELECT RAISE(ABORT,'forced failure'); END""")
    with pytest.raises(sqlite3.IntegrityError):
        cleanup_data_lifecycle("DNS_OBSERVATIONS", path, datetime.now(timezone.utc))
    with get_connection(path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM dns_observations").fetchone()[0] == 1
        assert connection.execute("SELECT COUNT(*) FROM management_audit_events WHERE event_type='DATA_LIFECYCLE_CLEANUP_EXECUTED'").fetchone()[0] == 0
        connection.execute("DROP TRIGGER fail_cleanup_audit")
    result = cleanup_data_lifecycle("DNS_OBSERVATIONS", path, datetime.now(timezone.utc))
    assert result["deleted_count"] == 1
    with get_connection(path) as connection:
        event = connection.execute("SELECT cleanup_data_class,cleanup_deleted_count,cleanup_batch_limit "
                                   "FROM management_audit_events WHERE event_type='DATA_LIFECYCLE_CLEANUP_EXECUTED'").fetchone()
        assert tuple(event) == ("DNS_OBSERVATIONS", 1, 100)
