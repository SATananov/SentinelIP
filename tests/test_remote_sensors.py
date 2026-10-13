from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import json
import sqlite3
import uuid

import pytest

from database.db import get_connection, initialize_database
from database.networks import create_network
from database.scopes import get_scope_for_network, create_scope
from database.remote_sensors import RemoteSensorStore
from services.remote_sensor_models import LocalScopeGrant, RemoteSensorError, RemoteSensorAuthError, capabilities


@pytest.fixture
def setup(tmp_path):
    now = [datetime(2026, 10, 12, tzinfo=timezone.utc)]
    store = RemoteSensorStore(tmp_path / 'remote.db', clock=lambda: now[0])
    site = store.create_site('Home')
    return store, site, now


def enroll(store, site):
    invitation = store.create_enrollment(site['id'])
    return store.consume_enrollment(invitation.secret, name='Sensor A', platform='linux', version='1', reported_capabilities=['HOST_DISCOVERY'])


def scope(store):
    network = create_network('192.168.1.0/24', 'LAN', '', True, True, store.db_path)
    return get_scope_for_network(network['id'], store.db_path)


def heartbeat(store, issued):
    return store.heartbeat(issued.record['id'], issued.secret, platform='windows', version='2', reported_capabilities=['SERVICE_DISCOVERY'])


def test_site_and_sensor_identity_metadata_and_status(setup):
    store, site, now = setup
    assert store.list_sites() == [site]
    issued = enroll(store, site)
    second = enroll(store, site)
    assert uuid.UUID(issued.record['sensor_uuid'])
    assert issued.record['sensor_uuid'] != second.record['sensor_uuid']
    assert issued.record['site_id'] == site['id']
    assert issued.record['status'] == 'PENDING'
    assert issued.record['last_seen_at'] is None
    assert store.list_sensors(site['id']) == [issued.record, second.record]
    live = heartbeat(store, issued)
    assert live['status'] == 'ONLINE'
    assert live['platform'] == 'windows'
    assert live['capabilities'] == ['SERVICE_DISCOVERY']
    now[0] += timedelta(minutes=5)
    assert store.get_sensor(issued.record['id'])['status'] == 'ONLINE'
    now[0] += timedelta(seconds=1)
    assert store.get_sensor(issued.record['id'])['status'] == 'OFFLINE'
    store.set_site_enabled(site['id'], False)
    assert store.get_sensor(issued.record['id'])['status'] == 'DISABLED'
    with pytest.raises(RemoteSensorAuthError):
        heartbeat(store, issued)
    assert store.get_site(site['id'])['enabled'] is False


def test_enrollment_hash_only_explicit_expiration_one_time(setup):
    store, site, _ = setup
    first = store.create_enrollment(site['id'])
    second = store.create_enrollment(site['id'])
    assert len(first.secret) == 43
    assert first.secret != second.secret
    assert first.secret not in repr(first)
    with get_connection(store.db_path) as c:
        row = c.execute('SELECT token_hash,expires_at,created_at FROM sensor_enrollment_tokens WHERE id=?', (first.record['id'],)).fetchone()
        assert row[0] != first.secret and len(row[0]) == 64
        assert datetime.fromisoformat(row[1]) - datetime.fromisoformat(row[2]) == timedelta(minutes=15)
    issued = store.consume_enrollment(first.secret, name='A', platform='linux', version='1')
    assert issued.secret != first.secret and issued.secret not in repr(issued)
    with pytest.raises(RemoteSensorAuthError):
        store.consume_enrollment(first.secret, name='B', platform='linux', version='1')
    serialized = json.dumps(store.list_enrollments(site['id']) + store.list_sensors(site['id']))
    for value in (first.secret, second.secret, issued.secret, 'token_hash', 'credential_hash', 'credential_salt'):
        assert value not in serialized
    with get_connection(store.db_path) as c:
        dump = '\n'.join(c.iterdump())
        assert first.secret not in dump and issued.secret not in dump


@pytest.mark.parametrize('failure', ['expired', 'revoked', 'site_disabled', 'unknown'])
def test_enrollment_fail_closed(setup, failure):
    store, site, now = setup
    invite = store.create_enrollment(site['id'], 60)
    if failure == 'expired':
        now[0] += timedelta(seconds=60)
    elif failure == 'revoked':
        store.revoke_enrollment(invite.record['id'])
    elif failure == 'site_disabled':
        store.set_site_enabled(site['id'], False)
    token = 'x' * 43 if failure == 'unknown' else invite.secret
    with pytest.raises(RemoteSensorError) as exc:
        store.consume_enrollment(token, name='A', platform='linux', version='1')
    assert token not in str(exc.value)
    assert store.list_sensors(site['id']) == []


def test_concurrent_redemption_exactly_once(setup):
    store, site, _ = setup
    invitation = store.create_enrollment(site['id'])
    def consume(_):
        try:
            return store.consume_enrollment(invitation.secret, name='A', platform='linux', version='1').record['id']
        except RemoteSensorAuthError:
            return None
    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = list(executor.map(consume, range(2)))
    assert sum(value is not None for value in outcomes) == 1
    assert len(store.list_sensors(site['id'])) == 1


@pytest.mark.parametrize('value', [0, 59, 3601, True, '900'])
def test_bounded_enrollment_ttl(setup, value):
    store, site, _ = setup
    with pytest.raises(RemoteSensorError):
        store.create_enrollment(site['id'], value)


@pytest.mark.parametrize('value', [['SHELL'], ['EXEC'], ['RUN_COMMAND'], ['ARBITRARY_NMAP'], ['SCRIPT'], ['HOST_DISCOVERY'] * 5, 'HOST_DISCOVERY'])
def test_capability_whitelist(value):
    with pytest.raises(RemoteSensorError):
        capabilities(value)


def test_capabilities_deterministic():
    assert capabilities(['SERVICE_DISCOVERY', 'HOST_DISCOVERY', 'HOST_DISCOVERY']) == ('HOST_DISCOVERY', 'SERVICE_DISCOVERY')


def test_assignments_revalidate_credentials_scope_and_local_grant(setup):
    store, site, _ = setup
    issued = enroll(store, site)
    target_scope = scope(store)
    assignment = store.assign_scope(issued.record['id'], target_scope['id'])
    assert assignment == store.assign_scope(issued.record['id'], target_scope['id'])
    assert store.list_assignments(issued.record['id']) == [assignment]
    assert store.validate_assigned_target(issued.record['id'], issued.secret, target_scope['id'], '192.168.1.8') == '192.168.1.8'
    grant = LocalScopeGrant(issued.record['sensor_uuid'], target_scope['id'], '192.168.1.0/24')
    assert grant.validate_target(issued.record['sensor_uuid'], target_scope['id'], '192.168.1.8') == '192.168.1.8'
    for target in ('8.8.8.8', '192.168.2.8', '192.168.1.0/24', 'example.test'):
        with pytest.raises(RemoteSensorError):
            store.validate_assigned_target(issued.record['id'], issued.secret, target_scope['id'], target)
        with pytest.raises(RemoteSensorError):
            grant.validate_target(issued.record['sensor_uuid'], target_scope['id'], target)
    for identity, scope_id in [('another-sensor', target_scope['id']), (issued.record['sensor_uuid'], 999)]:
        with pytest.raises(RemoteSensorError):
            grant.validate_target(identity, scope_id, '192.168.1.8')
    store.remove_assignment(issued.record['id'], target_scope['id'])
    with pytest.raises(RemoteSensorError):
        store.validate_assigned_target(issued.record['id'], issued.secret, target_scope['id'], '192.168.1.8')


@pytest.mark.parametrize('scope_type,target', [('PUBLIC_IPV4','8.8.8.8'), ('HOSTNAME','example.test'), ('PUBLIC_CIDR','8.8.8.0/29')])
def test_public_scopes_never_assignable(setup, scope_type, target):
    store, site, _ = setup
    issued = enroll(store, site)
    public = create_scope(scope_type=scope_type, canonical_target=target, authorized=True, enabled=True,
                          authorization_confirmed_at='2026-10-12', authorization_confirmation_version='fixture', authorization_source='fixture', db_path=store.db_path)
    with pytest.raises(RemoteSensorError):
        store.assign_scope(issued.record['id'], public['id'])
    assert store.list_assignments(issued.record['id']) == []


@pytest.mark.parametrize('table,field,value', [
    ('authorized_scopes','enabled',0), ('authorized_scopes','authorized',0),
    ('authorized_scopes','authorization_confirmed_at',''),
    ('authorized_scopes','authorization_confirmation_version',''), ('authorized_scopes','authorization_source',''),
    ('networks','enabled',0), ('networks','authorized',0),
    ('remote_sensors','enabled',0), ('sites','enabled',0),
])
def test_revalidation_after_assignment(setup, table, field, value):
    store, site, _ = setup
    issued = enroll(store, site)
    target_scope = scope(store)
    store.assign_scope(issued.record['id'], target_scope['id'])
    with get_connection(store.db_path) as c:
        c.execute(f'UPDATE {table} SET {field}=?', (value,))
    with pytest.raises(RemoteSensorError):
        store.assign_scope(issued.record['id'], target_scope['id'])
    with pytest.raises(RemoteSensorError):
        store.validate_assigned_target(issued.record['id'], issued.secret, target_scope['id'], '192.168.1.8')


def test_changed_scope_is_not_silently_reauthorized(setup):
    store, site, _ = setup
    issued = enroll(store, site)
    target_scope = scope(store)
    store.assign_scope(issued.record['id'], target_scope['id'])
    with get_connection(store.db_path) as c:
        c.execute("UPDATE networks SET cidr='192.168.2.0/24'")
        c.execute("UPDATE authorized_scopes SET canonical_target='192.168.2.0/24'")
    with pytest.raises(RemoteSensorError):
        store.assign_scope(issued.record['id'], target_scope['id'])
    with pytest.raises(RemoteSensorError):
        store.validate_assigned_target(issued.record['id'], issued.secret, target_scope['id'], '192.168.2.8')


def test_site_is_not_authentication_and_scopes_not_self_claimed(setup):
    store, site, _ = setup
    issued = enroll(store, site)
    target_scope = scope(store)
    with pytest.raises(RemoteSensorAuthError):
        store.validate_assigned_target(issued.record['id'], str(site['id']), target_scope['id'], '192.168.1.8')
    with pytest.raises(RemoteSensorError):
        store.validate_assigned_target(issued.record['id'], issued.secret, target_scope['id'], '192.168.1.8')
    with pytest.raises(RemoteSensorAuthError) as exc:
        store.heartbeat(issued.record['id'], 'x' * 43, platform='linux', version='1')
    assert 'x' * 43 not in str(exc.value)
    assert store.get_sensor(issued.record['id'])['status'] == 'PENDING'


def test_revocation_not_reversed_by_reenable(setup):
    store, site, _ = setup
    issued = enroll(store, site)
    store.revoke_sensor(issued.record['id'])
    assert store.get_sensor(issued.record['id'])['status'] == 'DISABLED'
    with pytest.raises(RemoteSensorError):
        store.set_sensor_enabled(issued.record['id'], True)
    with pytest.raises(RemoteSensorAuthError):
        heartbeat(store, issued)


def test_scope_cannot_be_shared_across_sites_even_after_unassignment(setup):
    store, site, _ = setup
    first = enroll(store, site)
    second = enroll(store, store.create_site('Warehouse'))
    target_scope = scope(store)
    store.assign_scope(first.record['id'], target_scope['id'])
    store.remove_assignment(first.record['id'], target_scope['id'])
    with pytest.raises(RemoteSensorError):
        store.assign_scope(second.record['id'], target_scope['id'])
    same_site = enroll(store, site)
    store.assign_scope(same_site.record['id'], target_scope['id'])
    with get_connection(store.db_path) as c:
        assert c.execute('PRAGMA foreign_key_check').fetchall() == []
        with pytest.raises(sqlite3.IntegrityError):
            c.execute('INSERT INTO sensor_scope_assignments VALUES (?,?,?,?,?)', (second.record['id'], target_scope['id'], site['id'], '192.168.1.0/24', 'fixture'))


@pytest.mark.parametrize('cidr', ['8.8.8.0/24', '100.64.0.0/24', '192.0.2.0/24', '127.0.0.0/24', '10.0.0.0/23', '192.168.1.8/24', '::1/128'])
def test_local_grant_rejects_non_lan_or_unbounded(cidr):
    with pytest.raises(RemoteSensorError):
        LocalScopeGrant('sensor', 1, cidr)


def test_unique_uuid_and_site_fk(setup):
    store, site, _ = setup
    first = enroll(store, site)
    second = enroll(store, site)
    with get_connection(store.db_path) as c:
        with pytest.raises(sqlite3.IntegrityError):
            c.execute('UPDATE remote_sensors SET sensor_uuid=? WHERE id=?', (first.record['sensor_uuid'], second.record['id']))
        with pytest.raises(sqlite3.IntegrityError):
            c.execute('UPDATE remote_sensors SET site_id=999 WHERE id=?', (first.record['id'],))
