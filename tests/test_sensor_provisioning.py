"""10F deployment, grant provisioning, and first-run tests; no real scans/services."""
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
from types import SimpleNamespace
from uuid import UUID

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from api.sensor_enrollment import register_machine_routes, SensorBodyLimitMiddleware
from database.networks import create_network
from database.remote_sensors import RemoteSensorStore
from database.scopes import get_scope_for_network
from sensor.client import EnrollmentClient, SensorClientError
from sensor.config import load_config
from sensor.state import load_grants, write_config, write_grants
from services.sensor_transport import authenticated_sensor_headers

ROOT = Path(__file__).resolve().parents[1]
SENSOR_UUID = 'd4a1410f-292c-4456-a904-8d34f5f3df5e'
SECRET = 's' * 43


def test_authenticated_grant_endpoint_returns_only_current_own_private_assignments(tmp_path):
    store = RemoteSensorStore(tmp_path / 'grant.db', clock=lambda: datetime(2026, 10, 13, tzinfo=timezone.utc))
    site = store.create_site('Site')
    invite = store.create_enrollment(site['id'])
    issued = store.consume_enrollment(invite.secret, sensor_uuid=SENSOR_UUID,
                                      name='sensor', platform='linux', version='1',
                                      reported_capabilities=['HOST_DISCOVERY', 'SERVICE_DISCOVERY'])
    network = create_network('192.168.1.0/24', 'LAN', '', True, True, store.db_path)
    scope = get_scope_for_network(network['id'], store.db_path)
    store.assign_scope(issued.record['id'], scope['id'])
    app = FastAPI()
    register_machine_routes(app, lambda: store)
    app.add_middleware(SensorBodyLimitMiddleware)
    with TestClient(app, base_url='https://core.test', client=('192.168.1.10', 5000)) as client:
        headers = authenticated_sensor_headers(SENSOR_UUID, issued.secret,
                                               now=datetime(2026, 10, 13, tzinfo=timezone.utc), nonce='A' * 43)
        response = client.get('/sensor/grant', headers=headers)
        assert response.status_code == 200
        assert response.json() == {'grants': [
            {'scope_id': scope['id'], 'scope_type': 'PRIVATE_NETWORK', 'cidr': '192.168.1.0/24',
             'capabilities': ['HOST_DISCOVERY', 'SERVICE_DISCOVERY']}]}
        assert set(response.json()['grants'][0]) == {'scope_id', 'scope_type', 'cidr', 'capabilities'}
        assert client.get('/sensor/grant', headers={'X-Sensor-UUID': SENSOR_UUID}).status_code == 401
        store.set_sensor_enabled(issued.record['id'], False)
        disabled = authenticated_sensor_headers(SENSOR_UUID, issued.secret,
                                                now=datetime(2026, 10, 13, tzinfo=timezone.utc), nonce='B' * 43)
        assert client.get('/sensor/grant', headers=disabled).status_code == 401


def test_local_grant_refresh_validates_and_replaces_atomically(tmp_path):
    grant_path = tmp_path / 'grants.json'
    caps = ('HOST_DISCOVERY', 'SERVICE_DISCOVERY')
    grants = [{'scope_id': 3, 'scope_type': 'PRIVATE_NETWORK', 'cidr': '192.168.3.0/24',
               'capabilities': ['HOST_DISCOVERY']}]
    write_grants(grant_path, SENSOR_UUID, grants, caps, replace=False)
    assert load_grants(grant_path, SENSOR_UUID, caps)[3].cidr == '192.168.3.0/24'
    assert grant_path.stat().st_mode & 0o777 == 0o600
    write_grants(grant_path, SENSOR_UUID, [], caps, replace=True)
    assert load_grants(grant_path, SENSOR_UUID, caps) == {}
    with pytest.raises(Exception):
        write_grants(grant_path, SENSOR_UUID, [{'scope_id': 4, 'scope_type': 'PUBLIC_CIDR',
                                                'cidr': '8.8.8.0/24', 'capabilities': []}], caps)
    grant_path.chmod(0o644)
    with pytest.raises(Exception, match='permissions'):
        load_grants(grant_path, SENSOR_UUID, caps)


def test_config_writer_is_protected_and_does_not_overwrite(tmp_path):
    path = tmp_path / 'config.json'
    value = {'core_url': 'https://core.test', 'sensor_uuid': SENSOR_UUID,
             'sensor_credential': SECRET, 'grant_file': str(tmp_path / 'grants.json')}
    write_config(path, value)
    assert path.stat().st_mode & 0o777 == 0o600
    assert load_config(path, environ={}).sensor_credential == SECRET
    with pytest.raises(Exception, match='overwrite'):
        write_config(path, value)


def test_enrollment_http_client_posts_only_bounded_registration_without_machine_auth(tmp_path):
    class Response:
        status = 201
        def read(self, amount=-1):
            return json.dumps({'sensor_uuid': SENSOR_UUID, 'credential': SECRET}).encode()[:amount]
        def close(self): pass
        def getcode(self): return self.status
    class Opener:
        def __init__(self): self.request = None
        def open(self, request, timeout): self.request = request; return Response()
    opener = Opener()
    client = EnrollmentClient('https://core.test', opener=opener)
    result = client.register(enrollment_token='T' * 43, sensor_uuid=SENSOR_UUID,
                             sensor_name='sensor', platform='linux', version='1.0.0',
                             capabilities=['HOST_DISCOVERY'])
    assert result['credential'] == SECRET
    request = opener.request
    assert request.full_url == 'https://core.test/sensor-enrollment/register'
    assert request.get_method() == 'POST'
    assert request.get_header('Authorization') is None
    body = json.loads(request.data)
    assert body['enrollment_token'] == 'T' * 43 and set(body) == {
        'enrollment_token', 'sensor_uuid', 'sensor_name', 'platform', 'version', 'capabilities'}


def test_enrollment_cli_saves_secret_only_after_success_and_never_prints_it(tmp_path, monkeypatch, capsys):
    import sensor.__main__ as cli
    config_path, grant_path = tmp_path / 'config.json', tmp_path / 'grants.json'
    received = {}

    class FakeEnrollment:
        core_url = 'https://core.test'
        def __init__(self, *args, **kwargs): pass
        def register(self, **kwargs):
            received.update(kwargs)
            return {'sensor_uuid': kwargs['sensor_uuid'], 'credential': SECRET}
        def close(self): pass

    class FakeCore:
        def __init__(self, config): self.config = config
        def get_self(self): return {'sensor_uuid': self.config.sensor_uuid, 'enabled': True}
        def get_grant(self): return {'grants': []}
        def close(self): pass

    monkeypatch.setattr(cli, 'EnrollmentClient', FakeEnrollment)
    monkeypatch.setattr(cli, 'CoreClient', FakeCore)
    monkeypatch.setattr(cli, '_check_dependencies', lambda config: True)
    monkeypatch.setattr(cli, '_check_nmap', lambda: True)
    monkeypatch.setattr(cli.getpass, 'getpass', lambda prompt: 'T' * 43)
    args = SimpleNamespace(config=str(config_path), grant_file=str(grant_path),
                           core_url='https://core.test', development_mode=False,
                           sensor_uuid=None, name='Test sensor', platform='linux', capability=None,
                           request_timeout=15)
    cli._enroll(args, __import__('logging').getLogger('test'))
    assert received['enrollment_token'] == 'T' * 43
    assert str(UUID(received['sensor_uuid'])) == received['sensor_uuid']
    assert config_path.exists() and grant_path.exists()
    assert SECRET in config_path.read_text()
    output = capsys.readouterr().out
    assert SECRET not in output and 'T' * 43 not in output


def test_enrollment_failure_does_not_leave_credential_file(tmp_path, monkeypatch):
    import sensor.__main__ as cli

    class FailedEnrollment:
        core_url = 'https://core.test'
        def __init__(self, *args, **kwargs): pass
        def register(self, **kwargs): raise SensorClientError('ENROLLMENT_REJECTED')
        def close(self): pass

    monkeypatch.setattr(cli, 'EnrollmentClient', FailedEnrollment)
    monkeypatch.setattr(cli, '_check_nmap', lambda: True)
    monkeypatch.setattr(cli.getpass, 'getpass', lambda prompt: 'T' * 43)
    args = SimpleNamespace(config=str(tmp_path / 'config.json'), grant_file=str(tmp_path / 'grant.json'),
                           core_url='https://core.test', development_mode=False, sensor_uuid=None,
                           name='Test', platform='linux', capability=None, request_timeout=15)
    with pytest.raises(SensorClientError):
        cli._enroll(args, __import__('logging').getLogger('test'))
    assert not (tmp_path / 'config.json').exists()
    assert not (tmp_path / 'grant.json').exists()


def test_post_registration_provisioning_failure_leaves_no_secret_and_requires_revocation(tmp_path, monkeypatch):
    import sensor.__main__ as cli

    class SuccessfulEnrollment:
        core_url = 'https://core.test'
        def __init__(self, *args, **kwargs): pass
        def register(self, **kwargs):
            return {'sensor_uuid': kwargs['sensor_uuid'], 'credential': SECRET}
        def close(self): pass

    class UnavailableCore:
        def __init__(self, config): pass
        def get_self(self): raise SensorClientError('CORE_UNAVAILABLE')
        def close(self): pass

    monkeypatch.setattr(cli, 'EnrollmentClient', SuccessfulEnrollment)
    monkeypatch.setattr(cli, 'CoreClient', UnavailableCore)
    monkeypatch.setattr(cli, '_check_nmap', lambda: True)
    monkeypatch.setattr(cli.getpass, 'getpass', lambda prompt: 'T' * 43)
    args = SimpleNamespace(config=str(tmp_path / 'config.json'), grant_file=str(tmp_path / 'grant.json'),
                           core_url='https://core.test', development_mode=False, sensor_uuid=None,
                           name='Test', platform='linux', capability=None, request_timeout=15)
    with pytest.raises(Exception, match='revoke that sensor'):
        cli._enroll(args, __import__('logging').getLogger('test'))
    assert not (tmp_path / 'config.json').exists()
    assert not (tmp_path / 'grant.json').exists()


def test_enrollment_refuses_existing_config_before_request(tmp_path, monkeypatch):
    import sensor.__main__ as cli
    config_path = tmp_path / 'config.json'
    config_path.write_text('{}')
    args = SimpleNamespace(config=str(config_path), grant_file=str(tmp_path / 'grant.json'),
                           core_url='https://core.test', development_mode=False, sensor_uuid=None,
                           name='Test', platform='linux', capability=None, request_timeout=15)
    monkeypatch.setattr(cli, 'EnrollmentClient', lambda *a, **k: pytest.fail('must not make a request'))
    with pytest.raises(Exception, match='already exists'):
        cli._enroll(args, __import__('logging').getLogger('test'))


def test_linux_installer_staging_is_idempotent_and_uninstall_preserves_config(tmp_path):
    stage = tmp_path / 'stage'
    install = ROOT / 'packaging/linux/install.sh'
    uninstall = ROOT / 'packaging/linux/uninstall.sh'
    subprocess.run(['bash', '-n', str(install)], check=True)
    subprocess.run(['bash', '-n', str(uninstall)], check=True)
    for _ in range(2):
        subprocess.run([str(install), '--root', str(stage)], check=True, capture_output=True, text=True)
    config = stage / 'etc/sentinelip-sensor/config.json'
    example = stage / 'etc/sentinelip-sensor/config.example.json'
    assert not config.exists()
    assert example.exists() and example.stat().st_mode & 0o777 == 0o600
    service = (stage / 'etc/systemd/system/sentinelip-sensor.service').read_text()
    assert 'User=sentinelip-sensor' in service
    assert 'NoNewPrivileges=true' in service
    assert 'CapabilityBoundingSet=' in service and 'ExecStart=' in service
    text = install.read_text()
    assert 'eval ' not in text and 'curl ' not in text and 'wget ' not in text
    rejected = subprocess.run(['bash', str(install), '--root', str(tmp_path / '..' / 'escape')],
                              capture_output=True, text=True)
    assert rejected.returncode != 0
    subprocess.run([str(uninstall), '--root', str(stage)], check=True, capture_output=True, text=True)
    assert not config.exists() and example.exists()
    config.write_text('{"test":"credential"}')
    grant = stage / 'etc/sentinelip-sensor/grants.json'
    grant.write_text('{"grants":[]}')
    subprocess.run([str(install), '--root', str(stage)], check=True, capture_output=True, text=True)
    subprocess.run([str(uninstall), '--root', str(stage), '--purge'], check=True, capture_output=True, text=True)
    assert not config.exists() and not example.exists()


def test_cli_has_no_raw_scan_shell_or_command_subcommands():
    from sensor.__main__ import _parser
    help_text = _parser().format_help().lower()
    assert 'enroll' in help_text and 'self-test' in help_text and 'run' in help_text
    assert 'shell' not in help_text and 'scan ' not in help_text and 'exec ' not in help_text

