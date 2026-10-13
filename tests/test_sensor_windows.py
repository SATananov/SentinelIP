"""10G Windows adapter/packaging tests run on Linux without scans or service installs."""
from contextlib import nullcontext
from dataclasses import replace
import importlib
import ipaddress
import json
import logging
import os
from pathlib import Path, PureWindowsPath
import shutil
import subprocess
import sys
from types import SimpleNamespace
from uuid import UUID

import pytest

from sensor import platforms, windows_security as security
from services import windows_sensor_executor as windows
from services.remote_sensor_executor import LinuxRemoteSensorExecutor
from services.remote_sensor_models import LocalExecutorGrant, RemoteSensorError, RemoteTaskContext
from services.scanner_adapters.nmap_adapter import CONSERVATIVE_TCP_PORTS, ScannerTimeoutError, ScannerExecutionError

UUID_VALUE = 'd4a1410f-292c-4456-a904-8d34f5f3df5e'
TASK = RemoteTaskContext('a97b086b-b0f2-4623-9ec2-ea2ffbe1d31b', UUID_VALUE, 1,
                         'PRIVATE_NETWORK', 'DISCOVER_NETWORK', '192.168.1.0/24', network_id=2)
GRANT = LocalExecutorGrant(UUID_VALUE, 1, '192.168.1.0/24', frozenset({'HOST_DISCOVERY', 'SERVICE_DISCOVERY'}))
XML = '<nmaprun><host><status state="up"/><address addr="192.168.1.20" addrtype="ipv4"/><ports><port protocol="tcp" portid="80"><state state="open"/><service name="http" product="test" version="1"/></port></ports></host></nmaprun>'
ROOT = Path(__file__).resolve().parents[1]


def row(address='192.168.1.8', prefix=24, active=True):
    return {'ip_address': address, 'prefix_length': prefix, 'active': active}


@pytest.mark.parametrize('name,expected', [('Linux', LinuxRemoteSensorExecutor), ('Windows', windows.WindowsRemoteSensorExecutor)])
def test_executor_selection_uses_os_not_metadata(monkeypatch, name, expected):
    monkeypatch.setattr(platforms.platform, 'system', lambda: name)
    monkeypatch.setattr(windows, 'resolve_nmap', lambda: r'C:\Program Files\Nmap\nmap.exe')
    assert isinstance(platforms.select_executor(), expected)


def test_unsupported_platform_fails(monkeypatch):
    monkeypatch.setattr(platforms.platform, 'system', lambda: 'Darwin')
    with pytest.raises(RemoteSensorError, match='Unsupported'):
        platforms.select_executor()


def test_windows_interfaces_filter_and_canonicalize():
    rows = [row(), row(), row('10.1.2.3', 16), row('127.0.0.1', 8), row('169.254.1.2', 16),
            row('8.8.8.8', 24), row('192.168.2.3', active=False)]
    assert windows.parse_interfaces(json.dumps(rows)) == (
        ipaddress.IPv4Network('10.1.0.0/16'), ipaddress.IPv4Network('192.168.1.0/24'))


@pytest.mark.parametrize('value', ['bad', '{}', '[null]', json.dumps([row(prefix=True)]),
                                  json.dumps([row(address='::1')]), json.dumps([row(active='true')]),
                                  json.dumps([row(address='bogus', active=False)]), json.dumps([row()] * 257)])
def test_malformed_interfaces_fail_closed(value):
    with pytest.raises(RemoteSensorError):
        windows.parse_interfaces(value)


def test_interface_query_is_fixed_read_only_and_bounded(monkeypatch):
    calls = []
    monkeypatch.setitem(sys.modules, 'win32api', SimpleNamespace(GetSystemDirectory=lambda: r'C:\Windows\System32'))
    monkeypatch.setattr(windows, 'assert_code', lambda path: None)
    def run(argv, **kwargs):
        calls.append((argv, kwargs))
        return SimpleNamespace(returncode=0, stdout=json.dumps([row()]), stderr='')
    monkeypatch.setattr(windows.subprocess, 'run', run)
    assert str(windows.connected_private_networks()[0]) == '192.168.1.0/24'
    argv, options = calls[0]
    assert argv[-1] == windows.INTERFACE_QUERY
    assert options['shell'] is False and options['timeout'] == 15
    assert '-NoProfile' in argv and '-NonInteractive' in argv
    assert 'Get-NetIPAddress' in argv[-1] and 'Get-NetIPInterface' in argv[-1]
    assert '192.168.1' not in argv[-1]


def make_executor(monkeypatch, *, xml=XML):
    calls = []
    monkeypatch.setattr(windows, 'resolve_nmap', lambda: r'C:\Program Files\Nmap\nmap.exe')
    def run(argv, **kwargs):
        calls.append((argv, kwargs))
        return SimpleNamespace(returncode=0, stdout=xml, stderr='')
    monkeypatch.setattr(windows.subprocess, 'run', run)
    return windows.WindowsRemoteSensorExecutor(network_provider=lambda: windows.parse_interfaces(json.dumps([row()]))), calls


def test_windows_typed_network_and_services_use_fixed_unprivileged_profiles(monkeypatch):
    executor, calls = make_executor(monkeypatch)
    result = executor.discover_network(TASK, GRANT)
    assert result.hosts[0].ip_address == '192.168.1.20'
    service_task = replace(TASK, task_type='DISCOVER_SERVICES', target_ip='192.168.1.20', target_device_id=3)
    result = executor.discover_services(service_task, GRANT)
    assert result.ports[0].port == 80
    host, services = [call[0] for call in calls]
    assert host[-1] == '192.168.1.0/24' and '-sn' in host and '-PS80,443' in host
    assert '-sT' in services and '-Pn' in services and '--version-light' in services
    assert services[services.index('-p') + 1] == ','.join(map(str, CONSERVATIVE_TCP_PORTS))
    for args, options in calls:
        assert '--unprivileged' in args and '--max-retries' in args
        assert not {'-sS', '-A', '-O', '-p-', '-sU', '--script', '-sC'} & set(args)
        assert options['shell'] is False and options['timeout'] in {30, 45}
    assert not hasattr(executor, 'execute') and not hasattr(executor, 'run_shell')


@pytest.mark.parametrize('task,grant', [
    (replace(TASK, scope_type='PUBLIC_CIDR'), GRANT),
    (replace(TASK, sensor_uuid='other'), GRANT),
    (replace(TASK, scope_cidr='192.168.2.0/24'), GRANT),
    (replace(TASK, task_type='DISCOVER_SERVICES', target_ip='8.8.8.8', target_device_id=3), GRANT),
    (replace(TASK, task_type='SHELL'), GRANT),
    (TASK, replace(GRANT, capabilities=frozenset())),
])
def test_invalid_task_rejected_before_interface_or_scanner(monkeypatch, task, grant):
    executor, calls = make_executor(monkeypatch)
    executor.network_provider = lambda: pytest.fail('must validate grant before OS query')
    with pytest.raises(RemoteSensorError):
        executor.discover_network(task, grant)
    assert not calls


def test_disconnected_scope_and_outside_observation_rejected(monkeypatch):
    executor, calls = make_executor(monkeypatch, xml=XML.replace('192.168.1.20', '8.8.8.8'))
    executor.network_provider = lambda: ()
    with pytest.raises(RemoteSensorError, match='active'):
        executor.discover_network(TASK, GRANT)
    assert not calls
    executor.network_provider = lambda: (ipaddress.IPv4Network('192.168.1.0/24'),)
    with pytest.raises(RemoteSensorError, match='outside'):
        executor.discover_network(TASK, GRANT)


@pytest.mark.parametrize('failure,expected', [(subprocess.TimeoutExpired('nmap', 30), ScannerTimeoutError),
                                             (OSError('secret'), ScannerExecutionError)])
def test_scanner_failure_sanitized(monkeypatch, failure, expected):
    executor, _ = make_executor(monkeypatch)
    def fail(*a, **k): raise failure
    monkeypatch.setattr(windows.subprocess, 'run', fail)
    with pytest.raises(expected) as caught:
        executor.discover_network(TASK, GRANT)
    assert 'secret' not in str(caught.value)


@pytest.fixture
def fake_win_modules(monkeypatch):
    shell = SimpleNamespace(SHGetFolderPath=lambda *args: r'C:\Program Files')
    shellcon = SimpleNamespace(CSIDL_PROGRAM_FILES=38, CSIDL_PROGRAM_FILESX86=42, CSIDL_COMMON_APPDATA=35)
    monkeypatch.setitem(sys.modules, 'win32com', SimpleNamespace())
    monkeypatch.setitem(sys.modules, 'win32com.shell', SimpleNamespace(shell=shell, shellcon=shellcon))
    def missing(*args): raise FileNotFoundError
    monkeypatch.setitem(sys.modules, 'winreg', SimpleNamespace(HKEY_LOCAL_MACHINE=1, OpenKey=missing))
    return shell


def test_nmap_path_resolution_checks_filename_existence_and_acl(monkeypatch, fake_win_modules):
    class FakePath(PureWindowsPath):
        def is_file(self): return 'Missing' not in str(self)
    monkeypatch.setattr(windows, 'Path', FakePath)
    checked = []
    monkeypatch.setattr(windows, 'assert_code', lambda path: checked.append(path))
    path = r'C:\Program Files\Nmap\nmap.exe'
    assert windows.resolve_nmap(path) == path and str(checked[0]) == path
    for invalid in [r'C:\Tools\cmd.exe', 'nmap.exe', r'\\server\share\nmap.exe', r'C:\Tools\nmap.exe:payload']:
        with pytest.raises(RemoteSensorError): windows.resolve_nmap(invalid)
    with pytest.raises(RemoteSensorError, match='missing'):
        windows.resolve_nmap(r'C:\Missing\nmap.exe')
    monkeypatch.setattr(windows, 'assert_code', lambda path: (_ for _ in ()).throw(RemoteSensorError('unsafe ACL')))
    with pytest.raises(RemoteSensorError, match='ACL'): windows.resolve_nmap(path)


def test_programdata_path_uses_known_folder_not_environment(monkeypatch, fake_win_modules):
    fake_win_modules.SHGetFolderPath = lambda *args: r'D:\ProgramData'
    monkeypatch.setenv('ProgramData', r'C:\Untrusted')
    assert str(platforms.windows_data_directory()) == r'D:\ProgramData\SentinelIP\Sensor'


@pytest.mark.parametrize('owner,entries', [
    (security.ADMINISTRATORS, None),
    ('S-1-5-21-123', [(0, 0, 0x1F01FF, security.ADMINISTRATORS)]),
    (security.ADMINISTRATORS, [(0, 0, 0x120089, 'S-1-1-0')]),
    (security.ADMINISTRATORS, [(5, 0, 1, security.SYSTEM)]),
])
def test_insecure_secret_acls_rejected(owner, entries):
    with pytest.raises(RemoteSensorError): security.validate_acl(owner, entries, secret=True)


def test_private_acl_accepted_and_broad_code_read_only_allowed():
    entries = [(0, 0, 0x1F01FF, sid) for sid in security.SECRET_TRUSTEES]
    security.validate_acl(security.ADMINISTRATORS, entries, secret=True)
    security.validate_acl(security.SYSTEM, [(0, 0, 0x120089, 'S-1-1-0')], secret=False)
    with pytest.raises(RemoteSensorError):
        security.validate_acl(security.SYSTEM, [(0, 0, 0x120116, 'S-1-1-0')], secret=False)


def windows_storage(monkeypatch):
    from sensor import state
    calls = []
    proxy = SimpleNamespace(**{name: getattr(os, name) for name in ('fdopen', 'fsync', 'replace', 'rename', 'link', 'unlink', 'path')}, name='nt')
    monkeypatch.setattr(state, 'os', proxy)
    monkeypatch.setattr(security, 'assert_secret', lambda path: calls.append(('check', str(path))))
    def protect(path):
        assert Path(path).read_bytes() == b''  # Secret bytes cannot precede the ACL.
        calls.append(('protect', str(path)))
    monkeypatch.setattr(security, 'protect_secret', protect)
    return calls


def test_windows_atomic_storage_protects_before_write_and_cleans_failures(tmp_path, monkeypatch):
    from sensor.state import write_grants
    calls = windows_storage(monkeypatch)
    path = tmp_path / 'grants.json'
    write_grants(path, UUID_VALUE, [], ('HOST_DISCOVERY',))
    assert calls[0][0] == 'check' and calls[1][0] == 'protect'
    assert json.loads(path.read_text())['sensor_uuid'] == UUID_VALUE
    before = path.read_bytes()
    def refuse(*args): raise RemoteSensorError('bad ACL')
    monkeypatch.setattr(security, 'protect_secret', refuse)
    with pytest.raises(RemoteSensorError): write_grants(path, UUID_VALUE, [], ('HOST_DISCOVERY',))
    assert path.read_bytes() == before and not list(tmp_path.glob('.sentinel-sensor-*'))


def test_windows_config_read_requires_acl(tmp_path, monkeypatch):
    from sensor import config
    path = tmp_path / 'config.json'
    path.write_text('{}')
    monkeypatch.setattr(config, 'os', SimpleNamespace(name='nt'))
    monkeypatch.setattr(security, 'assert_secret', lambda path: (_ for _ in ()).throw(RemoteSensorError('ACL rejected')))
    with pytest.raises(RemoteSensorError, match='ACL'): config._read_config(path)


def test_windows_enrollment_shared_http_flow_protects_uuid_credential_grant(tmp_path, monkeypatch, capsys):
    import sensor.__main__ as cli
    from sensor.client import CoreClient, EnrollmentClient
    calls = windows_storage(monkeypatch)
    requests = []
    sensor_uuid = []
    class Response:
        def __init__(self, value, status=200): self.value, self.status = value, status
        def getcode(self): return self.status
        def read(self, amount): return json.dumps(self.value).encode()[:amount]
        def close(self): pass
    class Opener:
        def open(self, request, timeout):
            requests.append(request)
            if request.full_url.endswith('/register'):
                raw = json.loads(request.data)
                assert raw['platform'] == 'windows'
                sensor_uuid.append(raw['sensor_uuid'])
                return Response({'sensor_uuid': sensor_uuid[0], 'credential': 'S' * 43}, 201)
            if request.full_url.endswith('/self'):
                return Response({'sensor_uuid': sensor_uuid[0], 'enabled': True})
            return Response({'grants': []})
    monkeypatch.setattr(cli, 'EnrollmentClient', lambda *a, **k: EnrollmentClient(*a, **k, opener=Opener()))
    monkeypatch.setattr(cli, 'CoreClient', lambda config: CoreClient(config, opener=Opener()))
    monkeypatch.setattr(cli, '_check_nmap', lambda: None)
    monkeypatch.setattr(cli.getpass, 'getpass', lambda prompt: 'T' * 43)
    monkeypatch.setattr(windows.subprocess, 'run', lambda *a, **k: pytest.fail('enrollment cannot scan'))
    args = SimpleNamespace(config=str(tmp_path / 'config.json'), grant_file=str(tmp_path / 'grants.json'),
                           request_timeout=15, sensor_uuid=None, capability=None, core_url='https://core.test',
                           development_mode=False, platform='windows', name='Windows sensor')
    cli._enroll(args, logging.getLogger('test.sensor'))
    raw = json.loads((tmp_path / 'config.json').read_text())
    assert str(UUID(raw['sensor_uuid'])) == sensor_uuid[0] and raw['sensor_credential'] == 'S' * 43
    assert len([entry for entry in calls if entry[0] == 'protect']) == 2
    assert len(requests) == 3 and all('/tasks/' not in r.full_url for r in requests)
    output = capsys.readouterr()
    assert 'S' * 43 not in output.out + output.err and 'T' * 43 not in output.out + output.err


def test_windows_self_test_checks_only_dependency_identity_and_grant(tmp_path, monkeypatch):
    import sensor.__main__ as cli
    from sensor.config import SensorConfig
    from sensor.state import write_grants
    path = tmp_path / 'grants.json'
    write_grants(path, UUID_VALUE, [], ('HOST_DISCOVERY',))
    config = SensorConfig('https://core.test', UUID_VALUE, 'S' * 43, path, platform_name='windows')
    calls = []
    monkeypatch.setattr(cli.platform, 'system', lambda: 'Windows')
    monkeypatch.setattr(windows, 'resolve_nmap', lambda: calls.append('dependency'))
    monkeypatch.setattr(windows.subprocess, 'run', lambda *a, **k: pytest.fail('self-test cannot scan'))
    client = SimpleNamespace(get_self=lambda: {'sensor_uuid': UUID_VALUE, 'enabled': True}, get_grant=lambda: {'grants': []})
    cli._self_test(config, client, logging.getLogger('test.sensor'))
    assert calls == ['dependency']


def test_windows_packaging_has_closed_paths_identity_and_preservation():
    base = ROOT / 'packaging/windows'
    install, uninstall = (base / 'install.ps1').read_text(), (base / 'uninstall.ps1').read_text()
    common = (base / 'common.ps1').read_text()
    for script in base.glob('*.ps1'):
        text = script.read_text().lower()
        assert 'set-strictmode' in text and "$erroractionpreference = 'stop'" in text
        assert not any(word in text for word in ('invoke-expression', 'invoke-webrequest', 'downloadfile', 'curl ', 'iex '))
    assert 'GetFolderPath' in common and 'CommonApplicationData' in common
    assert 'Assert-TrustedExecutable' in install and 'Assert-SensorTree' in uninstall
    assert 'config.example.json' in uninstall and 'if ($Purge)' in uninstall
    assert 'Start-Service' not in install.split("if (-not $PythonPath)")[1]
    assert 'Remove-Item -LiteralPath $paths.Data -Recurse' not in uninstall
    assert 'SetAccessRuleProtection($true, $false)' in common and "'S-1-5-19'" in common


def test_powershell_scripts_parse_without_execution():
    executable = shutil.which('pwsh')
    if not executable: pytest.skip('PowerShell unavailable; static checks cover packaging')
    script = "$bad=$false; Get-ChildItem packaging/windows/*.ps1 | ForEach-Object { $t=$null; $e=$null; $null=[System.Management.Automation.Language.Parser]::ParseFile($_.FullName,[ref]$t,[ref]$e); if ($e.Count) { $e; $bad=$true } }; if ($bad) { exit 1 }"
    result = subprocess.run([executable, '-NoLogo', '-NoProfile', '-NonInteractive', '-Command', script], cwd=ROOT,
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr

@pytest.fixture
def service_module(monkeypatch):
    logs, statuses, installs, changes = [], [], [], []
    class Framework:
        def __init__(self, args): pass
        def ReportServiceStatus(self, status, **kw): statuses.append((status, kw))
    constants = ['SERVICE_STOP_PENDING', 'SERVICE_STOPPED', 'SERVICE_DEMAND_START', 'SC_MANAGER_CONNECT',
                 'SERVICE_CHANGE_CONFIG', 'SERVICE_CONFIG_FAILURE_ACTIONS', 'SERVICE_CONFIG_FAILURE_ACTIONS_FLAG',
                 'SC_ACTION_RESTART', 'SC_ACTION_NONE']
    api = SimpleNamespace(**{name: i for i, name in enumerate(constants, 1)})
    api.error = type('WinError', (Exception,), {})
    api.OpenSCManager = lambda *a: 'manager'
    api.OpenService = lambda *a: 'service'
    api.CloseServiceHandle = lambda *a: None
    api.ChangeServiceConfig2 = lambda *a: changes.append(a)
    util = SimpleNamespace(ServiceFramework=Framework, QueryServiceStatus=lambda *a: (0, 1),
                           ChangeServiceConfig=lambda *a, **k: installs.append((a, k)),
                           SetServiceCustomOption=lambda *a: None)
    monkeypatch.setitem(sys.modules, 'servicemanager', SimpleNamespace(LogInfoMsg=lambda msg: logs.append(msg),
                                                                     LogErrorMsg=lambda msg: logs.append(msg)))
    monkeypatch.setitem(sys.modules, 'win32service', api)
    monkeypatch.setitem(sys.modules, 'win32serviceutil', util)
    monkeypatch.setitem(sys.modules, 'winreg', SimpleNamespace(HKEY_LOCAL_MACHINE=1, OpenKey=lambda *a: nullcontext('key'),
                                                            QueryValueEx=lambda *a: (r'C:\Program Files\Nmap\nmap.exe', 1)))
    monkeypatch.delitem(sys.modules, 'sensor.windows_service', raising=False)
    module = importlib.import_module('sensor.windows_service')
    yield SimpleNamespace(module=module, logs=logs, statuses=statuses, installs=installs, changes=changes)
    sys.modules.pop('sensor.windows_service', None)


def test_scm_stop_and_service_runtime_use_shared_event_without_threads(service_module, monkeypatch):
    module = service_module.module
    service = module.SentinelIPSensorService([])
    closed, runs = [], []
    monkeypatch.setattr(module, 'default_paths', lambda: (Path('config.json'), Path('grants.json')))
    monkeypatch.setattr(module, 'load_config', lambda path: 'config')
    monkeypatch.setattr(module, 'CoreClient', lambda config: SimpleNamespace(close=lambda: closed.append(True)))
    def run(config, client, stop_event, logger):
        runs.append((config, stop_event))
        service.SvcStop()
        assert stop_event.is_set()
    monkeypatch.setattr(module, 'run_sensor', run)
    service.SvcDoRun()
    assert runs == [('config', service.stop_event)] and closed == [True]
    assert service_module.statuses[0][1]['waitHint'] == 120000


def test_scm_failure_is_sanitized_and_eventlog_excludes_secret_fields(service_module, monkeypatch):
    module = service_module.module
    monkeypatch.setattr(module, 'default_paths', lambda: (Path('config.json'), Path('grants.json')))
    def fail(path): raise ValueError('SECRET-CREDENTIAL')
    monkeypatch.setattr(module, 'load_config', fail)
    module.SentinelIPSensorService([]).SvcDoRun()
    handler = module.EventLogHandler()
    handler.emit(logging.LogRecord('test', logging.INFO, '', 1,
                 json.dumps({'status': 'HEARTBEAT_OK', 'Authorization': 'SECRET-CREDENTIAL', 'credential': 'SECRET-CREDENTIAL'}), (), None))
    assert service_module.statuses[-1][1]['svcExitCode'] == 1
    assert 'HEARTBEAT_OK' in service_module.logs[-1]
    assert all('SECRET-CREDENTIAL' not in msg for msg in service_module.logs)


def test_service_installs_as_localservice_with_bounded_recovery(service_module, monkeypatch):
    monkeypatch.setattr(security, 'assert_code', lambda path: None)
    monkeypatch.setattr(windows, 'resolve_nmap', lambda: r'C:\Program Files\Nmap\nmap.exe')
    service_module.module.install_service('SentinelIPSensorService.SentinelIPSensorService')
    _, options = service_module.installs[0]
    assert options['userName'] == r'NT AUTHORITY\LocalService'
    actions = service_module.changes[0][2]['Actions']
    assert [delay for _, delay in actions] == [10000, 30000, 60000, 0]
    assert service_module.changes[0][2]['Command'] == ''


def _windows_install_module_lists():
    """Mirror the installer's closed module lists without executing PowerShell."""
    import re
    text = (ROOT / 'packaging/windows/install.ps1').read_text()
    values = {}
    for variable in ('sensorModules', 'serviceModules'):
        match = re.search(r'\$' + variable + r'\s*=\s*@\((.*?)\)', text, re.S)
        assert match, f'{variable} missing from Windows installer'
        values[variable] = re.findall(r"'([^']+)'", match.group(1))
    return values


def test_windows_packaged_python_dependency_closure_is_complete():
    """Every local import reachable from packaged modules must itself be packaged."""
    import ast

    lists = _windows_install_module_lists()
    packaged = {
        *(f'sensor.{name}' for name in lists['sensorModules']),
        *(f'services.{name}' for name in lists['serviceModules']),
        'services.scanner_adapters.__init__',
        'services.scanner_adapters.nmap_adapter',
    }
    pending = list(packaged)
    visited = set()
    missing = set()
    while pending:
        module = pending.pop()
        if module in visited:
            continue
        visited.add(module)
        path = ROOT.joinpath(*module.split('.')).with_suffix('.py')
        assert path.is_file(), f'packaged module source missing: {module}'
        tree = ast.parse(path.read_text(), filename=str(path))
        for node in ast.walk(tree):
            imported = []
            if isinstance(node, ast.Import):
                imported = [item.name for item in node.names]
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                imported = [node.module]
            elif isinstance(node, ast.ImportFrom) and node.level == 1 and node.module:
                imported = [module.rsplit('.', 1)[0] + '.' + node.module]
            for name in imported:
                if not name.startswith(('sensor.', 'services.')):
                    continue
                candidate = ROOT.joinpath(*name.split('.')).with_suffix('.py')
                if candidate.is_file() and name not in packaged:
                    missing.add(name)
                elif candidate.is_file() and name not in visited:
                    pending.append(name)
    assert not missing, f'Windows installer omits runtime module(s): {sorted(missing)}'


def test_windows_packaged_tree_imports_without_repository_fallback(tmp_path):
    """Build the installer's Python tree and import it with only that tree on sys.path."""
    lists = _windows_install_module_lists()
    app = tmp_path / 'installed'
    (app / 'sensor').mkdir(parents=True)
    (app / 'services/scanner_adapters').mkdir(parents=True)
    for name in lists['sensorModules']:
        shutil.copy2(ROOT / 'sensor' / f'{name}.py', app / 'sensor' / f'{name}.py')
    for name in lists['serviceModules']:
        shutil.copy2(ROOT / 'services' / f'{name}.py', app / 'services' / f'{name}.py')
    for name in ('__init__.py', 'nmap_adapter.py'):
        shutil.copy2(ROOT / 'services/scanner_adapters' / name, app / 'services/scanner_adapters' / name)
    shutil.copy2(ROOT / 'packaging/windows/sensor_launcher.py', app / 'sensor_launcher.py')

    code = (
        "import pathlib,sys; root=pathlib.Path(sys.argv[1]).resolve(); "
        "sys.path=[str(root)]+[p for p in sys.path if 'SentinelIP' not in p and p not in ('', str(pathlib.Path.cwd()))]; "
        "import sensor.__main__, services.windows_sensor_executor; "
        "assert pathlib.Path(sensor.__main__.__file__).resolve().is_relative_to(root); "
        "assert pathlib.Path(services.windows_sensor_executor.__file__).resolve().is_relative_to(root)"
    )
    result = subprocess.run([sys.executable, '-I', '-c', code, str(app)], cwd=tmp_path,
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr
