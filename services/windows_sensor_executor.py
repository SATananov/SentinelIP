"""Windows adapters: fixed local interface query and unprivileged typed discovery."""
from datetime import datetime
import ipaddress
import json
import os
from pathlib import Path
import shutil
import subprocess

from services.remote_sensor_executor import BoundedRemoteSensorExecutor
from services.remote_sensor_models import RemoteSensorError, RFC1918, private_lan, validate_remote_task
from services.scan_models import ScanResult
from services.service_models import ServiceDiscoveryResult
from services.scanner_adapters.nmap_adapter import (
    CONSERVATIVE_TCP_PORTS, NmapHostDiscoveryScanner, NmapServiceDiscoveryScanner,
    ScannerExecutionError, ScannerTimeoutError,
)
from sensor.windows_security import assert_code, validate_local_path

# Constant, read-only query. No task, target, config value, or user input is interpolated.
INTERFACE_QUERY = r"""
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$connected = @(Get-NetIPInterface -AddressFamily IPv4 | Where-Object ConnectionState -eq 'Connected' | Select-Object -ExpandProperty InterfaceIndex)
$rows = @(Get-NetIPAddress -AddressFamily IPv4 | ForEach-Object {
    [pscustomobject]@{
        ip_address = [string]$_.IPAddress
        prefix_length = [int]$_.PrefixLength
        active = [bool](($connected -contains $_.InterfaceIndex) -and ($_.AddressState -eq 'Preferred'))
    }
})
ConvertTo-Json -InputObject $rows -Compress -Depth 3
""".strip()


def resolve_nmap(configured=None):
    """Only admin-protected nmap.exe files are eligible; never use shell/PATHEXT."""
    from win32com.shell import shell, shellcon
    candidates = []
    configured = configured or os.environ.get('SENTINEL_SENSOR_NMAP')
    if not configured:
        import winreg
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                    r'SYSTEM\CurrentControlSet\Services\SentinelIPSensor\Parameters') as key:
                configured, _ = winreg.QueryValueEx(key, 'NmapPath')
        except FileNotFoundError:
            pass
    if configured:
        candidates = [configured]
    else:
        found = shutil.which('nmap.exe')
        if found:
            candidates.append(found)
        for folder_id in (shellcon.CSIDL_PROGRAM_FILES, shellcon.CSIDL_PROGRAM_FILESX86):
            root = shell.SHGetFolderPath(0, folder_id, None, 0)
            candidates.append(str(Path(root) / 'Nmap' / 'nmap.exe'))
    for candidate in candidates:
        path = validate_local_path(candidate)
        if path.name.lower() != 'nmap.exe':
            raise RemoteSensorError('Windows scanner must be an admin-installed nmap.exe.')
        concrete = Path(str(path))
        if not concrete.is_file():
            continue
        assert_code(concrete)
        return str(concrete)
    raise RemoteSensorError('Windows Nmap is missing; install Nmap explicitly or configure SENTINEL_SENSOR_NMAP.')


def parse_interfaces(output):
    if not isinstance(output, str) or len(output.encode('utf-8')) > 65536:
        raise RemoteSensorError('Windows interface response exceeds its bound.')
    try:
        rows = json.loads(output.lstrip('\ufeff'))
        if not isinstance(rows, list) or len(rows) > 256:
            raise ValueError
        networks = set()
        for row in rows:
            if (not isinstance(row, dict) or set(row) != {'ip_address', 'prefix_length', 'active'}
                    or type(row['active']) is not bool or type(row['prefix_length']) is not int
                    or not 1 <= row['prefix_length'] <= 32 or not isinstance(row['ip_address'], str)):
                raise ValueError
            address = ipaddress.IPv4Address(row['ip_address'])
            if not row['active'] or address.is_loopback or address.is_link_local:
                continue
            network = ipaddress.IPv4Network(f"{address}/{row['prefix_length']}", strict=False)
            if any(network.subnet_of(private) for private in RFC1918):
                networks.add(network)
        return tuple(sorted(networks, key=lambda n: (int(n.network_address), n.prefixlen)))
    except (ValueError, TypeError) as exc:
        raise RemoteSensorError('Windows interface response is malformed.') from exc


def connected_private_networks():
    import win32api
    powershell = Path(win32api.GetSystemDirectory()) / 'WindowsPowerShell' / 'v1.0' / 'powershell.exe'
    assert_code(powershell)
    try:
        completed = subprocess.run(
            [str(powershell), '-NoLogo', '-NoProfile', '-NonInteractive', '-Command', INTERFACE_QUERY],
            shell=False, timeout=15, capture_output=True, text=True, encoding='utf-8', check=False,
            creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0),
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RemoteSensorError('Windows interface query failed.') from exc
    if completed.returncode != 0:
        raise RemoteSensorError('Windows interface query failed.')
    return parse_interfaces(completed.stdout)


def _nmap_xml(arguments, timeout):
    try:
        completed = subprocess.run(arguments, shell=False, timeout=timeout, capture_output=True,
                                   text=True, check=False,
                                   creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
    except subprocess.TimeoutExpired as exc:
        raise ScannerTimeoutError('Windows scanner timed out.') from exc
    except OSError as exc:
        raise ScannerExecutionError('Windows scanner could not be started.') from exc
    if (completed.returncode != 0
            or len(completed.stdout.encode('utf-8')) + len(completed.stderr.encode('utf-8')) > 1_048_576):
        raise ScannerExecutionError('Windows scanner failed or exceeded its output bound.')
    return completed.stdout


class WindowsHostScanner:
    def __init__(self, executable):
        self.executable = executable

    def discover_hosts(self, network_cidr):
        network = str(private_lan(network_cidr))
        started = datetime.now()
        xml = _nmap_xml([self.executable, '--unprivileged', '-sn', '-n', '-PS80,443',
                         '--disable-arp-ping', '--max-retries', '2', '--host-timeout', '10s',
                         '-oX', '-', network], 30)
        ended = datetime.now()
        hosts = NmapHostDiscoveryScanner()._parse_hosts(xml, ended)
        return ScanResult(target_network=network, scanner='nmap', started_at=started,
                          completed_at=ended, hosts=tuple(hosts))


class WindowsServiceScanner:
    def __init__(self, executable):
        self.executable = executable

    def discover_services(self, ip_address):
        address = ipaddress.IPv4Address(ip_address)
        if str(address) != ip_address or not any(address in n for n in RFC1918):
            raise RemoteSensorError('Windows service target must be private IPv4.')
        started = datetime.now()
        xml = _nmap_xml([self.executable, '--unprivileged', '-Pn', '-n', '-sT', '-sV',
                         '--version-light', '--open', '-p', ','.join(map(str, CONSERVATIVE_TCP_PORTS)),
                         '--max-retries', '2', '--host-timeout', '30s', '-oX', '-', ip_address], 45)
        ended = datetime.now()
        ports, services = NmapServiceDiscoveryScanner()._parse_services(xml, ip_address, ended)
        return ServiceDiscoveryResult(target_ip=ip_address, scanner='nmap', started_at=started,
                                      completed_at=ended, ports=tuple(ports), services=tuple(services))


class WindowsRemoteSensorExecutor(BoundedRemoteSensorExecutor):
    def __init__(self, *, network_provider=None):
        executable = resolve_nmap()
        super().__init__(WindowsHostScanner(executable), WindowsServiceScanner(executable))
        self.network_provider = network_provider or connected_private_networks

    def _validate_connected_grant(self, task, grant):
        validate_remote_task(task, grant)
        # Interface presence is only an additional restriction, never authorization.
        if not any(private_lan(grant.cidr).subnet_of(network) for network in self.network_provider()):
            raise RemoteSensorError('Assigned scope is not on an active private Windows interface.')

    def discover_network(self, task, grant):
        self._validate_connected_grant(task, grant)
        return super().discover_network(task, grant)

    def discover_services(self, task, grant):
        self._validate_connected_grant(task, grant)
        return super().discover_services(task, grant)
