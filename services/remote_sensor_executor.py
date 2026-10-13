"""Typed local execution adapter for future sensor processes; no command interface."""
from collections.abc import Mapping
from typing import Protocol
import ipaddress

from services.host_discovery import discover_hosts
from services.remote_sensor_models import (
    LocalExecutorGrant, RemoteSensorError, RemoteTaskContext, validate_remote_task,
)
from services.scan_models import ScanResult
from services.scanner import HostDiscoveryScanner, ServiceDiscoveryScanner
from services.service_discovery import discover_services
from services.service_models import ServiceDiscoveryResult
from services.scanner_adapters.nmap_adapter import NmapHostDiscoveryScanner, NmapServiceDiscoveryScanner


class RemoteSensorExecutor(Protocol):
    def discover_network(self, task: RemoteTaskContext, grant: LocalExecutorGrant) -> ScanResult: ...
    def discover_services(self, task: RemoteTaskContext, grant: LocalExecutorGrant) -> ServiceDiscoveryResult: ...


class BoundedRemoteSensorExecutor:
    """Shared typed task and result validation around platform scanners."""
    def __init__(self, host_scanner: HostDiscoveryScanner | None = None,
                 service_scanner: ServiceDiscoveryScanner | None = None):
        self.host_scanner = host_scanner or NmapHostDiscoveryScanner(timeout_seconds=30, max_output_bytes=1_048_576)
        self.service_scanner = service_scanner or NmapServiceDiscoveryScanner(timeout_seconds=45, max_output_bytes=1_048_576)

    def discover_network(self, task: RemoteTaskContext, grant: LocalExecutorGrant) -> ScanResult:
        validate_remote_task(task, grant)
        network = {'id': task.network_id, 'cidr': grant.cidr, 'authorized': True, 'enabled': True}
        result = discover_hosts(network, self.host_scanner)
        cidr = ipaddress.IPv4Network(grant.cidr, strict=True)
        if any(ipaddress.IPv4Address(host.ip_address) not in cidr for host in result.hosts):
            raise RemoteSensorError('Scanner returned an address outside the local grant.')
        return result

    def discover_services(self, task: RemoteTaskContext, grant: LocalExecutorGrant) -> ServiceDiscoveryResult:
        target = validate_remote_task(task, grant)
        if target is None or task.network_id is None or task.target_device_id is None:
            raise RemoteSensorError('Service task context is incomplete.')
        network = {'id': task.network_id, 'cidr': grant.cidr, 'authorized': True, 'enabled': True}
        device = {'id': task.target_device_id, 'network_id': task.network_id, 'last_ip_address': target}
        return discover_services(network, device, self.service_scanner)


class LinuxRemoteSensorExecutor(BoundedRemoteSensorExecutor):
    """Existing fixed, conservative Linux Nmap profiles."""


def task_context_from_claim(claim: Mapping[str, object]) -> RemoteTaskContext:
    """Decode only the typed fields returned by Core; arbitrary keys are rejected."""
    allowed = {'id', 'sensor_uuid', 'scope_id', 'scope_type', 'task_type', 'scope_cidr',
               'target_ip', 'network_id', 'target_device_id', 'status', 'expires_at',
               'claimed_at', 'started_at', 'attempt_count'}
    if not isinstance(claim, Mapping) or set(claim) - allowed:
        raise RemoteSensorError('Claim contains unsupported task fields.')
    if (type(claim.get('scope_id')) is not int or type(claim.get('network_id')) is not int
            or ('target_device_id' in claim and claim['target_device_id'] is not None
                and type(claim['target_device_id']) is not int)):
        raise RemoteSensorError('Claim contains invalid task identifiers.')
    try:
        return RemoteTaskContext(
            task_id=str(claim['id']), sensor_uuid=str(claim['sensor_uuid']),
            scope_id=claim['scope_id'], scope_type=str(claim['scope_type']),
            task_type=str(claim['task_type']), scope_cidr=str(claim['scope_cidr']),
            target_ip=claim.get('target_ip'), network_id=claim.get('network_id'),
            target_device_id=claim.get('target_device_id'),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise RemoteSensorError('Claim is missing typed task metadata.') from exc
