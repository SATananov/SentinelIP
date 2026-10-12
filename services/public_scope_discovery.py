from collections.abc import Mapping

from database import cves as cves_db
from database import inventory as inventory_db
from services.device_inventory import DeviceInventoryError
from services.risk_engine import RiskEngine
from services.scan_models import ScanResult
from services.scope_authorization import (
    ScopeAuthorizationError,
    require_public_ipv4_scope,
)
from services.service_inventory import ServiceInventoryService
from services.service_models import ServiceDiscoveryResult


class PublicScopeDiscoveryError(ValueError):
    """Raised when public scope evidence cannot be safely persisted."""


def scan_public_scope(
    scope: Mapping[str, object],
    host_scanner,
    service_scanner,
    *,
    db_path,
) -> dict:
    try:
        target = require_public_ipv4_scope(scope)
    except ScopeAuthorizationError as exc:
        raise PublicScopeDiscoveryError(str(exc)) from exc

    host_result = host_scanner.discover_public_host(target)
    if not isinstance(host_result, ScanResult):
        raise PublicScopeDiscoveryError("Host scanner returned invalid evidence.")
    if host_result.target_network != target or host_result.errors:
        raise PublicScopeDiscoveryError("Host scan result does not match the scope.")
    if any(host.ip_address != target for host in host_result.hosts):
        raise PublicScopeDiscoveryError("Host scan returned evidence outside scope.")
    host = next((item for item in host_result.hosts if item.ip_address == target), None)
    if host is None:
        return {
            "scope_id": scope["id"],
            "target": target,
            "state": "NOT_OBSERVED",
            "device": None,
            "ports": [],
            "services": [],
            "findings": [],
            "cve_matches": [],
        }

    observed_at = inventory_db.timestamp_text(host.discovered_at)
    try:
        device = inventory_db.create_scope_device(
            scope["id"],
            first_seen=observed_at,
            last_seen=observed_at,
            status="ONLINE",
            db_path=db_path,
        )
        inventory_db.save_scope_device_observation(
            scope_id=scope["id"],
            device_id=device["id"],
            ip_address=target,
            status="ONLINE",
            observed_at=observed_at,
            source=host.source,
            db_path=db_path,
        )
    except (ValueError, DeviceInventoryError) as exc:
        raise PublicScopeDiscoveryError(str(exc)) from exc

    service_result = service_scanner.discover_public_services(target)
    if not isinstance(service_result, ServiceDiscoveryResult):
        raise PublicScopeDiscoveryError("Service scanner returned invalid evidence.")
    inventory = ServiceInventoryService(db_path=db_path).process_public_result(
        scope, device, service_result
    )
    current_device = inventory_db.get_device(device["id"], db_path=db_path)
    findings = RiskEngine(db_path=db_path).evaluate_scope_device(
        current_device, scope["id"]
    )
    return {
        "scope_id": scope["id"],
        "target": target,
        "state": "OBSERVED",
        "device": current_device,
        "ports": inventory["ports"],
        "services": inventory["services"],
        "findings": findings,
        "cve_matches": cves_db.list_device_cve_matches(device["id"], db_path),
    }
