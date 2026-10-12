from collections.abc import Mapping

from database import cves as cves_db
from database import inventory as inventory_db
from database import scopes as scopes_db
from services.device_inventory import DeviceInventoryError
from services.hostname_resolution import (
    HostnameResolutionError,
    HostnameResolver,
    IneligibleHostnameResolution,
)
from services.public_target_policy import normalize_public_ipv4
from services.risk_engine import RiskEngine
from services.scan_models import ScanResult
from services.scope_authorization import (
    ScopeAuthorizationError,
    require_hostname_scope,
)
from services.service_inventory import ServiceInventoryService
from services.service_models import ServiceDiscoveryResult


class HostnameScopeDiscoveryError(ValueError):
    """Raised when hostname evidence cannot be safely scanned or persisted."""


class HostnameReauthorizationRequired(HostnameScopeDiscoveryError):
    """Raised when current DNS evidence differs from the confirmed address set."""


class HostnameResolverUnavailable(HostnameScopeDiscoveryError):
    """Raised when DNS could not be checked because the resolver failed or timed out."""


def verify_hostname_resolution(scope, resolver: HostnameResolver, *, db_path) -> tuple[str, ...]:
    try:
        hostname = require_hostname_scope(scope, require_current=False)
    except ScopeAuthorizationError as exc:
        raise HostnameScopeDiscoveryError(str(exc)) from exc
    if (
        scope.get("resolution_status") != "CURRENT"
        or not isinstance(scope.get("resolution_verified_at"), str)
        or not scope["resolution_verified_at"].strip()
        or not isinstance(scope.get("resolution_version"), str)
        or not scope["resolution_version"].strip()
    ):
        raise HostnameReauthorizationRequired(
            "Hostname resolution changed or has not been authorized again."
        )
    approved = tuple(scopes_db.list_hostname_addresses(scope["id"], db_path))
    try:
        approved = tuple(sorted(normalize_public_ipv4(value) for value in approved))
    except ValueError as exc:
        scopes_db.mark_hostname_resolution_stale(scope["id"], db_path)
        raise HostnameReauthorizationRequired(
            "The approved hostname address set is invalid and requires authorization again."
        ) from exc
    if not approved:
        scopes_db.mark_hostname_resolution_stale(scope["id"], db_path)
        raise HostnameReauthorizationRequired(
            "The hostname has no approved addresses and requires authorization again."
        )
    try:
        current = resolver.resolve(hostname).resolved_ipv4
    except IneligibleHostnameResolution as exc:
        scopes_db.mark_hostname_resolution_stale(scope["id"], db_path)
        raise HostnameReauthorizationRequired(
            "Current hostname resolution is no longer eligible; authorization is required again."
        ) from exc
    except HostnameResolutionError as exc:
        raise HostnameResolverUnavailable("Hostname DNS resolution could not be completed.") from exc
    if current != approved:
        scopes_db.mark_hostname_resolution_stale(scope["id"], db_path)
        raise HostnameReauthorizationRequired(
            "Hostname DNS results changed. Review the current addresses and renew authorization before scanning."
        )
    return approved


def scan_hostname_scope(
    scope: Mapping[str, object],
    resolver: HostnameResolver,
    host_scanner,
    service_scanner,
    *,
    db_path,
) -> dict:
    hostname = require_hostname_scope(scope, require_current=False)
    approved = verify_hostname_resolution(scope, resolver, db_path=db_path)

    assets = []
    for address in approved:
        host_result = host_scanner.discover_public_host(address)
        if (
            not isinstance(host_result, ScanResult)
            or host_result.target_network != address
            or host_result.errors
            or any(host.ip_address != address for host in host_result.hosts)
        ):
            raise HostnameScopeDiscoveryError("Host scan result does not match the approved address.")
        host = next((item for item in host_result.hosts if item.ip_address == address), None)
        if host is None:
            continue

        observed_at = inventory_db.timestamp_text(host.discovered_at)
        try:
            device = inventory_db.create_scope_device(
                scope["id"],
                ip_address=address,
                first_seen=observed_at,
                last_seen=observed_at,
                status="ONLINE",
                db_path=db_path,
            )
            inventory_db.save_scope_device_observation(
                scope_id=scope["id"],
                device_id=device["id"],
                ip_address=address,
                status="ONLINE",
                observed_at=observed_at,
                source=host.source,
                db_path=db_path,
            )
        except (ValueError, DeviceInventoryError) as exc:
            raise HostnameScopeDiscoveryError(str(exc)) from exc

        service_result = service_scanner.discover_public_services(address)
        if not isinstance(service_result, ServiceDiscoveryResult):
            raise HostnameScopeDiscoveryError("Service scanner returned invalid evidence.")
        inventory = ServiceInventoryService(db_path=db_path).process_hostname_result(
            scope, device, service_result
        )
        current_device = inventory_db.get_device(device["id"], db_path=db_path)
        findings = RiskEngine(db_path=db_path).evaluate_scope_device(
            current_device, scope["id"]
        )
        assets.append(
            {
                "device": current_device,
                "ports": inventory["ports"],
                "services": inventory["services"],
                "findings": findings,
                "cve_matches": cves_db.list_device_cve_matches(device["id"], db_path),
            }
        )

    return {
        "scope_id": scope["id"],
        "target": hostname,
        "state": "OBSERVED" if assets else "NOT_OBSERVED",
        "approved_addresses": list(approved),
        "devices": [asset["device"] for asset in assets],
        "assets": assets,
    }
