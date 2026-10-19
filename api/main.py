import csv

from api.remote_sensors import local_management, register_remote_routes
from api.sensor_enrollment import SensorBodyLimitMiddleware, register_machine_routes
from api.remote_tasks import register_remote_task_routes
from api.perimeter_ingestion import register_perimeter_ingestion_routes
from api.external_exposure_assessment import register_external_exposure_assessment_routes
from api.external_exposure_classification import register_external_exposure_classification_routes
from api.external_exposure_changes import register_external_exposure_change_routes
from api.external_exposure_dashboard import register_external_exposure_dashboard_routes
from api.incident_reviews import register_incident_review_routes
from api.investigation import register_investigation_routes
from api.data_lifecycle import register_data_lifecycle_routes
from api.management_audit import register_management_audit_routes
from database.remote_sensors import RemoteSensorStore
import io
import sqlite3
from datetime import datetime, timedelta
from typing import Literal

from fastapi import Depends, FastAPI, Header, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from database import inventory as workspace_inventory_db
from database import cves as workspace_cves_db
from database import findings as workspace_findings_db
from database import services as workspace_services_db
from services.service_discovery import (
    ServiceDiscoveryError,
    discover_services as workspace_discover_services,
)
from services.service_inventory import ServiceInventoryService
from database import networks as workspace_networks_db
from services.device_inventory import DeviceInventoryService
from services.host_discovery import HostDiscoveryError, discover_hosts as workspace_discover_hosts
from services.scanner_adapters.nmap_adapter import (
    NmapHostDiscoveryScanner,
    NmapServiceDiscoveryScanner,
    ScannerExecutionError,
    ScannerParseError,
    ScannerTimeoutError,
    ScannerUnavailableError,
)
from fastapi.responses import Response, StreamingResponse

from database.db import (
    get_alerts,
    get_event_type_counts,
    get_events_over_time,
    get_filtered_events,
    get_overview,
    get_paginated_events,
    get_severity_counts,
    get_source_ips,
    get_top_source_ips,
    initialize_database,
)
from database.db import DB_PATH
from database.threats import get_threat, query_threats
from database.correlations import get_correlation, query_correlations
from database.web_detections import query_web_detections
from database.incidents import get_incident, query_incidents
from database.perimeter import get_perimeter_event, query_perimeter_events
from database.perimeter_detections import get_perimeter_detection, query_perimeter_detections
from database.perimeter_policy_correlations import (
    get_perimeter_policy_correlation,
    query_perimeter_policy_correlations,
)
from database.perimeter_host_correlations import (
    get_perimeter_host_correlation,
    query_perimeter_host_correlations,
)
from database.external_exposures import (
    get_external_exposure,
    query_external_exposures,
    list_exposure_observations,
)
from services.perimeter_dashboard import build_perimeter_dashboard
from database.networks import (
    create_network,
    delete_network,
    get_network,
    list_networks,
    update_network,
)
from api.schemas import NetworkCreate, NetworkResponse, NetworkUpdate
from api.schemas import DnsTelemetryCreate, WebTelemetryCreate
from services.pdf_report import build_security_report
from services.telemetry_ingestion import TelemetryIngestionError, ingest_dns, ingest_web
from services.target_policy import TargetPolicyError
from database.scopes import get_scope as get_authorized_scope
from database.scopes import (
    create_hostname_scope,
    create_scope,
    get_scope_for_network,
    list_scopes,
    reauthorize_hostname_scope,
    require_cidr_membership,
)
from services.scope_authorization import (
    ScopeAuthorizationError,
    require_private_network_scope,
    require_public_ipv4_scope,
    require_hostname_scope,
    HOSTNAME_CONFIRMATION_VERSION,
)
from api.schemas import (
    AuthorizedScopeResponse,
    HostnamePreviewRequest,
    HostnameScopeCreate,
    PublicIPv4ScopeCreate,
    PublicCIDRPreview,
    PublicCIDRScopeCreate,
)
from database.inventory import list_scope_devices
from services.public_target_policy import (
    PUBLIC_IPV4_CONFIRMATION_VERSION,
    PublicTargetPolicyError,
    normalize_public_ipv4,
)
from services.public_scope_discovery import (
    PublicScopeDiscoveryError, scan_public_scope, scan_public_cidr_scope,
)
from services.public_cidr_policy import (
    normalize_public_cidr, public_cidr_addresses, PUBLIC_CIDR_CONFIRMATION_VERSION,
    MAX_PUBLIC_CIDR_ADDRESSES,
)
from services.risk_engine import RiskEngine
from services.local_network_discovery import (
    LocalNetworkDiscoveryError,
    discover_local_networks,
)
from services.hostname_policy import HostnamePolicyError, normalize_hostname
from services.hostname_resolution import (
    HostnameResolutionError,
    HostnameResolver,
    IneligibleHostnameResolution,
    preview_hostname,
)
from services.hostname_scope_discovery import (
    HostnameReauthorizationRequired,
    HostnameResolverUnavailable,
    HostnameScopeDiscoveryError,
    scan_hostname_scope,
    verify_hostname_resolution,
)


app = FastAPI(
    title="SentinelIP API",
    version="2.5.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "DELETE"],
    allow_headers=["*"],
)


def resolve_since(time_range: str):
    if time_range == "15m":
        return (
            datetime.now() - timedelta(minutes=15)
        ).isoformat(timespec="seconds")

    if time_range == "1h":
        return (
            datetime.now() - timedelta(hours=1)
        ).isoformat(timespec="seconds")

    if time_range == "24h":
        return (
            datetime.now() - timedelta(hours=24)
        ).isoformat(timespec="seconds")

    return None


@app.get("/health")
def health():
    return {
        "status": "ok",
        "service": "SentinelIP",
    }


def _telemetry_error(exc: TelemetryIngestionError):
    raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc


@app.post("/telemetry/web", status_code=202)
def ingest_web_telemetry(
    payload: WebTelemetryCreate,
    sensor_id: int | None = Header(default=None, alias="X-SentinelIP-Sensor-ID"),
    sensor_token: str | None = Header(default=None, alias="X-SentinelIP-Sensor-Token"),
):
    if sensor_id is None:
        raise HTTPException(status_code=401, detail="Telemetry authentication failed.")
    try:
        return ingest_web(
            sensor_id,
            sensor_token,
            payload.model_dump(),
            db_path=DB_PATH,
        )
    except TelemetryIngestionError as exc:
        _telemetry_error(exc)


@app.post("/telemetry/dns", status_code=202)
def ingest_dns_telemetry(
    payload: DnsTelemetryCreate,
    sensor_id: int | None = Header(default=None, alias="X-SentinelIP-Sensor-ID"),
    sensor_token: str | None = Header(default=None, alias="X-SentinelIP-Sensor-Token"),
):
    if sensor_id is None:
        raise HTTPException(status_code=401, detail="Telemetry authentication failed.")
    try:
        return ingest_dns(
            sensor_id,
            sensor_token,
            payload.model_dump(),
            db_path=DB_PATH,
        )
    except TelemetryIngestionError as exc:
        _telemetry_error(exc)


@app.get("/networks", response_model=list[NetworkResponse], dependencies=[Depends(local_management)])
def networks():
    initialize_database(DB_PATH)
    return list_networks(db_path=DB_PATH)


@app.post("/networks", response_model=NetworkResponse, status_code=201,
          dependencies=[Depends(local_management)])
def create_authorized_network(payload: NetworkCreate):
    try:
        return create_network(
            cidr=payload.cidr,
            name=payload.name,
            description=payload.description,
            authorized=payload.authorized,
            enabled=payload.enabled,
            db_path=DB_PATH,
            actor_type="LOCAL_OPERATOR",
        )
    except TargetPolicyError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except sqlite3.IntegrityError as exc:
        raise HTTPException(
            status_code=409,
            detail="A network with this CIDR already exists.",
        ) from exc


@app.get("/networks/{network_id}", response_model=NetworkResponse,
         dependencies=[Depends(local_management)])
def get_authorized_network(network_id: int):
    network = get_network(network_id, db_path=DB_PATH)

    if network is None:
        raise HTTPException(status_code=404, detail="Network not found.")

    return network


@app.patch("/networks/{network_id}", response_model=NetworkResponse,
           dependencies=[Depends(local_management)])
def update_authorized_network(
    network_id: int,
    payload: NetworkUpdate,
):
    if get_network(network_id, db_path=DB_PATH) is None:
        raise HTTPException(status_code=404, detail="Network not found.")

    updates = payload.model_dump(exclude_unset=True)

    if any(value is None for value in updates.values()):
        raise HTTPException(
            status_code=422,
            detail="Network update values cannot be null.",
        )

    return update_network(network_id, db_path=DB_PATH, actor_type="LOCAL_OPERATOR", **updates)


@app.delete("/networks/{network_id}", status_code=204, dependencies=[Depends(local_management)])
def delete_authorized_network(network_id: int):
    if not delete_network(network_id, db_path=DB_PATH, actor_type="LOCAL_OPERATOR"):
        raise HTTPException(status_code=404, detail="Network not found.")


@app.get("/scopes", response_model=list[AuthorizedScopeResponse], dependencies=[Depends(local_management)])
def authorized_scopes():
    return list_scopes(db_path=DB_PATH)


@app.get("/scopes/{scope_id}", response_model=AuthorizedScopeResponse,
         dependencies=[Depends(local_management)])
def authorized_scope_detail(scope_id: int):
    if scope_id <= 0:
        raise HTTPException(status_code=422, detail="Scope ID must be positive.")
    scope = get_authorized_scope(scope_id, db_path=DB_PATH)
    if scope is None:
        raise HTTPException(status_code=404, detail="Scope not found.")
    return scope


@app.post(
    "/scopes/public-ipv4",
    response_model=AuthorizedScopeResponse,
    status_code=201,
    dependencies=[Depends(local_management)],
)
def create_authorized_public_ipv4_scope(payload: PublicIPv4ScopeCreate):
    if payload.authorization_confirmed is not True:
        raise HTTPException(
            status_code=422,
            detail="Explicit authorization confirmation is required.",
        )
    if payload.authorization_confirmation_version != PUBLIC_IPV4_CONFIRMATION_VERSION:
        raise HTTPException(
            status_code=422,
            detail="Authorization confirmation version is unsupported.",
        )
    try:
        target = normalize_public_ipv4(payload.target)
    except PublicTargetPolicyError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    try:
        return create_scope(
            scope_type="PUBLIC_IPV4",
            canonical_target=target,
            name=payload.name,
            description=payload.description,
            authorized=True,
            enabled=True,
            authorization_confirmed_at=datetime.now().isoformat(timespec="seconds"),
            authorization_confirmation_version=payload.authorization_confirmation_version,
            authorization_source="api_explicit_authorization_confirmation",
            db_path=DB_PATH,
            actor_type="LOCAL_OPERATOR",
        )
    except sqlite3.IntegrityError as exc:
        raise HTTPException(
            status_code=409,
            detail="A scope for this public IPv4 target already exists.",
        ) from exc


@app.post("/scopes/public-cidr/preview", dependencies=[Depends(local_management)])
def preview_public_cidr(payload: PublicCIDRPreview):
    try:
        target = normalize_public_cidr(payload.target)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return {"canonical_target": target, "address_count": len(public_cidr_addresses(target)),
            "maximum_addresses": MAX_PUBLIC_CIDR_ADDRESSES, "enumeration": "ALL_ADDRESSES"}


@app.post("/scopes/public-cidr", response_model=AuthorizedScopeResponse, status_code=201,
          dependencies=[Depends(local_management)])
def create_public_cidr_scope(payload: PublicCIDRScopeCreate):
    if payload.authorization_confirmed is not True or payload.authorization_confirmation_version != PUBLIC_CIDR_CONFIRMATION_VERSION:
        raise HTTPException(status_code=422, detail="Explicit public CIDR authorization with the supported confirmation version is required.")
    try:
        target = normalize_public_cidr(payload.target)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    try:
        return create_scope(
            scope_type="PUBLIC_CIDR", canonical_target=target,
            name=payload.name, description=payload.description, authorized=True, enabled=True,
            authorization_confirmed_at=datetime.now().isoformat(timespec="seconds"),
            authorization_confirmation_version=PUBLIC_CIDR_CONFIRMATION_VERSION,
            authorization_source="api_explicit_public_cidr_confirmation", db_path=DB_PATH,
            actor_type="LOCAL_OPERATOR",
        )
    except sqlite3.IntegrityError as exc:
        raise HTTPException(status_code=409, detail="A scope for this public CIDR already exists.") from exc


def _verified_hostname_approval(payload: HostnameScopeCreate):
    if payload.authorization_confirmed is not True:
        raise HTTPException(
            status_code=422,
            detail="Explicit authorization confirmation is required.",
        )
    if payload.authorization_confirmation_version != HOSTNAME_CONFIRMATION_VERSION:
        raise HTTPException(
            status_code=422,
            detail="Authorization confirmation version is unsupported.",
        )
    try:
        hostname = normalize_hostname(payload.canonical_hostname)
    except HostnamePolicyError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    if hostname != payload.canonical_hostname:
        raise HTTPException(
            status_code=422,
            detail="A canonical hostname is required.",
        )
    try:
        requested_addresses = tuple(
            sorted(normalize_public_ipv4(value) for value in payload.approved_resolved_ipv4)
        )
    except PublicTargetPolicyError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    if len(requested_addresses) != len(set(requested_addresses)):
        raise HTTPException(status_code=422, detail="Approved IPv4 addresses must be unique.")
    try:
        resolved = HostnameResolver().resolve(hostname)
    except IneligibleHostnameResolution as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except HostnameResolutionError as exc:
        raise HTTPException(status_code=503, detail="Hostname DNS resolution could not be verified.") from exc
    if requested_addresses != resolved.resolved_ipv4:
        raise HTTPException(
            status_code=409,
            detail="Hostname DNS results changed. Preview the current addresses and confirm authorization again.",
        )
    return hostname, requested_addresses, resolved.resolution_version


@app.post("/scopes/hostname/preview", dependencies=[Depends(local_management)])
def preview_authorized_hostname(payload: HostnamePreviewRequest):
    try:
        hostname = normalize_hostname(payload.hostname)
    except HostnamePolicyError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return preview_hostname(hostname, HostnameResolver())


@app.post(
    "/scopes/hostname",
    response_model=AuthorizedScopeResponse,
    status_code=201,
    dependencies=[Depends(local_management)],
)
def create_authorized_hostname_scope(payload: HostnameScopeCreate):
    hostname, addresses, resolution_version = _verified_hostname_approval(payload)
    try:
        return create_hostname_scope(
            canonical_hostname=hostname,
            approved_addresses=list(addresses),
            name=payload.name,
            description=payload.description,
            authorization_confirmed_at=datetime.now().isoformat(timespec="seconds"),
            authorization_confirmation_version=payload.authorization_confirmation_version,
            authorization_source="api_explicit_hostname_authorization_confirmation",
            resolution_version=resolution_version,
            db_path=DB_PATH,
            actor_type="LOCAL_OPERATOR",
        )
    except sqlite3.IntegrityError as exc:
        raise HTTPException(
            status_code=409,
            detail="A scope for this hostname already exists.",
        ) from exc


@app.post(
    "/scopes/{scope_id}/hostname/reauthorize",
    response_model=AuthorizedScopeResponse,
    dependencies=[Depends(local_management)],
)
def reauthorize_hostname(scope_id: int, payload: HostnameScopeCreate):
    scope = get_authorized_scope(scope_id, db_path=DB_PATH)
    if scope is None:
        raise HTTPException(status_code=404, detail="Scope not found.")
    if scope.get("scope_type") != "HOSTNAME":
        raise HTTPException(status_code=403, detail="The scope is not a hostname target.")
    try:
        existing_hostname = require_hostname_scope(
            scope, require_current=False, require_enabled=False
        )
        requested_hostname = normalize_hostname(payload.canonical_hostname)
        if requested_hostname != existing_hostname or requested_hostname != payload.canonical_hostname:
            raise HTTPException(status_code=422, detail="Hostname does not match the existing scope.")
    except HostnamePolicyError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except ScopeAuthorizationError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    hostname, addresses, resolution_version = _verified_hostname_approval(payload)
    try:
        return reauthorize_hostname_scope(
            scope_id,
            approved_addresses=list(addresses),
            authorization_confirmed_at=datetime.now().isoformat(timespec="seconds"),
            authorization_confirmation_version=payload.authorization_confirmation_version,
            authorization_source="api_explicit_hostname_reauthorization_confirmation",
            resolution_version=resolution_version,
            db_path=DB_PATH,
            actor_type="LOCAL_OPERATOR",
        )
    except ScopeAuthorizationError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc


@app.get("/scopes/{scope_id}/devices", dependencies=[Depends(local_management)])
def list_scope_inventory_devices(scope_id: int):
    scope = get_authorized_scope(scope_id, db_path=DB_PATH)
    if scope is None:
        raise HTTPException(status_code=404, detail="Scope not found.")
    return list_scope_devices(scope_id, db_path=DB_PATH)


@app.post("/scopes/{scope_id}/discover", dependencies=[Depends(local_management)])
def discover_public_scope(scope_id: int):
    scope = get_authorized_scope(scope_id, db_path=DB_PATH)
    if scope is None:
        raise HTTPException(status_code=404, detail="Scope not found.")
    try:
        if scope.get("scope_type") == "PUBLIC_IPV4":
            require_public_ipv4_scope(scope)
            result = scan_public_scope(
                scope,
                NmapHostDiscoveryScanner(),
                NmapServiceDiscoveryScanner(),
                db_path=DB_PATH,
            )
        elif scope.get("scope_type") == "PUBLIC_CIDR":
            require_cidr_membership(scope, DB_PATH)
            result = scan_public_cidr_scope(
                scope, NmapHostDiscoveryScanner(), NmapServiceDiscoveryScanner(), db_path=DB_PATH,
            )
        elif scope.get("scope_type") == "HOSTNAME":
            result = scan_hostname_scope(
                scope,
                HostnameResolver(),
                NmapHostDiscoveryScanner(),
                NmapServiceDiscoveryScanner(),
                db_path=DB_PATH,
            )
        else:
            raise HTTPException(status_code=403, detail="This scope type cannot be scanned.")
    except ScopeAuthorizationError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except HostnameReauthorizationRequired as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except HostnameResolverUnavailable as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except (PublicScopeDiscoveryError, HostnameScopeDiscoveryError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except ScannerUnavailableError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except ScannerTimeoutError as exc:
        raise HTTPException(status_code=504, detail=str(exc)) from exc
    except (ScannerExecutionError, ScannerParseError) as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    return result


@app.post("/scopes/{scope_id}/devices/{device_id}/discover-services",
          dependencies=[Depends(local_management)])
def discover_public_scope_device_services(scope_id: int, device_id: int):
    scope = get_authorized_scope(scope_id, db_path=DB_PATH)
    if scope is None:
        raise HTTPException(status_code=404, detail="Scope not found.")
    device = workspace_inventory_db.get_device(device_id, db_path=DB_PATH)
    if device is None or device.get("scope_id") != scope_id or device.get("network_id") is not None:
        raise HTTPException(status_code=404, detail="Scope device not found.")
    try:
        if scope.get("scope_type") == "PUBLIC_IPV4":
            target = require_public_ipv4_scope(scope)
            if device.get("last_ip_address") != target:
                raise HTTPException(status_code=403, detail="Device target does not match scope.")
            hostname_scope = False
        elif scope.get("scope_type") == "PUBLIC_CIDR":
            addresses = require_cidr_membership(scope, DB_PATH)
            target = device.get("last_ip_address")
            if target not in addresses:
                raise HTTPException(status_code=403, detail="Device is outside the authorized CIDR.")
            hostname_scope = False
        elif scope.get("scope_type") == "HOSTNAME":
            approved = verify_hostname_resolution(
                scope, HostnameResolver(), db_path=DB_PATH
            )
            target = device.get("last_ip_address")
            if target not in approved:
                raise HTTPException(status_code=403, detail="Device address is not approved for this hostname scope.")
            hostname_scope = True
        else:
            raise HTTPException(status_code=403, detail="This scope type does not support service discovery.")
        service_scanner = NmapServiceDiscoveryScanner()
        result = service_scanner.discover_public_services(target)
        inventory_service = ServiceInventoryService(db_path=DB_PATH)
        if hostname_scope:
            inventory = inventory_service.process_hostname_result(scope, device, result)
        elif scope["scope_type"] == "PUBLIC_CIDR":
            inventory = inventory_service.process_cidr_result(scope, device, result)
        else:
            inventory = inventory_service.process_public_result(scope, device, result)
        current_device = workspace_inventory_db.get_device(device_id, db_path=DB_PATH)
        findings = RiskEngine(db_path=DB_PATH).evaluate_scope_device(
            current_device, scope_id
        )
        matches = workspace_cves_db.list_device_cve_matches(device_id, db_path=DB_PATH)
    except ScopeAuthorizationError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except HostnameReauthorizationRequired as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except HostnameResolverUnavailable as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except HostnameScopeDiscoveryError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except ServiceDiscoveryError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except ScannerUnavailableError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except ScannerTimeoutError as exc:
        raise HTTPException(status_code=504, detail=str(exc)) from exc
    except (ScannerExecutionError, ScannerParseError) as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    return {
        "scope_id": scope_id,
        "device_id": device_id,
        "target": target,
        **inventory,
        "findings": findings,
        "cve_matches": matches,
    }


@app.get("/external-exposures", dependencies=[Depends(local_management)])
def external_exposures(
    scope_id: int | None = Query(default=None, ge=1),
    device_id: int | None = Query(default=None, ge=1),
    target_ip: str | None = None,
    port_number: int | None = Query(default=None, ge=1, le=65535),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
):
    if target_ip is not None:
        try:
            target_ip = normalize_public_ipv4(target_ip)
        except PublicTargetPolicyError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
    result = query_external_exposures(
        scope_id=scope_id, device_id=device_id, target_ip=target_ip,
        port_number=port_number, limit=limit, offset=offset, db_path=DB_PATH,
    )
    return {**result, "count": len(result["items"]), "limit": limit, "offset": offset}


@app.get("/external-exposures/{exposure_id}", dependencies=[Depends(local_management)])
def external_exposure(exposure_id: int):
    exposure = get_external_exposure(exposure_id, db_path=DB_PATH)
    if exposure is None:
        raise HTTPException(status_code=404, detail="External exposure not found.")
    return exposure


@app.get("/external-exposures/{exposure_id}/observations",
         dependencies=[Depends(local_management)])
def external_exposure_observations(
    exposure_id: int,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
):
    if get_external_exposure(exposure_id, db_path=DB_PATH) is None:
        raise HTTPException(status_code=404, detail="External exposure not found.")
    result = list_exposure_observations(
        exposure_id, limit=limit, offset=offset, db_path=DB_PATH
    )
    return {**result, "count": len(result["items"]), "limit": limit, "offset": offset}


@app.get("/network-candidates", dependencies=[Depends(local_management)])
def network_candidates():
    try:
        candidates = discover_local_networks()
    except LocalNetworkDiscoveryError as exc:
        raise HTTPException(
            status_code=503,
            detail="Local network candidates are unavailable.",
        ) from exc

    return [candidate.as_dict() for candidate in candidates]


@app.get("/overview", dependencies=[Depends(local_management)])
def overview():
    return get_overview()


@app.get("/events", dependencies=[Depends(local_management)])
def events(
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    severity: Literal["INFO", "WARNING", "ALERT"] | None = None,
    source_ip: str | None = None,
    time_range: Literal["15m", "1h", "24h", "all"] = "all",
):
    since = resolve_since(time_range)

    result = get_paginated_events(
        limit=limit,
        offset=offset,
        severity=severity,
        source_ip=source_ip,
        since=since,
    )

    return {
        "total": result["total"],
        "count": len(result["items"]),
        "limit": limit,
        "offset": offset,
        "severity": severity,
        "source_ip": source_ip,
        "time_range": time_range,
        "events": result["items"],
    }


@app.get("/source-ips", dependencies=[Depends(local_management)])
def source_ips():
    return {
        "items": get_source_ips(),
    }


@app.get("/alerts", dependencies=[Depends(local_management)])
def alerts(
    limit: int = Query(
        default=20,
        ge=1,
        le=100,
    )
):
    alert_list = get_alerts(
        limit=limit,
    )

    return {
        "count": len(alert_list),
        "alerts": alert_list,
    }


@app.get("/stats/severity", dependencies=[Depends(local_management)])
def severity_stats():
    return {
        "items": get_severity_counts(),
    }


@app.get("/stats/event-types", dependencies=[Depends(local_management)])
def event_type_stats():
    return {
        "items": get_event_type_counts(),
    }


@app.get("/stats/top-ips", dependencies=[Depends(local_management)])
def top_ip_stats(
    limit: int = Query(
        default=10,
        ge=1,
        le=100,
    )
):
    return {
        "items": get_top_source_ips(
            limit=limit,
        ),
    }


@app.get("/stats/timeline", dependencies=[Depends(local_management)])
def timeline_stats(
    limit: int = Query(
        default=30,
        ge=1,
        le=120,
    )
):
    return {
        "items": get_events_over_time(
            limit=limit,
        ),
    }


@app.get("/export/events.json", dependencies=[Depends(local_management)])
def export_events_json(
    severity: Literal["INFO", "WARNING", "ALERT"] | None = None,
    source_ip: str | None = None,
    time_range: Literal["15m", "1h", "24h", "all"] = "all",
):
    since = resolve_since(time_range)

    event_list = get_filtered_events(
        severity=severity,
        source_ip=source_ip,
        since=since,
    )

    return {
        "generated_at": datetime.now().isoformat(
            timespec="seconds"
        ),
        "count": len(event_list),
        "filters": {
            "severity": severity,
            "source_ip": source_ip,
            "time_range": time_range,
        },
        "events": event_list,
    }


@app.get("/export/events.csv", dependencies=[Depends(local_management)])
def export_events_csv(
    severity: Literal["INFO", "WARNING", "ALERT"] | None = None,
    source_ip: str | None = None,
    time_range: Literal["15m", "1h", "24h", "all"] = "all",
):
    since = resolve_since(time_range)

    event_list = get_filtered_events(
        severity=severity,
        source_ip=source_ip,
        since=since,
    )

    output = io.StringIO()

    fieldnames = [
        "id",
        "timestamp",
        "source_ip",
        "username",
        "event_type",
        "severity",
        "message",
        "event_count",
    ]

    writer = csv.DictWriter(
        output,
        fieldnames=fieldnames,
    )

    writer.writeheader()

    for event in event_list:
        writer.writerow(event)

    output.seek(0)

    filename = (
        "sentinelip-events-"
        f"{datetime.now().strftime('%Y%m%d-%H%M%S')}.csv"
    )

    headers = {
        "Content-Disposition": (
            f'attachment; filename="{filename}"'
        )
    }

    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers=headers,
    )


@app.get("/export/report.pdf", dependencies=[Depends(local_management)])
def export_security_report(
    severity: Literal["INFO", "WARNING", "ALERT"] | None = None,
    source_ip: str | None = None,
    time_range: Literal["15m", "1h", "24h", "all"] = "all",
):
    since = resolve_since(time_range)

    event_list = get_filtered_events(
        severity=severity,
        source_ip=source_ip,
        since=since,
    )

    pdf_bytes = build_security_report(
        events=event_list,
        severity=severity,
        source_ip=source_ip,
        time_range=time_range,
    )

    filename = (
        "sentinelip-security-report-"
        f"{datetime.now().strftime('%Y%m%d-%H%M%S')}.pdf"
    )

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": (
                f'attachment; filename="{filename}"'
            )
        },
    )

# ---------------------------------------------------------------------------
# Perimeter evidence read API
# ---------------------------------------------------------------------------

@app.get("/perimeter-events", dependencies=[Depends(local_management)])
def perimeter_events(
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    site_id: int | None = Query(default=None, ge=1),
    sensor_id: int | None = Query(default=None, ge=1),
    source_type: Literal["FIREWALL", "ROUTER", "GATEWAY", "SENSOR", "OTHER"] | None = None,
    direction: Literal["INBOUND", "OUTBOUND", "LATERAL", "UNKNOWN"] | None = None,
    action: Literal["ALLOW", "BLOCK", "REJECT", "UNKNOWN"] | None = None,
    protocol: Literal["TCP", "UDP", "ICMP", "OTHER"] | None = None,
    source_ip: str | None = None,
    destination_ip: str | None = None,
    destination_port: int | None = Query(default=None, ge=1, le=65535),
):
    result = query_perimeter_events(
        limit=limit, offset=offset, site_id=site_id, sensor_id=sensor_id,
        source_type=source_type, direction=direction, action=action, protocol=protocol,
        source_ip=source_ip, destination_ip=destination_ip, destination_port=destination_port,
        db_path=DB_PATH,
    )
    return {
        "total": result["total"],
        "count": len(result["items"]),
        "limit": limit,
        "offset": offset,
        "filters": {
            "site_id": site_id, "sensor_id": sensor_id, "source_type": source_type,
            "direction": direction, "action": action, "protocol": protocol,
            "source_ip": source_ip, "destination_ip": destination_ip,
            "destination_port": destination_port,
        },
        "events": result["items"],
    }


@app.get("/perimeter-events/{event_id}", dependencies=[Depends(local_management)])
def perimeter_event_detail(event_id: int):
    if event_id <= 0:
        raise HTTPException(status_code=422, detail="Perimeter event ID must be positive.")
    item = get_perimeter_event(event_id, db_path=DB_PATH)
    if item is None:
        raise HTTPException(status_code=404, detail="Perimeter event not found.")
    return item


@app.get("/perimeter-detections", dependencies=[Depends(local_management)])
def perimeter_detections(
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    site_id: int | None = Query(default=None, ge=1),
    detection_type: Literal["INBOUND_ATTEMPT", "REPEATED_INBOUND_ATTEMPTS"] | None = None,
    action: Literal["ALLOW", "BLOCK", "REJECT", "UNKNOWN"] | None = None,
    protocol: Literal["TCP", "UDP", "ICMP", "OTHER"] | None = None,
    source_ip: str | None = None,
    destination_ip: str | None = None,
    destination_port: int | None = Query(default=None, ge=1, le=65535),
):
    result = query_perimeter_detections(
        limit=limit, offset=offset, site_id=site_id, detection_type=detection_type,
        action=action, protocol=protocol, source_ip=source_ip, destination_ip=destination_ip,
        destination_port=destination_port, db_path=DB_PATH,
    )
    return {
        "total": result["total"], "count": len(result["items"]), "limit": limit, "offset": offset,
        "filters": {
            "site_id": site_id, "detection_type": detection_type, "action": action, "protocol": protocol,
            "source_ip": source_ip, "destination_ip": destination_ip, "destination_port": destination_port,
        },
        "detections": result["items"],
    }


@app.get("/perimeter-detections/{detection_id}", dependencies=[Depends(local_management)])
def perimeter_detection_detail(detection_id: int):
    if detection_id <= 0:
        raise HTTPException(status_code=422, detail="Perimeter detection ID must be positive.")
    item = get_perimeter_detection(detection_id, db_path=DB_PATH)
    if item is None:
        raise HTTPException(status_code=404, detail="Perimeter detection not found.")
    return item


@app.get("/perimeter-policy-correlations", dependencies=[Depends(local_management)])
def perimeter_policy_correlations(
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    site_id: int | None = Query(default=None, ge=1),
    correlation_type: Literal["BLOCK_THEN_ALLOW", "ALLOW_THEN_BLOCK"] | None = None,
    protocol: Literal["TCP", "UDP", "ICMP", "OTHER"] | None = None,
    source_type: Literal["FIREWALL", "ROUTER", "GATEWAY", "SENSOR", "OTHER"] | None = None,
    source_key: str | None = Query(default=None, min_length=1, max_length=128),
    source_ip: str | None = None,
    destination_ip: str | None = None,
    destination_port: int | None = Query(default=None, ge=1, le=65535),
    primary_action: Literal["ALLOW", "BLOCK", "REJECT"] | None = None,
):
    result = query_perimeter_policy_correlations(
        limit=limit, offset=offset, site_id=site_id, correlation_type=correlation_type,
        protocol=protocol, source_type=source_type, source_key=source_key, source_ip=source_ip, destination_ip=destination_ip,
        destination_port=destination_port, primary_action=primary_action, db_path=DB_PATH,
    )
    return {
        "total": result["total"], "count": len(result["items"]), "limit": limit, "offset": offset,
        "filters": {
            "site_id": site_id, "correlation_type": correlation_type, "protocol": protocol,
            "source_type": source_type, "source_key": source_key, "source_ip": source_ip, "destination_ip": destination_ip,
            "destination_port": destination_port, "primary_action": primary_action,
        },
        "correlations": result["items"],
    }


@app.get("/perimeter-policy-correlations/{correlation_id}",
         dependencies=[Depends(local_management)])
def perimeter_policy_correlation_detail(correlation_id: int):
    if correlation_id <= 0:
        raise HTTPException(status_code=422, detail="Perimeter policy correlation ID must be positive.")
    item = get_perimeter_policy_correlation(correlation_id, db_path=DB_PATH)
    if item is None:
        raise HTTPException(status_code=404, detail="Perimeter policy correlation not found.")
    return item


@app.get("/perimeter-host-correlations", dependencies=[Depends(local_management)])
def perimeter_host_correlations(
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    site_id: int | None = Query(default=None, ge=1),
    device_id: int | None = Query(default=None, ge=1),
    network_id: int | None = Query(default=None, ge=1),
    scope_id: int | None = Query(default=None, ge=1),
    protocol: Literal["TCP", "UDP", "ICMP", "OTHER"] | None = None,
    action: Literal["ALLOW", "BLOCK", "REJECT", "UNKNOWN"] | None = None,
    destination_ip: str | None = None,
    destination_port: int | None = Query(default=None, ge=1, le=65535),
):
    result = query_perimeter_host_correlations(
        limit=limit, offset=offset, site_id=site_id, device_id=device_id, network_id=network_id,
        scope_id=scope_id, protocol=protocol, action=action, destination_ip=destination_ip,
        destination_port=destination_port, db_path=DB_PATH,
    )
    return {
        "total": result["total"], "count": len(result["items"]), "limit": limit, "offset": offset,
        "filters": {
            "site_id": site_id, "device_id": device_id, "network_id": network_id, "scope_id": scope_id,
            "protocol": protocol, "action": action, "destination_ip": destination_ip,
            "destination_port": destination_port,
        },
        "correlations": result["items"],
    }


@app.get("/perimeter-host-correlations/{correlation_id}",
         dependencies=[Depends(local_management)])
def perimeter_host_correlation_detail(correlation_id: int):
    if correlation_id <= 0:
        raise HTTPException(status_code=422, detail="Perimeter host correlation ID must be positive.")
    item = get_perimeter_host_correlation(correlation_id, db_path=DB_PATH)
    if item is None:
        raise HTTPException(status_code=404, detail="Perimeter host correlation not found.")
    return item



@app.get("/perimeter-dashboard", dependencies=[Depends(local_management)])
def perimeter_dashboard(
    site_id: int | None = Query(default=None, ge=1),
    source_type: Literal["FIREWALL", "ROUTER", "GATEWAY", "SENSOR", "OTHER"] | None = None,
    time_range: Literal["1h", "6h", "24h", "72h", "7d", "all"] = "24h",
):
    try:
        return build_perimeter_dashboard(
            site_id=site_id, source_type=source_type, time_range=time_range, db_path=DB_PATH
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Deterministic security read API
# ---------------------------------------------------------------------------

@app.get("/threats", dependencies=[Depends(local_management)])
def threats(
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    threat_type: Literal[
        "SSH_BRUTE_FORCE_THREAT",
        "SUSPICIOUS_AUTH_ACTIVITY",
        "WEB_CREDENTIAL_FLOW_THREAT",
    ] | None = None,
    state: Literal["ANOMALOUS", "SUSPECTED"] | None = None,
    severity: Literal["LOW", "MEDIUM", "HIGH"] | None = None,
    confidence: Literal["LOW", "MEDIUM", "HIGH"] | None = None,
    source_ip: str | None = None,
    device_id: int | None = Query(default=None, ge=1),
    sensor_id: int | None = Query(default=None, ge=1),
):
    result = query_threats(
        limit=limit,
        offset=offset,
        threat_type=threat_type,
        state=state,
        severity=severity,
        confidence=confidence,
        source_ip=source_ip,
        device_id=device_id,
        sensor_id=sensor_id,
        db_path=DB_PATH,
    )

    return {
        "total": result["total"],
        "count": len(result["items"]),
        "limit": limit,
        "offset": offset,
        "filters": {
            "threat_type": threat_type,
            "state": state,
            "severity": severity,
            "confidence": confidence,
            "source_ip": source_ip,
            "device_id": device_id,
            "sensor_id": sensor_id,
        },
        "threats": result["items"],
    }


@app.get("/threats/{threat_id}", dependencies=[Depends(local_management)])
def threat_detail(threat_id: int):
    if threat_id <= 0:
        raise HTTPException(status_code=422, detail="Threat ID must be positive.")

    item = get_threat(threat_id, db_path=DB_PATH)

    if item is None:
        raise HTTPException(status_code=404, detail="Threat not found.")

    return item


@app.get("/correlations", dependencies=[Depends(local_management)])
def correlations(
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    correlation_type: Literal[
        "SSH_AUTH_ACTIVITY_PATTERN",
        "WEB_CREDENTIAL_ACTIVITY_CHAIN",
    ] | None = None,
    state: Literal["RELATED", "PATTERN", "CHAIN_REVIEW"] | None = None,
    severity: Literal["MEDIUM"] | None = None,
    confidence: Literal["MEDIUM", "HIGH"] | None = None,
    source_ip: str | None = None,
    device_id: int | None = Query(default=None, ge=1),
    sensor_id: int | None = Query(default=None, ge=1),
):
    result = query_correlations(
        limit=limit,
        offset=offset,
        correlation_type=correlation_type,
        state=state,
        severity=severity,
        confidence=confidence,
        source_ip=source_ip,
        device_id=device_id,
        sensor_id=sensor_id,
        db_path=DB_PATH,
    )

    return {
        "total": result["total"],
        "count": len(result["items"]),
        "limit": limit,
        "offset": offset,
        "filters": {
            "correlation_type": correlation_type,
            "state": state,
            "severity": severity,
            "confidence": confidence,
            "source_ip": source_ip,
            "device_id": device_id,
            "sensor_id": sensor_id,
        },
        "correlations": result["items"],
    }


@app.get("/correlations/{correlation_id}", dependencies=[Depends(local_management)])
def correlation_detail(correlation_id: int):
    if correlation_id <= 0:
        raise HTTPException(status_code=422, detail="Correlation ID must be positive.")

    item = get_correlation(correlation_id, db_path=DB_PATH)

    if item is None:
        raise HTTPException(status_code=404, detail="Correlation not found.")

    return item


@app.get("/web-detections", dependencies=[Depends(local_management)])
def web_detections(
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0, le=100000),
):
    result = query_web_detections(limit=limit, offset=offset, db_path=DB_PATH)
    return {
        "total": result["total"],
        "count": len(result["items"]),
        "limit": limit,
        "offset": offset,
        "detections": result["items"],
    }


@app.get("/incidents", dependencies=[Depends(local_management)])
def incidents(
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    incident_type: Literal[
        "AUTHENTICATION_REVIEW",
        "WEB_ACTIVITY_REVIEW",
        "MULTI_SIGNAL_REVIEW",
    ] | None = None,
    status: Literal["OPEN"] | None = None,
    priority: Literal["MEDIUM"] | None = None,
):
    result = query_incidents(
        limit=limit,
        offset=offset,
        incident_type=incident_type,
        status=status,
        priority=priority,
        db_path=DB_PATH,
    )

    return {
        "total": result["total"],
        "count": len(result["items"]),
        "limit": limit,
        "offset": offset,
        "filters": {
            "incident_type": incident_type,
            "status": status,
            "priority": priority,
        },
        "incidents": result["items"],
    }


@app.get("/incidents/{incident_id}", dependencies=[Depends(local_management)])
def incident_detail(incident_id: int):
    if incident_id <= 0:
        raise HTTPException(status_code=422, detail="Incident ID must be positive.")

    item = get_incident(incident_id, db_path=DB_PATH)

    if item is None:
        raise HTTPException(status_code=404, detail="Incident not found.")

    return item

# Network Workspace: explicit authorized-network discovery bridge.
# The caller must explicitly request discovery for a stored network.
# Existing target-policy, scanner, and inventory services remain authoritative.

def _workspace_network_or_404(network_id: int):
    network = workspace_networks_db.get_network(network_id, db_path=DB_PATH)
    if network is None:
        raise HTTPException(status_code=404, detail="Network not found.")
    return network


def _workspace_require_network_scope(network: dict):
    scope = get_scope_for_network(network["id"], db_path=DB_PATH)
    require_private_network_scope(network, scope)
    return scope


def _workspace_discover(network: dict):
    scanner = NmapHostDiscoveryScanner()
    scan_result = workspace_discover_hosts(network, scanner)
    return DeviceInventoryService(db_path=DB_PATH).process_scan(
        network,
        scan_result,
    )


@app.get("/networks/{network_id}/devices", dependencies=[Depends(local_management)])
def list_network_devices(network_id: int):
    _workspace_network_or_404(network_id)
    return workspace_inventory_db.list_devices(
        network_id=network_id,
        db_path=DB_PATH,
    )


@app.post("/networks/{network_id}/discover", dependencies=[Depends(local_management)])
def discover_network_devices(network_id: int):
    network = _workspace_network_or_404(network_id)

    try:
        _workspace_require_network_scope(network)
        devices = _workspace_discover(network)
    except ScopeAuthorizationError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except HostDiscoveryError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except ScannerUnavailableError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except ScannerTimeoutError as exc:
        raise HTTPException(status_code=504, detail=str(exc)) from exc
    except (ScannerExecutionError, ScannerParseError) as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    return {
        "network_id": network["id"],
        "cidr": network["cidr"],
        "device_count": len(devices),
        "devices": devices,
    }
# Network Workspace 09B: explicit single-device service discovery.
# The stored device and its stored authorized network remain authoritative.


def _workspace_device_or_404(device_id: int):
    device = workspace_inventory_db.get_device(device_id, db_path=DB_PATH)
    if device is None:
        raise HTTPException(status_code=404, detail="Device not found.")
    return device


def _workspace_discover_services(network: dict, device: dict):
    scanner = NmapServiceDiscoveryScanner()
    result = workspace_discover_services(network, device, scanner)
    return ServiceInventoryService(db_path=DB_PATH).process_result(
        network,
        device,
        result,
    )


@app.get("/devices/{device_id}", dependencies=[Depends(local_management)])
def get_workspace_device(device_id: int):
    return _workspace_device_or_404(device_id)


@app.post("/devices/{device_id}/discover-services", dependencies=[Depends(local_management)])
def discover_device_services(device_id: int):
    device = _workspace_device_or_404(device_id)
    network = _workspace_network_or_404(device["network_id"])

    try:
        _workspace_require_network_scope(network)
        persisted = _workspace_discover_services(network, device)
    except ScopeAuthorizationError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ServiceDiscoveryError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except ScannerUnavailableError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except ScannerTimeoutError as exc:
        raise HTTPException(status_code=504, detail=str(exc)) from exc
    except (ScannerExecutionError, ScannerParseError) as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    return {
        "device_id": device["id"],
        "network_id": network["id"],
        "ip_address": device["last_ip_address"],
        "port_count": len(persisted["ports"]),
        "service_count": len(persisted["services"]),
        "ports": persisted["ports"],
        "services": persisted["services"],
    }


@app.get("/devices/{device_id}/ports", dependencies=[Depends(local_management)])
def list_workspace_device_ports(device_id: int):
    _workspace_device_or_404(device_id)
    return workspace_services_db.list_ports(device_id, db_path=DB_PATH)


@app.get("/devices/{device_id}/services", dependencies=[Depends(local_management)])
def list_workspace_device_services(device_id: int):
    _workspace_device_or_404(device_id)
    return workspace_services_db.list_services(device_id, db_path=DB_PATH)


@app.get("/devices/{device_id}/findings", dependencies=[Depends(local_management)])
def list_workspace_device_findings(device_id: int):
    _workspace_device_or_404(device_id)
    return workspace_findings_db.list_device_findings(
        device_id,
        db_path=DB_PATH,
    )


@app.get("/devices/{device_id}/cve-matches", dependencies=[Depends(local_management)])
def list_workspace_device_cve_matches(device_id: int):
    _workspace_device_or_404(device_id)
    return workspace_cves_db.list_device_cve_matches(
        device_id,
        db_path=DB_PATH,
    )


# This router exposes local management only; no remote execution/ingestion routes.
register_remote_routes(app, lambda: RemoteSensorStore(DB_PATH))
register_machine_routes(app, lambda: RemoteSensorStore(DB_PATH))
register_remote_task_routes(app, lambda: RemoteSensorStore(DB_PATH))
register_investigation_routes(app, lambda: DB_PATH)
register_data_lifecycle_routes(app, lambda: DB_PATH)
register_management_audit_routes(app, lambda: DB_PATH)
register_perimeter_ingestion_routes(app, lambda: RemoteSensorStore(DB_PATH), lambda: DB_PATH)
register_external_exposure_assessment_routes(app, lambda: DB_PATH)
register_external_exposure_classification_routes(app, lambda: DB_PATH)
register_external_exposure_change_routes(app, lambda: DB_PATH)
register_external_exposure_dashboard_routes(app, lambda: DB_PATH)
register_incident_review_routes(app, lambda: DB_PATH)
app.add_middleware(SensorBodyLimitMiddleware)
