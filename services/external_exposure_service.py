from collections.abc import Mapping

from database import external_exposures as exposure_db
from database import scopes as scopes_db
from database.db import DB_PATH
from services.external_exposure_models import ExternalExposureObservation
from services.public_target_policy import normalize_public_ipv4
from services.scope_authorization import (
    ScopeAuthorizationError,
    require_hostname_scope,
    require_public_cidr_scope,
    require_public_ipv4_scope,
)
from services.service_models import ServiceDiscoveryResult


class ExternalExposureError(ValueError):
    """Raised when public service evidence cannot become exposure evidence safely."""


def _authorized_target(scope: Mapping, device: Mapping, db_path):
    if not isinstance(scope, Mapping) or not isinstance(device, Mapping):
        raise ExternalExposureError("Persisted public scope and device records are required.")
    scope_id = scope.get("id")
    if type(scope_id) is not int or scope_id <= 0 or device.get("scope_id") != scope_id:
        raise ExternalExposureError("Device does not belong to the public scope.")
    if device.get("network_id") is not None or type(device.get("id")) is not int or device["id"] <= 0:
        raise ExternalExposureError("External exposure device identity is invalid.")
    try:
        target_ip = normalize_public_ipv4(device.get("last_ip_address"))
        scope_type = scope.get("scope_type")
        if scope_type == "PUBLIC_IPV4":
            if target_ip != require_public_ipv4_scope(scope):
                raise ExternalExposureError("Device target does not match the public IPv4 scope.")
        elif scope_type == "PUBLIC_CIDR":
            require_public_cidr_scope(scope)
            if target_ip not in scopes_db.require_cidr_membership(scope, db_path):
                raise ExternalExposureError("Device target is outside the public CIDR scope.")
        elif scope_type == "HOSTNAME":
            require_hostname_scope(scope)
            if target_ip not in scopes_db.list_hostname_addresses(scope_id, db_path):
                raise ExternalExposureError("Device target is not approved for the hostname scope.")
        else:
            raise ExternalExposureError("Scope type cannot produce external exposure evidence.")
    except (ScopeAuthorizationError, ValueError) as exc:
        if isinstance(exc, ExternalExposureError):
            raise
        raise ExternalExposureError(str(exc)) from exc
    return scope_id, scope_type, target_ip


class ExternalExposureService:
    def __init__(self, db_path=DB_PATH):
        self.db_path = db_path

    def record_service_scan(self, scope: Mapping, device: Mapping, result: ServiceDiscoveryResult):
        if not isinstance(result, ServiceDiscoveryResult) or result.errors:
            raise ExternalExposureError("A successful normalized service scan is required.")
        scope_id, scope_type, target_ip = _authorized_target(scope, device, self.db_path)
        if result.target_ip != target_ip:
            raise ExternalExposureError("Service scan target does not match the authorized public device.")

        services_by_port = {(item.port, item.transport): item for item in result.services}
        records = []
        for port in result.ports:
            if port.ip_address != target_ip or port.state != "open" or port.transport != "tcp":
                raise ExternalExposureError("Exposure evidence must be an open TCP observation for the target.")
            service = services_by_port.get((port.port, port.transport))
            observation = ExternalExposureObservation(
                scope_id=scope_id,
                scope_type=scope_type,
                canonical_target=scope["canonical_target"],
                device_id=device["id"],
                target_ip=target_ip,
                port_number=port.port,
                transport=port.transport,
                observed_at=port.observed_at,
                source=port.source,
                scanner=result.scanner,
                service_name=service.service_name if service else None,
                product=service.product if service else None,
                version=service.version if service else None,
                extra_info=service.extra_info if service else None,
                service_confidence=service.confidence if service else None,
            )
            observation_record = exposure_db.record_observation(observation, self.db_path)
            exposure = observation_record["exposure"]
            from services.external_exposure_assessment import assess_exposure
            from services.external_exposure_classification import classify_exposure
            from services.external_exposure_change_detection import process_observation_change
            assess_exposure(exposure, self.db_path)
            classify_exposure(exposure, self.db_path)
            process_observation_change(observation_record, self.db_path)
            records.append(exposure)

        from services.external_exposure_change_detection import reconcile_completed_scan
        observed_ids = {record["id"] for record in records}
        source = result.ports[0].source if result.ports else "authorized-service-scan"
        reconcile_completed_scan(
            scope_id=scope_id, device_id=device["id"], observed_exposure_ids=observed_ids,
            completed_at=result.completed_at.isoformat(timespec="seconds"),
            source=source, scanner=result.scanner, db_path=self.db_path,
        )
        return records
