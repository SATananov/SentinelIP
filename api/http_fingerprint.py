from datetime import datetime, timezone
from typing import Callable, Literal

from fastapi import Depends, FastAPI, HTTPException, Path, Query, Request
from pydantic import BaseModel, ConfigDict

from api.remote_sensors import local_management
from services.hostname_scope_discovery import HostnameReauthorizationRequired
from services.http_endpoint_fingerprint import HttpEndpointError, HttpEndpointFingerprintService
from services.http_endpoint_history import (
    HistoryAccessError,
    HistoryCursorError,
    list_http_endpoint_history,
)
from services.http_endpoint_observations import persist_http_endpoint_observation


class HttpFingerprintRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    scheme: Literal["http", "https"]


def register_http_fingerprint_routes(app: FastAPI, db_path_provider: Callable):
    @app.get(
        "/scopes/{scope_id}/devices/{device_id}/ports/{port_id}/http-observations",
        dependencies=[Depends(local_management)],
    )
    def http_endpoint_history(
        request: Request,
        scope_id: int = Path(gt=0),
        device_id: int = Path(gt=0),
        port_id: int = Path(gt=0),
        limit: int = Query(default=20, ge=1, le=100),
        cursor: str | None = Query(default=None, max_length=512),
        scan_run_id: str | None = Query(default=None, min_length=1, max_length=36),
    ):
        allowed = {"limit", "cursor", "scan_run_id"}
        if set(request.query_params.keys()) - allowed:
            raise HTTPException(422, "Unsupported endpoint history filter.")
        if any(len(request.query_params.getlist(key)) != 1 for key in request.query_params.keys()):
            raise HTTPException(422, "Endpoint history filters must not be repeated.")
        try:
            return list_http_endpoint_history(
                scope_id, device_id, port_id, limit=limit, cursor=cursor,
                scan_run_id=scan_run_id, db_path=db_path_provider(),
            )
        except HistoryAccessError as exc:
            raise HTTPException(exc.status_code, str(exc)) from exc
        except HistoryCursorError as exc:
            raise HTTPException(422, str(exc)) from exc

    @app.post(
        "/scopes/{scope_id}/devices/{device_id}/ports/{port_id}/fingerprint-http",
        dependencies=[Depends(local_management)],
    )
    async def fingerprint_http_endpoint(
        scope_id: int,
        device_id: int,
        port_id: int,
        payload: HttpFingerprintRequest,
    ):
        db_path = db_path_provider()
        service = HttpEndpointFingerprintService(db_path)
        started_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
        try:
            result = await service.inspect(
                scope_id, device_id, port_id, scheme=payload.scheme,
            )
        except HttpEndpointError as exc:
            raise HTTPException(exc.status_code, str(exc)) from exc
        except HostnameReauthorizationRequired as exc:
            raise HTTPException(409, str(exc)) from exc
        if result.get("outcome") == "CAPACITY_REJECTED":
            return {**result, "persistence": {"status": "NOT_ATTEMPTED", "reason": "capacity_rejected"}}
        try:
            persisted = persist_http_endpoint_observation(
                result, db_path, started_at=started_at,
                completed_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
            )
        except Exception as exc:
            raise HTTPException(503, {
                "code": "observation_persistence_failed",
                "message": "Inspection completed but its observation could not be stored.",
                "inspection_outcome": result.get("outcome"),
                "persistence_status": "FAILED",
            }) from exc
        return {
            **result,
            "persistence": {
                "status": "PERSISTED",
                "observation_id": persisted["observation_id"],
                "scan_run_id": persisted["scan_run_id"],
                "scan_target_id": persisted["scan_target_id"],
            },
        }
