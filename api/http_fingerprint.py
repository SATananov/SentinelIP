from typing import Callable, Literal

from fastapi import Depends, FastAPI, HTTPException
from pydantic import BaseModel, ConfigDict

from api.remote_sensors import local_management
from services.hostname_scope_discovery import HostnameReauthorizationRequired
from services.http_endpoint_fingerprint import HttpEndpointError, HttpEndpointFingerprintService


class HttpFingerprintRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    scheme: Literal["http", "https"]


def register_http_fingerprint_routes(app: FastAPI, db_path_provider: Callable):
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
        service = HttpEndpointFingerprintService(db_path_provider())
        try:
            return await service.inspect(
                scope_id, device_id, port_id, scheme=payload.scheme,
            )
        except HttpEndpointError as exc:
            raise HTTPException(exc.status_code, str(exc)) from exc
        except HostnameReauthorizationRequired as exc:
            raise HTTPException(409, str(exc)) from exc
