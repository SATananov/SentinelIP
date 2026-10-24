"""Direct-local, read-only lifecycle preview API."""

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict, StrictBool, StrictStr

from api.remote_sensors import local_management
from database.data_lifecycle import cleanup_data_lifecycle, preview_data_lifecycle


class CleanupRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    data_class: StrictStr
    confirmed: StrictBool | None = None


def register_data_lifecycle_routes(app: FastAPI, db_path_provider):
    @app.get("/data-lifecycle/preview", dependencies=[Depends(local_management)])
    def data_lifecycle_preview(request: Request, response: Response):
        if request.query_params:
            raise HTTPException(422, "Lifecycle preview does not accept query parameters.")
        if request.headers.get("content-length") not in (None, "0") or request.headers.get("transfer-encoding"):
            raise HTTPException(422, "Lifecycle preview does not accept a request body.")
        result = preview_data_lifecycle(db_path_provider())
        response.headers["Cache-Control"] = "no-store"
        return result

    @app.post("/data-lifecycle/cleanup", dependencies=[Depends(local_management)])
    def data_lifecycle_cleanup(request: Request, response: Response, body: CleanupRequest):
        if request.query_params:
            raise HTTPException(422, "Lifecycle cleanup does not accept query parameters.")
        if body.data_class not in {
            "DNS_OBSERVATIONS", "WEB_OBSERVATIONS", "LEGACY_EVENTS", "PERIMETER_EVIDENCE",
        }:
            raise HTTPException(422, "Unsupported lifecycle cleanup data class.")
        if body.data_class == "PERIMETER_EVIDENCE" and body.confirmed is not True:
            raise HTTPException(422, "Explicit perimeter evidence cleanup confirmation is required.")
        if body.data_class != "PERIMETER_EVIDENCE" and body.confirmed is not None:
            raise HTTPException(422, "Confirmation is only accepted for perimeter evidence cleanup.")
        try:
            result = cleanup_data_lifecycle(body.data_class, db_path_provider())
        except Exception as exc:
            # Database details are intentionally not returned to the local client.
            raise HTTPException(500, "Lifecycle cleanup failed.") from exc
        response.headers["Cache-Control"] = "no-store"
        return result
