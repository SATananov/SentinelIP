"""Direct-local, read-only lifecycle preview API."""

from fastapi import Depends, FastAPI, HTTPException, Request, Response

from api.remote_sensors import local_management
from database.data_lifecycle import preview_data_lifecycle


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
