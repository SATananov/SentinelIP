from typing import Literal

from fastapi import Depends, HTTPException, Query

from api.remote_sensors import local_management
from services.external_exposure_dashboard import build_external_exposure_dashboard


DashboardTimeRange = Literal["24h", "72h", "7d", "30d", "all"]


def register_external_exposure_dashboard_routes(app, db_path_provider):
    @app.get("/external-exposure-dashboard", dependencies=[Depends(local_management)])
    def external_exposure_dashboard(
        scope_id: int | None = Query(default=None, ge=1),
        time_range: DashboardTimeRange = "7d",
        recent_limit: int = Query(default=20, ge=1, le=50),
    ):
        try:
            return build_external_exposure_dashboard(
                scope_id=scope_id,
                time_range=time_range,
                recent_limit=recent_limit,
                db_path=db_path_provider(),
            )
        except LookupError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
