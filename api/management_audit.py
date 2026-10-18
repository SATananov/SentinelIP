"""Direct-local, read-only management change history API."""

from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response

from api.remote_sensors import local_management
from database.management_audit import EVENT_ENTITY, query_events


def register_management_audit_routes(app: FastAPI, db_path_provider):
    @app.get("/management-audit-events", dependencies=[Depends(local_management)])
    def management_audit_events(
        request: Request,
        response: Response,
        event_type: str | None = Query(default=None),
        entity_type: str | None = Query(default=None),
        entity_id: str | None = Query(default=None, min_length=1, max_length=128),
        site_id: int | None = Query(default=None, gt=0),
        limit: int = Query(default=50, ge=1, le=100),
        offset: int = Query(default=0, ge=0),
    ):
        allowed = {"event_type", "entity_type", "entity_id", "site_id", "limit", "offset"}
        if set(request.query_params.keys()) - allowed:
            raise HTTPException(422, "Unsupported management audit filter.")
        if any(len(request.query_params.getlist(key)) != 1 for key in request.query_params.keys()):
            raise HTTPException(422, "Management audit filters must not be repeated.")
        if event_type is not None and event_type not in EVENT_ENTITY:
            raise HTTPException(422, "Unsupported management audit event type.")
        if entity_type is not None and entity_type not in set(EVENT_ENTITY.values()):
            raise HTTPException(422, "Unsupported management audit entity type.")
        if entity_id is not None and entity_type is None:
            raise HTTPException(422, "Entity type is required with entity ID.")
        try:
            result = query_events(
                event_type=event_type, entity_type=entity_type, entity_id=entity_id,
                site_id=site_id, limit=limit, offset=offset, db_path=db_path_provider(),
            )
        except Exception as exc:
            raise HTTPException(500, "Management audit history is unavailable.") from exc
        response.headers["Cache-Control"] = "no-store"
        return result
