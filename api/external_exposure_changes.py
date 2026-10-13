from typing import Literal

from fastapi import HTTPException, Query

from database import external_exposure_changes as change_db
from services.public_target_policy import PublicTargetPolicyError, normalize_public_ipv4


ChangeType = Literal[
    "NEW_EXPOSURE", "SERVICE_CHANGED", "FINGERPRINT_CHANGED",
    "EXPOSURE_DISAPPEARED", "EXPOSURE_REAPPEARED",
]
PresenceState = Literal["PRESENT", "ABSENT"]


def register_external_exposure_change_routes(app, db_path_provider):
    @app.get("/external-exposure-changes")
    def external_exposure_changes(
        scope_id: int | None = Query(default=None, ge=1),
        change_type: ChangeType | None = None,
        target_ip: str | None = None,
        port_number: int | None = Query(default=None, ge=1, le=65535),
        presence_state: PresenceState | None = None,
        limit: int = Query(default=100, ge=1, le=500),
        offset: int = Query(default=0, ge=0),
    ):
        if target_ip is not None:
            try:
                target_ip = normalize_public_ipv4(target_ip)
            except PublicTargetPolicyError as exc:
                raise HTTPException(status_code=422, detail=str(exc)) from exc
        result = change_db.query_changes(
            scope_id=scope_id, change_type=change_type, target_ip=target_ip,
            port_number=port_number, presence_state=presence_state,
            limit=limit, offset=offset, db_path=db_path_provider(),
        )
        return {**result, "count": len(result["items"]), "limit": limit, "offset": offset}

    @app.get("/external-exposure-changes/{change_id}")
    def external_exposure_change(change_id: int):
        item = change_db.get_change(change_id, db_path_provider())
        if item is None:
            raise HTTPException(status_code=404, detail="External exposure change not found.")
        return item
