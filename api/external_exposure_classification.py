from typing import Literal

from fastapi import HTTPException, Query

from database import external_exposure_classifications as classification_db
from services.public_target_policy import PublicTargetPolicyError, normalize_public_ipv4

ServiceRole = Literal["REMOTE_ADMIN", "WEB", "FILE_SHARING", "DATABASE", "MAIL", "DNS", "VPN", "OTHER", "UNKNOWN"]
ExposureProfile = Literal["COMMON_PUBLIC_SERVICE", "SENSITIVE_ADMIN_SERVICE", "INTERNAL_STYLE_SERVICE", "UNKNOWN_SERVICE"]


def register_external_exposure_classification_routes(app, db_path_provider):
    @app.get("/external-exposure-classifications")
    def external_exposure_classifications(
        scope_id: int | None = Query(default=None, ge=1),
        service_role: ServiceRole | None = None,
        exposure_profile: ExposureProfile | None = None,
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
        result = classification_db.query_classifications(
            scope_id=scope_id, service_role=service_role, exposure_profile=exposure_profile,
            target_ip=target_ip, port_number=port_number, limit=limit, offset=offset,
            db_path=db_path_provider(),
        )
        return {**result, "count": len(result["items"]), "limit": limit, "offset": offset}

    @app.get("/external-exposure-classifications/{classification_id}")
    def external_exposure_classification(classification_id: int):
        item = classification_db.get_classification(classification_id, db_path_provider())
        if item is None:
            raise HTTPException(status_code=404, detail="External exposure classification not found.")
        return item
