from typing import Literal

from fastapi import Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field, StrictInt

from database import external_exposure_assessments as assessment_db
from api.remote_sensors import local_management
from services.external_exposure_assessment import (
    ExternalExposureAssessmentError,
    configure_scope_policy,
    remove_scope_policy,
)
from services.external_exposure_assessment_models import ExternalExposureAssessmentModelError
from services.public_target_policy import PublicTargetPolicyError, normalize_public_ipv4


class ExposurePolicyInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    expected_tcp_ports: list[StrictInt] = Field(default_factory=list, max_length=64)


def register_external_exposure_assessment_routes(app, db_path_provider):
    @app.get("/scopes/{scope_id}/external-exposure-policy",
             dependencies=[Depends(local_management)])
    def get_external_exposure_policy(scope_id: int):
        policy = assessment_db.get_policy(scope_id, db_path_provider())
        if policy is None:
            raise HTTPException(status_code=404, detail="External exposure policy not found.")
        return policy

    @app.put("/scopes/{scope_id}/external-exposure-policy",
             dependencies=[Depends(local_management)])
    def put_external_exposure_policy(scope_id: int, body: ExposurePolicyInput):
        try:
            return configure_scope_policy(scope_id, body.expected_tcp_ports, db_path_provider(),
                                          actor_type="LOCAL_OPERATOR")
        except (ExternalExposureAssessmentError, ExternalExposureAssessmentModelError) as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @app.delete("/scopes/{scope_id}/external-exposure-policy", status_code=204,
                dependencies=[Depends(local_management)])
    def delete_external_exposure_policy(scope_id: int):
        try:
            removed = remove_scope_policy(scope_id, db_path_provider(), actor_type="LOCAL_OPERATOR")
        except ExternalExposureAssessmentError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        if not removed:
            raise HTTPException(status_code=404, detail="External exposure policy not found.")
        return None

    @app.get("/external-exposure-assessments")
    def external_exposure_assessments(
        scope_id: int | None = Query(default=None, ge=1),
        classification: Literal["EXPECTED", "UNEXPECTED", "REVIEW"] | None = None,
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
        result = assessment_db.query_assessments(
            scope_id=scope_id,
            classification=classification,
            target_ip=target_ip,
            port_number=port_number,
            limit=limit,
            offset=offset,
            db_path=db_path_provider(),
        )
        return {**result, "count": len(result["items"]), "limit": limit, "offset": offset}

    @app.get("/external-exposure-assessments/{assessment_id}")
    def external_exposure_assessment(assessment_id: int):
        assessment = assessment_db.get_assessment(assessment_id, db_path_provider())
        if assessment is None:
            raise HTTPException(status_code=404, detail="External exposure assessment not found.")
        return assessment
