"""Explicit analyst incident review APIs over existing evidence records."""
from typing import Literal

from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field, StrictInt, StrictStr

from database import incident_reviews as reviews_db

EvidenceType = Literal['PERIMETER_DETECTION','PERIMETER_POLICY_CORRELATION',
    'PERIMETER_HOST_CORRELATION','EXTERNAL_EXPOSURE_CHANGE','THREAT_DETECTION',
    'THREAT_CORRELATION','WEB_DETECTION']
State = Literal['OPEN','IN_REVIEW','CLOSED']
Priority = Literal['LOW','MEDIUM','HIGH','CRITICAL']
Confidence = Literal['LOW','MEDIUM','HIGH']
Disposition = Literal['UNREVIEWED','EXPECTED_ACTIVITY','BENIGN','NEEDS_MONITORING',
    'ACTION_REQUIRED','FALSE_POSITIVE','INCONCLUSIVE']


class Input(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)


class ReviewCreate(Input):
    title: StrictStr = Field(min_length=1, max_length=160)
    summary: StrictStr = Field(default='', max_length=4000)
    state: State = 'OPEN'
    priority: Priority = 'MEDIUM'
    confidence: Confidence = 'MEDIUM'
    site_id: StrictInt | None = Field(default=None, ge=1)
    scope_id: StrictInt | None = Field(default=None, ge=1)
    device_id: StrictInt | None = Field(default=None, ge=1)
    disposition: Disposition = 'UNREVIEWED'
    analyst_note: StrictStr | None = Field(default=None, max_length=4000)


class ReviewUpdate(Input):
    title: StrictStr | None = Field(default=None, min_length=1, max_length=160)
    summary: StrictStr | None = Field(default=None, max_length=4000)
    state: State | None = None
    priority: Priority | None = None
    confidence: Confidence | None = None
    disposition: Disposition | None = None
    analyst_note: StrictStr | None = Field(default=None, max_length=4000)
    site_id: StrictInt | None = Field(default=None, ge=1)
    scope_id: StrictInt | None = Field(default=None, ge=1)
    device_id: StrictInt | None = Field(default=None, ge=1)


class EvidenceCreate(Input):
    evidence_type: EvidenceType
    evidence_id: StrictInt = Field(gt=0)
    reason: StrictStr | None = Field(default=None, max_length=500)


def _raise(exc):
    raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc


def register_incident_review_routes(app: FastAPI, db_path_provider):
    @app.get('/incident-reviews')
    def list_incident_reviews(
        state: State | None = None,
        priority: Priority | None = None,
        site_id: int | None = Query(default=None, ge=1),
        scope_id: int | None = Query(default=None, ge=1),
        device_id: int | None = Query(default=None, ge=1),
        disposition: Disposition | None = None,
        limit: int = Query(default=20, ge=1, le=100),
        offset: int = Query(default=0, ge=0),
    ):
        result = reviews_db.list_reviews(state=state,priority=priority,site_id=site_id,
            scope_id=scope_id,device_id=device_id,disposition=disposition,
            limit=limit,offset=offset,db_path=db_path_provider())
        return {**result,'count':len(result['items']),'limit':limit,'offset':offset}

    @app.get('/incident-reviews/{incident_id}')
    def get_incident_review(incident_id: int):
        if incident_id <= 0:
            raise HTTPException(422,'Incident review ID must be positive.')
        item = reviews_db.get_review(incident_id,db_path_provider())
        if item is None:
            raise HTTPException(404,'Incident review not found.')
        return item

    @app.post('/incident-reviews',status_code=201)
    def create_incident_review(payload: ReviewCreate):
        try:
            return reviews_db.create_review(**payload.model_dump(),db_path=db_path_provider())
        except reviews_db.IncidentReviewError as exc:
            _raise(exc)

    @app.patch('/incident-reviews/{incident_id}')
    def update_incident_review(incident_id: int,payload: ReviewUpdate):
        if incident_id <= 0:
            raise HTTPException(422,'Incident review ID must be positive.')
        try:
            return reviews_db.update_review(incident_id,payload.model_dump(exclude_unset=True),db_path_provider())
        except reviews_db.IncidentReviewError as exc:
            _raise(exc)

    @app.get('/incident-reviews/{incident_id}/evidence')
    def get_incident_review_evidence(incident_id: int,
        limit: int = Query(default=100,ge=1,le=500),offset: int = Query(default=0,ge=0)):
        try:
            return {**reviews_db.list_evidence(incident_id,limit=limit,offset=offset,db_path=db_path_provider()),
                    'limit':limit,'offset':offset}
        except reviews_db.IncidentReviewError as exc:
            _raise(exc)

    @app.post('/incident-reviews/{incident_id}/evidence',status_code=201)
    def attach_incident_review_evidence(incident_id: int,payload: EvidenceCreate):
        try:
            return reviews_db.add_evidence(incident_id,evidence_type=payload.evidence_type,
                evidence_id=payload.evidence_id,reason=payload.reason,db_path=db_path_provider())
        except reviews_db.IncidentReviewError as exc:
            _raise(exc)

    @app.delete('/incident-reviews/{incident_id}/evidence/{evidence_type}/{evidence_id}')
    def detach_incident_review_evidence(incident_id: int,evidence_type: EvidenceType,evidence_id: int):
        try:
            return reviews_db.remove_evidence(incident_id,evidence_type,evidence_id,db_path_provider())
        except reviews_db.IncidentReviewError as exc:
            _raise(exc)
