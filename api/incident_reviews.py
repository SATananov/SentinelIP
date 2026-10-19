"""Explicit analyst incident review APIs over existing evidence records."""
from datetime import datetime, timezone
from typing import Literal

from fastapi import Depends, FastAPI, HTTPException, Query, Response
from pydantic import BaseModel, ConfigDict, Field, StrictInt, StrictStr

from database import incident_reviews as reviews_db
from database import incident_review_reports as reports_db
from api.remote_sensors import local_management
from services import incident_review_report_html as report_html
from services.incident_review_operations import (
    build_incident_review_operations, build_incident_review_activity,
    build_incident_review_trends, build_incident_review_site_workload,
    build_incident_review_scope_workload, build_incident_review_device_workload,
)

EvidenceType = Literal['PERIMETER_DETECTION','PERIMETER_POLICY_CORRELATION',
    'PERIMETER_HOST_CORRELATION','EXTERNAL_EXPOSURE_CHANGE','THREAT_DETECTION',
    'THREAT_CORRELATION','WEB_DETECTION']
State = Literal['OPEN','IN_REVIEW','CLOSED']
InitialState = Literal['OPEN','IN_REVIEW']
Priority = Literal['LOW','MEDIUM','HIGH','CRITICAL']
Confidence = Literal['LOW','MEDIUM','HIGH']
Disposition = Literal['UNREVIEWED','EXPECTED_ACTIVITY','BENIGN','NEEDS_MONITORING',
    'ACTION_REQUIRED','FALSE_POSITIVE','INCONCLUSIVE']
AttentionSignal = Literal['AGING_REVIEW','HIGH_PRIORITY_UNRESOLVED','NO_RECENT_ACTIVITY',
    'REOPENED_REVIEW','MISSING_SOURCE_EVIDENCE','NO_LINKED_EVIDENCE']
ActivityEventType = Literal['REVIEW_CREATED','STATE_CHANGED','REVIEW_CLOSED','REVIEW_REOPENED',
    'PRIORITY_CHANGED','CONFIDENCE_CHANGED','DISPOSITION_CHANGED','REVIEW_FIELD_CHANGED',
    'FINAL_SUMMARY_CHANGED','ANALYST_NOTE_ADDED','ANALYST_NOTE_CLEARED',
    'EVIDENCE_ATTACHED','EVIDENCE_DETACHED']
TrendsWindow = Literal['24h','7d','30d','90d']
MAX_INCIDENT_REVIEW_OFFSET = 100000


class Input(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)


class ReviewCreate(Input):
    title: StrictStr = Field(min_length=1, max_length=160)
    summary: StrictStr = Field(default='', max_length=4000)
    state: InitialState = 'OPEN'
    priority: Priority = 'MEDIUM'
    confidence: Confidence = 'MEDIUM'
    site_id: StrictInt | None = Field(default=None, ge=1)
    scope_id: StrictInt | None = Field(default=None, ge=1)
    device_id: StrictInt | None = Field(default=None, ge=1)
    disposition: Disposition = 'UNREVIEWED'
    analyst_note: StrictStr | None = Field(default=None, max_length=4000)
    final_summary: StrictStr | None = Field(default=None, max_length=4000)


class ReviewUpdate(Input):
    title: StrictStr | None = Field(default=None, min_length=1, max_length=160)
    summary: StrictStr | None = Field(default=None, max_length=4000)
    state: State | None = None
    priority: Priority | None = None
    confidence: Confidence | None = None
    disposition: Disposition | None = None
    analyst_note: StrictStr | None = Field(default=None, max_length=4000)
    final_summary: StrictStr | None = Field(default=None, max_length=4000)
    site_id: StrictInt | None = Field(default=None, ge=1)
    scope_id: StrictInt | None = Field(default=None, ge=1)
    device_id: StrictInt | None = Field(default=None, ge=1)


class EvidenceCreate(Input):
    evidence_type: EvidenceType
    evidence_id: StrictInt = Field(gt=0)
    reason: StrictStr | None = Field(default=None, max_length=500)


class PromotionReviewCreate(Input):
    title: StrictStr = Field(min_length=1, max_length=160)
    summary: StrictStr = Field(default='', max_length=4000)
    priority: Priority = 'MEDIUM'
    confidence: Confidence = 'MEDIUM'
    site_id: StrictInt | None = Field(default=None, ge=1)
    scope_id: StrictInt | None = Field(default=None, ge=1)
    device_id: StrictInt | None = Field(default=None, ge=1)


class InitialEvidence(Input):
    evidence_type: EvidenceType
    evidence_id: StrictInt = Field(gt=0)


class ReviewFromEvidenceCreate(Input):
    review: PromotionReviewCreate
    evidence: InitialEvidence


class NoteCreate(Input):
    note_text: StrictStr = Field(min_length=1, max_length=4000)


def _raise(exc):
    raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc


def register_incident_review_routes(app: FastAPI, db_path_provider):
    @app.get('/incident-review-operations', dependencies=[Depends(local_management)])
    def incident_review_operations(
        state: State | None = None,
        priority: Priority | None = None,
        disposition: Disposition | None = None,
        site_id: int | None = Query(default=None, ge=1),
        scope_id: int | None = Query(default=None, ge=1),
        device_id: int | None = Query(default=None, ge=1),
        has_evidence: bool | None = None,
        age_bucket: str | None = None,
        unresolved_only: bool = False,
        has_attention: bool | None = None,
        attention_signal: AttentionSignal | None = None,
        unattributed_only: bool = False,
        unattributed_scope_only: bool = False,
        unattributed_device_only: bool = False,
        sort: str = 'newest',
        limit: int = Query(default=20, ge=1, le=100),
        offset: int = Query(default=0, ge=0, le=100000),
    ):
        try:
            return build_incident_review_operations(
                state=state, priority=priority, disposition=disposition,
                site_id=site_id, scope_id=scope_id, device_id=device_id,
                has_evidence=has_evidence, age_bucket=age_bucket,
                unresolved_only=unresolved_only, has_attention=has_attention,
                attention_signal=attention_signal, unattributed_only=unattributed_only,
                unattributed_scope_only=unattributed_scope_only,
                unattributed_device_only=unattributed_device_only,
                sort=sort, limit=limit,
                offset=offset, db_path=db_path_provider(),
            )
        except reviews_db.IncidentReviewError as exc:
            _raise(exc)

    @app.get('/incident-review-operations/activity', dependencies=[Depends(local_management)])
    def incident_review_activity(
        event_type: ActivityEventType | None = None,
        incident_review_id: int | None = Query(default=None, ge=1),
        site_id: int | None = Query(default=None, ge=1),
        scope_id: int | None = Query(default=None, ge=1),
        device_id: int | None = Query(default=None, ge=1),
        since: str | None = None,
        until: str | None = None,
        limit: int = Query(default=20, ge=1, le=100),
        offset: int = Query(default=0, ge=0, le=100000),
    ):
        try:
            return build_incident_review_activity(
                event_type=event_type, incident_review_id=incident_review_id,
                site_id=site_id, scope_id=scope_id, device_id=device_id,
                since=since, until=until, limit=limit, offset=offset,
                db_path=db_path_provider(),
            )
        except reviews_db.IncidentReviewError as exc:
            _raise(exc)

    @app.get('/incident-review-operations/trends', dependencies=[Depends(local_management)])
    def incident_review_trends(window: TrendsWindow = '30d'):
        try:
            return build_incident_review_trends(window=window, db_path=db_path_provider())
        except reviews_db.IncidentReviewError as exc:
            _raise(exc)

    @app.get('/incident-review-operations/sites', dependencies=[Depends(local_management)])
    def incident_review_site_workload(
        sort: str = 'unresolved_desc',
        limit: int = Query(default=20, ge=1, le=100),
        offset: int = Query(default=0, ge=0, le=100000),
    ):
        try:
            return build_incident_review_site_workload(
                sort=sort, limit=limit, offset=offset, db_path=db_path_provider(),
            )
        except reviews_db.IncidentReviewError as exc:
            _raise(exc)

    @app.get('/incident-review-operations/scopes', dependencies=[Depends(local_management)])
    def incident_review_scope_workload(
        site_id: int | None = Query(default=None, ge=1),
        unattributed_only: bool = False,
        sort: str = 'unresolved_desc',
        limit: int = Query(default=20, ge=1, le=100),
        offset: int = Query(default=0, ge=0, le=100000),
    ):
        try:
            return build_incident_review_scope_workload(
                site_id=site_id, unattributed_only=unattributed_only, sort=sort,
                limit=limit, offset=offset, db_path=db_path_provider(),
            )
        except reviews_db.IncidentReviewError as exc:
            _raise(exc)

    @app.get('/incident-review-operations/devices', dependencies=[Depends(local_management)])
    def incident_review_device_workload(
        site_id: int | None = Query(default=None, ge=1),
        unattributed_only: bool = False,
        sort: str = 'unresolved_desc',
        limit: int = Query(default=20, ge=1, le=100),
        offset: int = Query(default=0, ge=0, le=100000),
    ):
        try:
            return build_incident_review_device_workload(
                site_id=site_id, unattributed_only=unattributed_only, sort=sort,
                limit=limit, offset=offset, db_path=db_path_provider(),
            )
        except reviews_db.IncidentReviewError as exc:
            _raise(exc)

    @app.get('/incident-reviews', dependencies=[Depends(local_management)])
    def list_incident_reviews(
        state: State | None = None,
        priority: Priority | None = None,
        site_id: int | None = Query(default=None, ge=1),
        scope_id: int | None = Query(default=None, ge=1),
        device_id: int | None = Query(default=None, ge=1),
        disposition: Disposition | None = None,
        limit: int = Query(default=20, ge=1, le=100),
        offset: int = Query(default=0, ge=0, le=MAX_INCIDENT_REVIEW_OFFSET),
    ):
        result = reviews_db.list_reviews(state=state,priority=priority,site_id=site_id,
            scope_id=scope_id,device_id=device_id,disposition=disposition,
            limit=limit,offset=offset,db_path=db_path_provider())
        return {**result,'count':len(result['items']),'limit':limit,'offset':offset}

    @app.get('/incident-reviews/{incident_id}', dependencies=[Depends(local_management)])
    def get_incident_review(incident_id: int):
        if incident_id <= 0:
            raise HTTPException(422,'Incident review ID must be positive.')
        item = reviews_db.get_review(incident_id,db_path_provider())
        if item is None:
            raise HTTPException(404,'Incident review not found.')
        return item

    @app.get('/incident-reviews/{incident_id}/report.json', dependencies=[Depends(local_management)])
    def get_incident_review_report(incident_id: int):
        if incident_id <= 0:
            raise HTTPException(422, detail='Incident review ID must be positive.')
        generated = datetime.now(timezone.utc).replace(microsecond=0)
        generated_at = generated.isoformat(timespec='seconds').replace('+00:00', 'Z')
        try:
            report = reports_db.build_incident_review_report(
                incident_id, generated_at, db_path_provider(),
            )
            content = reports_db.serialize_incident_review_report(report)
        except reports_db.IncidentReviewReportError as exc:
            raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc
        except Exception as exc:
            raise HTTPException(status_code=500, detail='Incident review report is unavailable.') from exc
        filename_time = generated.strftime('%Y%m%dT%H%M%SZ')
        filename = f'sentinelip-incident-review-{incident_id}-{filename_time}.json'
        return Response(
            content=content,
            media_type='application/json',
            headers={
                'Cache-Control': 'no-store',
                'Content-Disposition': f'attachment; filename="{filename}"',
            },
        )

    @app.get('/incident-reviews/{incident_id}/report.html', dependencies=[Depends(local_management)])
    def get_incident_review_report_html(incident_id: int):
        if incident_id <= 0:
            raise HTTPException(status_code=422, detail='Incident review ID must be positive.')
        generated = datetime.now(timezone.utc).replace(microsecond=0)
        generated_at = generated.isoformat(timespec='seconds').replace('+00:00', 'Z')
        try:
            report = reports_db.build_incident_review_report(
                incident_id, generated_at, db_path_provider(),
            )
            content = report_html.render_incident_review_report_html(report)
        except (reports_db.IncidentReviewReportError, report_html.IncidentReviewReportHtmlError) as exc:
            raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc
        except Exception as exc:
            raise HTTPException(status_code=500, detail='Incident review report is unavailable.') from exc
        filename_time = generated.strftime('%Y%m%dT%H%M%SZ')
        filename = f'sentinelip-incident-review-{incident_id}-{filename_time}.html'
        return Response(
            content=content,
            media_type='text/html',
            headers={
                'Cache-Control': 'no-store',
                'Content-Disposition': f'inline; filename="{filename}"',
                'Content-Security-Policy': (
                    "default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; "
                    "font-src 'none'; script-src 'none'; object-src 'none'; base-uri 'none'; "
                    "form-action 'none'; frame-ancestors 'none'"
                ),
                'X-Content-Type-Options': 'nosniff',
                'Referrer-Policy': 'no-referrer',
            },
        )

    @app.post('/incident-reviews',status_code=201, dependencies=[Depends(local_management)])
    def create_incident_review(payload: ReviewCreate):
        try:
            return reviews_db.create_review(**payload.model_dump(),db_path=db_path_provider())
        except reviews_db.IncidentReviewError as exc:
            _raise(exc)

    @app.post('/incident-reviews/from-evidence',status_code=201,
              dependencies=[Depends(local_management)])
    def create_incident_review_from_evidence(payload: ReviewFromEvidenceCreate):
        try:
            return reviews_db.create_review_from_evidence(
                **payload.review.model_dump(), **payload.evidence.model_dump(),
                db_path=db_path_provider())
        except reviews_db.IncidentReviewError as exc:
            _raise(exc)

    @app.patch('/incident-reviews/{incident_id}', dependencies=[Depends(local_management)])
    def update_incident_review(incident_id: int,payload: ReviewUpdate):
        if incident_id <= 0:
            raise HTTPException(422,'Incident review ID must be positive.')
        try:
            return reviews_db.update_review(incident_id,payload.model_dump(exclude_unset=True),db_path_provider())
        except reviews_db.IncidentReviewError as exc:
            _raise(exc)

    @app.get('/incident-reviews/{incident_id}/timeline', dependencies=[Depends(local_management)])
    def get_incident_review_timeline(incident_id: int,
        limit: int = Query(default=100,ge=1,le=100),offset: int = Query(default=0,ge=0,le=100000)):
        try:
            return {**reviews_db.list_timeline(incident_id,limit=limit,offset=offset,
                db_path=db_path_provider()),'limit':limit,'offset':offset}
        except reviews_db.IncidentReviewError as exc:
            _raise(exc)

    @app.get('/incident-reviews/{incident_id}/notes', dependencies=[Depends(local_management)])
    def get_incident_review_notes(incident_id: int,
        limit: int = Query(default=100,ge=1,le=100),offset: int = Query(default=0,ge=0,le=100000)):
        try:
            return {**reviews_db.list_notes(incident_id,limit=limit,offset=offset,
                db_path=db_path_provider()),'limit':limit,'offset':offset}
        except reviews_db.IncidentReviewError as exc:
            _raise(exc)

    @app.post('/incident-reviews/{incident_id}/notes',status_code=201,
              dependencies=[Depends(local_management)])
    def add_incident_review_note(incident_id: int,payload: NoteCreate):
        try:
            return reviews_db.add_note(incident_id,payload.note_text,db_path_provider())
        except reviews_db.IncidentReviewError as exc:
            _raise(exc)

    @app.get('/incident-reviews/{incident_id}/evidence', dependencies=[Depends(local_management)])
    def get_incident_review_evidence(incident_id: int,
        limit: int = Query(default=100,ge=1,le=500),
        offset: int = Query(default=0,ge=0,le=MAX_INCIDENT_REVIEW_OFFSET)):
        try:
            return {**reviews_db.list_evidence(incident_id,limit=limit,offset=offset,db_path=db_path_provider()),
                    'limit':limit,'offset':offset}
        except reviews_db.IncidentReviewError as exc:
            _raise(exc)

    @app.get('/incident-reviews/{incident_id}/related-evidence',
             dependencies=[Depends(local_management)])
    def get_related_incident_review_evidence(incident_id: int,
        limit: int = Query(default=100,ge=1,le=100), evidence_type: EvidenceType | None = None):
        try:
            return {**reviews_db.list_related_evidence(incident_id,limit=limit,
                evidence_type=evidence_type,db_path=db_path_provider()),'limit':limit}
        except reviews_db.IncidentReviewError as exc:
            _raise(exc)

    @app.post('/incident-reviews/{incident_id}/evidence',status_code=201,
              dependencies=[Depends(local_management)])
    def attach_incident_review_evidence(incident_id: int,payload: EvidenceCreate):
        try:
            return reviews_db.add_evidence(incident_id,evidence_type=payload.evidence_type,
                evidence_id=payload.evidence_id,reason=payload.reason,db_path=db_path_provider())
        except reviews_db.IncidentReviewError as exc:
            _raise(exc)

    @app.delete('/incident-reviews/{incident_id}/evidence/{evidence_type}/{evidence_id}',
                dependencies=[Depends(local_management)])
    def detach_incident_review_evidence(incident_id: int,evidence_type: EvidenceType,evidence_id: int):
        try:
            return reviews_db.remove_evidence(incident_id,evidence_type,evidence_id,db_path_provider())
        except reviews_db.IncidentReviewError as exc:
            _raise(exc)
