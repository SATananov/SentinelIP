"""Direct-local typed investigation lookup API."""
from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response

from api.remote_sensors import local_management
from database.investigation_lookup import (
    InvestigationLookupError,
    investigation_lookup as lookup,
)


def register_investigation_routes(app: FastAPI, db_path_provider):
    @app.get('/investigation-lookup', dependencies=[Depends(local_management)])
    def investigation_lookup(
        request: Request,
        response: Response,
        query_type: str = Query(...),
        value: str | None = Query(default=None),
        evidence_type: str | None = Query(default=None),
        evidence_id: str | None = Query(default=None),
    ):
        allowed = {'query_type', 'value', 'evidence_type', 'evidence_id'}
        if set(request.query_params.keys()) - allowed:
            raise HTTPException(422, 'Unsupported investigation lookup parameter.')
        if any(len(request.query_params.getlist(key)) != 1 for key in request.query_params.keys()):
            raise HTTPException(422, 'Investigation lookup parameters must not be repeated.')
        try:
            result = lookup(query_type, value=value, evidence_type=evidence_type,
                            evidence_id=evidence_id, db_path=db_path_provider())
        except InvestigationLookupError as exc:
            raise HTTPException(422, str(exc)) from exc
        response.headers['Cache-Control'] = 'no-store'
        return result
