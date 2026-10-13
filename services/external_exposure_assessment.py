from datetime import datetime, timezone

from database import external_exposure_assessments as assessment_db
from database import external_exposures as exposure_db
from database import scopes as scopes_db
from database.db import DB_PATH
from services.external_exposure_assessment_models import (
    ASSESSMENT_RULE_VERSION,
    ExternalExposureAssessmentDecision,
    normalize_expected_tcp_ports,
)
from services.scope_authorization import (
    ScopeAuthorizationError,
    require_hostname_scope,
    require_public_cidr_scope,
    require_public_ipv4_scope,
)


class ExternalExposureAssessmentError(ValueError):
    """Raised when exposure assessment policy or evidence is not valid."""


def _now():
    return datetime.now(timezone.utc).replace(tzinfo=None).isoformat(timespec="seconds")


def _require_assessable_scope(scope):
    if not isinstance(scope, dict) or type(scope.get("id")) is not int:
        raise ExternalExposureAssessmentError("Persisted authorized scope is required.")
    if scope.get("authorized") is not True or scope.get("enabled") is not True:
        raise ExternalExposureAssessmentError("Exposure assessment requires an enabled authorized scope.")
    try:
        scope_type = scope.get("scope_type")
        if scope_type == "PUBLIC_IPV4":
            require_public_ipv4_scope(scope)
        elif scope_type == "PUBLIC_CIDR":
            require_public_cidr_scope(scope)
        elif scope_type == "HOSTNAME":
            require_hostname_scope(scope)
        else:
            raise ExternalExposureAssessmentError("Only public scopes support exposure assessment.")
    except ScopeAuthorizationError as exc:
        raise ExternalExposureAssessmentError(str(exc)) from exc
    return scope


def configure_scope_policy(scope_id: int, expected_tcp_ports, db_path=DB_PATH):
    scope = scopes_db.get_scope(scope_id, db_path)
    _require_assessable_scope(scope)
    ports = normalize_expected_tcp_ports(expected_tcp_ports)
    policy = assessment_db.upsert_policy(scope_id, ports, db_path)
    reassess_scope(scope_id, db_path)
    return policy


def remove_scope_policy(scope_id: int, db_path=DB_PATH):
    scope = scopes_db.get_scope(scope_id, db_path)
    _require_assessable_scope(scope)
    removed = assessment_db.delete_policy(scope_id, db_path)
    reassess_scope(scope_id, db_path)
    return removed


def _decision(exposure, policy):
    if policy is None:
        return ExternalExposureAssessmentDecision(
            classification="REVIEW",
            rule_id="NO_EXPLICIT_EXPOSURE_POLICY",
            reason="No explicit expected-port policy exists for this authorized public scope.",
        )
    expected = set(policy["expected_tcp_ports"])
    if exposure["port_number"] in expected:
        return ExternalExposureAssessmentDecision(
            classification="EXPECTED",
            rule_id="PORT_DECLARED_EXPECTED",
            reason="The exposed TCP port is explicitly declared expected for this authorized public scope.",
        )
    return ExternalExposureAssessmentDecision(
        classification="UNEXPECTED",
        rule_id="PORT_NOT_DECLARED_EXPECTED",
        reason="The exposed TCP port is not in the explicit expected-port allowlist for this authorized public scope.",
    )


def assess_exposure(exposure, db_path=DB_PATH):
    if not isinstance(exposure, dict) or type(exposure.get("id")) is not int:
        raise ExternalExposureAssessmentError("Persisted external exposure is required.")
    scope = scopes_db.get_scope(exposure["scope_id"], db_path)
    _require_assessable_scope(scope)
    if exposure.get("scope_type") != scope.get("scope_type"):
        raise ExternalExposureAssessmentError("Exposure scope identity is inconsistent.")
    policy = assessment_db.get_policy(scope["id"], db_path)
    decision = _decision(exposure, policy)
    return assessment_db.upsert_assessment(
        exposure_id=exposure["id"],
        scope_id=scope["id"],
        policy_id=policy["id"] if policy else None,
        classification=decision.classification,
        reason=decision.reason,
        rule_id=decision.rule_id,
        rule_version=ASSESSMENT_RULE_VERSION,
        assessed_at=_now(),
        db_path=db_path,
    )


def reassess_scope(scope_id: int, db_path=DB_PATH):
    scope = scopes_db.get_scope(scope_id, db_path)
    _require_assessable_scope(scope)
    result = exposure_db.query_external_exposures(scope_id=scope_id, limit=500, offset=0, db_path=db_path)
    if result["total"] > 500:
        raise ExternalExposureAssessmentError("Scope has too many exposures for bounded synchronous reassessment.")
    return [assess_exposure(exposure, db_path) for exposure in result["items"]]
