"""Static routing plan for SentinelIP orchestration."""

from dataclasses import dataclass

from runtime_specialists.contracts import SpecialistIntent
from sentinel_orchestrator.contracts import (
    OrchestratorOperation,
    OrchestratorValidationError,
)


@dataclass(frozen=True)
class RouteSpec:
    specialist: str
    intent: SpecialistIntent
    allowed_arguments: tuple[str, ...]

    def __post_init__(self):
        if not isinstance(self.specialist, str) or not self.specialist:
            raise OrchestratorValidationError(
                "Route specialist must be a non-empty string."
            )
        if not isinstance(self.intent, SpecialistIntent):
            raise OrchestratorValidationError(
                "Route intent must be a SpecialistIntent."
            )
        if len(set(self.allowed_arguments)) != len(self.allowed_arguments):
            raise OrchestratorValidationError(
                "Route arguments must be unique."
            )


ROUTES = {
    OrchestratorOperation.THREAT_LIST: RouteSpec(
        specialist="threat_review",
        intent=SpecialistIntent.LIST,
        allowed_arguments=("limit", "offset"),
    ),
    OrchestratorOperation.THREAT_DETAIL: RouteSpec(
        specialist="threat_review",
        intent=SpecialistIntent.DETAIL,
        allowed_arguments=("threat_id",),
    ),
    OrchestratorOperation.CORRELATION_LIST: RouteSpec(
        specialist="correlation_review",
        intent=SpecialistIntent.LIST,
        allowed_arguments=("limit", "offset"),
    ),
    OrchestratorOperation.CORRELATION_DETAIL: RouteSpec(
        specialist="correlation_review",
        intent=SpecialistIntent.DETAIL,
        allowed_arguments=("correlation_id",),
    ),
    OrchestratorOperation.INCIDENT_LIST: RouteSpec(
        specialist="incident_review",
        intent=SpecialistIntent.LIST,
        allowed_arguments=("limit", "offset"),
    ),
    OrchestratorOperation.INCIDENT_DETAIL: RouteSpec(
        specialist="incident_review",
        intent=SpecialistIntent.DETAIL,
        allowed_arguments=("incident_id",),
    ),
}


def validate_route_arguments(operation, arguments):
    route = ROUTES[operation]
    actual = set(arguments)
    allowed = set(route.allowed_arguments)

    unexpected = actual - allowed
    if unexpected:
        fields = ", ".join(sorted(unexpected))
        raise OrchestratorValidationError(
            f"Unexpected orchestrator arguments: {fields}."
        )

    if route.intent is SpecialistIntent.DETAIL and actual != allowed:
        field = route.allowed_arguments[0]
        raise OrchestratorValidationError(
            f"{operation.value} requires exactly {field}."
        )

    return route
