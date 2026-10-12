"""Deterministic coordinator over the bounded specialist registry."""

from runtime_specialists.contracts import (
    SpecialistIntent,
    SpecialistRequest,
)
from runtime_specialists.registry import SpecialistRegistry
from sentinel_orchestrator.contracts import (
    OrchestratorOperation,
    OrchestratorRequest,
    OrchestratorResult,
    OrchestratorValidationError,
)
from sentinel_orchestrator.planning import (
    ROUTES,
    validate_route_arguments,
)


class SentinelIPOrchestrator:
    """Coordinate only explicitly defined read-only specialist routes."""

    def __init__(self, specialist_registry=None, db_path=None):
        if specialist_registry is None:
            if db_path is None:
                self.specialists = SpecialistRegistry()
            else:
                self.specialists = SpecialistRegistry(db_path=db_path)
        else:
            self.specialists = specialist_registry

        if not isinstance(self.specialists, SpecialistRegistry):
            raise OrchestratorValidationError(
                "SpecialistRegistry is required."
            )

    def execute(self, request: OrchestratorRequest) -> OrchestratorResult:
        if not isinstance(request, OrchestratorRequest):
            raise OrchestratorValidationError(
                "OrchestratorRequest is required."
            )

        if request.operation is OrchestratorOperation.SECURITY_OVERVIEW:
            return self._security_overview(request.arguments)

        if request.operation not in ROUTES:
            raise OrchestratorValidationError(
                "Unsupported orchestrator operation."
            )

        route = validate_route_arguments(
            request.operation,
            request.arguments,
        )
        result = self.specialists.execute(
            SpecialistRequest(
                specialist=route.specialist,
                intent=route.intent,
                arguments=request.arguments,
            )
        )

        return OrchestratorResult(
            operation=request.operation,
            data=result.data,
            specialist_calls=(route.specialist,),
        )

    def _security_overview(self, arguments):
        allowed = {"limit", "offset"}
        unexpected = set(arguments) - allowed
        if unexpected:
            fields = ", ".join(sorted(unexpected))
            raise OrchestratorValidationError(
                f"Unexpected overview arguments: {fields}."
            )

        limit = arguments.get("limit", 5)
        offset = arguments.get("offset", 0)
        specialist_arguments = {
            "limit": limit,
            "offset": offset,
        }

        plan = (
            ("threats", "threat_review"),
            ("correlations", "correlation_review"),
            ("incidents", "incident_review"),
        )

        data = {}
        calls = []

        for key, specialist_name in plan:
            result = self.specialists.execute(
                SpecialistRequest(
                    specialist=specialist_name,
                    intent=SpecialistIntent.LIST,
                    arguments=specialist_arguments,
                )
            )
            data[key] = result.data
            calls.append(specialist_name)

        return OrchestratorResult(
            operation=OrchestratorOperation.SECURITY_OVERVIEW,
            data=data,
            specialist_calls=tuple(calls),
        )
