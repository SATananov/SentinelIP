"""Bounded specialists that can only invoke explicit SentinelIP tools."""

from dataclasses import dataclass

from runtime_specialists.contracts import (
    SpecialistDomain,
    SpecialistIntent,
    SpecialistRequest,
    SpecialistResult,
    SpecialistValidationError,
)
from tool_layer.contracts import ToolCall
from tool_layer.registry import ToolRegistry


@dataclass(frozen=True)
class SpecialistSpec:
    name: str
    domain: SpecialistDomain
    list_tool: str
    detail_tool: str
    detail_id_field: str

    def __post_init__(self):
        values = (
            self.name,
            self.list_tool,
            self.detail_tool,
            self.detail_id_field,
        )
        if any(not isinstance(value, str) or not value.strip() for value in values):
            raise SpecialistValidationError(
                "Specialist specification fields must be non-empty strings."
            )
        if not isinstance(self.domain, SpecialistDomain):
            raise SpecialistValidationError(
                "Specialist specification domain must be a SpecialistDomain."
            )


SPECIALIST_SPECS = (
    SpecialistSpec(
        name="threat_review",
        domain=SpecialistDomain.THREAT_REVIEW,
        list_tool="list_threats",
        detail_tool="get_threat",
        detail_id_field="threat_id",
    ),
    SpecialistSpec(
        name="correlation_review",
        domain=SpecialistDomain.CORRELATION_REVIEW,
        list_tool="list_correlations",
        detail_tool="get_correlation",
        detail_id_field="correlation_id",
    ),
    SpecialistSpec(
        name="incident_review",
        domain=SpecialistDomain.INCIDENT_REVIEW,
        list_tool="list_incidents",
        detail_tool="get_incident",
        detail_id_field="incident_id",
    ),
)


class ReadOnlySpecialist:
    """Translate a typed specialist request into one authorized tool call."""

    def __init__(self, spec: SpecialistSpec, registry: ToolRegistry):
        if not isinstance(spec, SpecialistSpec):
            raise SpecialistValidationError("SpecialistSpec is required.")
        if not isinstance(registry, ToolRegistry):
            raise SpecialistValidationError("ToolRegistry is required.")
        self.spec = spec
        self.registry = registry

    def run(self, request: SpecialistRequest) -> SpecialistResult:
        if not isinstance(request, SpecialistRequest):
            raise SpecialistValidationError("SpecialistRequest is required.")
        if request.specialist != self.spec.name:
            raise SpecialistValidationError(
                "Request specialist does not match this specialist."
            )

        tool_name, arguments = self._tool_call(request)
        tool_result = self.registry.execute(
            ToolCall(tool_name, arguments)
        )

        return SpecialistResult(
            specialist=self.spec.name,
            domain=self.spec.domain,
            intent=request.intent,
            tool_name=tool_result.tool_name,
            data=tool_result.data,
        )

    def _tool_call(self, request: SpecialistRequest):
        if request.intent is SpecialistIntent.LIST:
            allowed = {"limit", "offset"}
            unexpected = set(request.arguments) - allowed
            if unexpected:
                fields = ", ".join(sorted(unexpected))
                raise SpecialistValidationError(
                    f"Unexpected list arguments: {fields}."
                )
            return self.spec.list_tool, dict(request.arguments)

        if request.intent is SpecialistIntent.DETAIL:
            expected = {self.spec.detail_id_field}
            actual = set(request.arguments)
            if actual != expected:
                raise SpecialistValidationError(
                    f"Detail request requires exactly "
                    f"{self.spec.detail_id_field}."
                )
            return self.spec.detail_tool, dict(request.arguments)

        raise SpecialistValidationError("Unsupported specialist intent.")
