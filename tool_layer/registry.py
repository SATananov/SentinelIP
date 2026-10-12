"""Explicit SentinelIP tool registry with no dynamic imports or shell execution."""

from database.db import DB_PATH
from tool_layer.contracts import (
    ToolAccess,
    ToolCall,
    ToolCapability,
    ToolResult,
    ToolSpec,
    ToolValidationError,
    UnknownToolError,
)
from tool_layer.policy import ToolPolicy
from tool_layer.security_tools import SecurityReadTools


SECURITY_TOOL_SPECS = (
    ToolSpec(
        name="list_threats",
        description="List persisted deterministic threat records.",
        access=ToolAccess.READ,
        capability=ToolCapability.SECURITY_STATE,
        input_fields=("limit", "offset"),
    ),
    ToolSpec(
        name="get_threat",
        description="Read one persisted deterministic threat record.",
        access=ToolAccess.READ,
        capability=ToolCapability.SECURITY_STATE,
        input_fields=("threat_id",),
    ),
    ToolSpec(
        name="list_correlations",
        description="List persisted deterministic correlation records.",
        access=ToolAccess.READ,
        capability=ToolCapability.SECURITY_STATE,
        input_fields=("limit", "offset"),
    ),
    ToolSpec(
        name="get_correlation",
        description="Read one persisted deterministic correlation record.",
        access=ToolAccess.READ,
        capability=ToolCapability.SECURITY_STATE,
        input_fields=("correlation_id",),
    ),
    ToolSpec(
        name="list_incidents",
        description="List persisted incident-review records.",
        access=ToolAccess.READ,
        capability=ToolCapability.SECURITY_STATE,
        input_fields=("limit", "offset"),
    ),
    ToolSpec(
        name="get_incident",
        description="Read one persisted incident-review record.",
        access=ToolAccess.READ,
        capability=ToolCapability.SECURITY_STATE,
        input_fields=("incident_id",),
    ),
)


class ToolRegistry:
    """Bounded dispatcher for explicitly registered SentinelIP tools."""

    def __init__(self, db_path=DB_PATH, policy=None):
        self.policy = policy or ToolPolicy()
        self.security = SecurityReadTools(db_path=db_path)
        self._specs = {spec.name: spec for spec in SECURITY_TOOL_SPECS}
        self._handlers = {
            "list_threats": self.security.list_threats,
            "get_threat": self.security.get_threat,
            "list_correlations": self.security.list_correlations,
            "get_correlation": self.security.get_correlation,
            "list_incidents": self.security.list_incidents,
            "get_incident": self.security.get_incident,
        }

    def catalog(self):
        return tuple(self._specs[name] for name in sorted(self._specs))

    def execute(self, call: ToolCall) -> ToolResult:
        if not isinstance(call, ToolCall):
            raise ToolValidationError("ToolCall is required.")

        spec = self._specs.get(call.name)
        if spec is None:
            raise UnknownToolError("Requested tool is not registered.")

        self.policy.authorize(spec)

        unexpected = set(call.arguments) - set(spec.input_fields)
        if unexpected:
            fields = ", ".join(sorted(unexpected))
            raise ToolValidationError(f"Unexpected tool arguments: {fields}.")

        handler = self._handlers[call.name]

        try:
            data = handler(**call.arguments)
        except TypeError as exc:
            raise ToolValidationError("Tool arguments do not match the contract.") from exc

        return ToolResult(
            tool_name=call.name,
            ok=True,
            data=data,
        )
