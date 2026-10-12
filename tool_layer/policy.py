"""Explicit allow-list policy for SentinelIP tools."""

from tool_layer.contracts import ToolAccess, ToolPolicyError, ToolSpec


ALLOWED_TOOL_NAMES = frozenset(
    {
        "list_threats",
        "get_threat",
        "list_correlations",
        "get_correlation",
        "list_incidents",
        "get_incident",
    }
)


class ToolPolicy:
    """Authorize only known read-only tools in this first tool-layer phase."""

    def authorize(self, spec: ToolSpec) -> None:
        if spec.access is not ToolAccess.READ:
            raise ToolPolicyError("Only read-only tools are allowed.")
        if spec.name not in ALLOWED_TOOL_NAMES:
            raise ToolPolicyError("Tool is not present in the explicit allow-list.")
