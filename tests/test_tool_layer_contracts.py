import pytest

from tool_layer.contracts import (
    ToolAccess,
    ToolCall,
    ToolCapability,
    ToolPolicyError,
    ToolResult,
    ToolSpec,
    ToolValidationError,
)
from tool_layer.policy import ToolPolicy


def test_tool_call_copies_argument_mapping():
    arguments = {"limit": 5}
    call = ToolCall("list_threats", arguments)
    arguments["limit"] = 99
    assert call.arguments == {"limit": 5}


def test_tool_contracts_reject_invalid_shapes():
    with pytest.raises(ToolValidationError):
        ToolCall("", {})
    with pytest.raises(ToolValidationError):
        ToolCall("list_threats", [])
    with pytest.raises(ToolValidationError):
        ToolResult(tool_name="x", ok=False)


def test_policy_accepts_known_read_tool():
    spec = ToolSpec(
        name="list_threats",
        description="Read threats.",
        access=ToolAccess.READ,
        capability=ToolCapability.SECURITY_STATE,
    )
    ToolPolicy().authorize(spec)


def test_policy_rejects_unlisted_tool():
    spec = ToolSpec(
        name="run_command",
        description="Not allowed.",
        access=ToolAccess.READ,
        capability=ToolCapability.SECURITY_STATE,
    )
    with pytest.raises(ToolPolicyError):
        ToolPolicy().authorize(spec)
