"""Typed contracts for the SentinelIP skill/tool boundary."""

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum


class ToolError(ValueError):
    """Base error for bounded tool-layer failures."""


class ToolValidationError(ToolError):
    """Raised when a tool call does not satisfy its typed contract."""


class ToolPolicyError(ToolError):
    """Raised when a tool is outside the allowed policy."""


class UnknownToolError(ToolError):
    """Raised when a caller asks for a tool that is not registered."""


class ToolAccess(StrEnum):
    READ = "READ"


class ToolCapability(StrEnum):
    SECURITY_STATE = "SECURITY_STATE"


@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    access: ToolAccess
    capability: ToolCapability
    input_fields: tuple[str, ...] = ()

    def __post_init__(self):
        if not isinstance(self.name, str) or not self.name.strip():
            raise ToolValidationError("Tool name must be a non-empty string.")
        if not isinstance(self.description, str) or not self.description.strip():
            raise ToolValidationError("Tool description must be a non-empty string.")
        if len(set(self.input_fields)) != len(self.input_fields):
            raise ToolValidationError("Tool input fields must be unique.")


@dataclass(frozen=True)
class ToolCall:
    name: str
    arguments: Mapping[str, object] = field(default_factory=dict)

    def __post_init__(self):
        if not isinstance(self.name, str) or not self.name.strip():
            raise ToolValidationError("Tool call name must be a non-empty string.")
        if not isinstance(self.arguments, Mapping):
            raise ToolValidationError("Tool arguments must be a mapping.")
        object.__setattr__(self, "arguments", dict(self.arguments))


@dataclass(frozen=True)
class ToolResult:
    tool_name: str
    ok: bool
    data: object | None = None
    error: str | None = None

    def __post_init__(self):
        if not isinstance(self.tool_name, str) or not self.tool_name.strip():
            raise ToolValidationError("Tool result name must be a non-empty string.")
        if type(self.ok) is not bool:
            raise ToolValidationError("Tool result ok flag must be boolean.")
        if self.ok and self.error is not None:
            raise ToolValidationError("Successful tool results cannot contain an error.")
        if not self.ok and not self.error:
            raise ToolValidationError("Failed tool results must contain an error.")
