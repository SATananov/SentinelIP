"""Typed contracts for the optional SentinelIP orchestrator."""

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum


class OrchestratorError(ValueError):
    """Base error for bounded orchestrator failures."""


class OrchestratorValidationError(OrchestratorError):
    """Raised when an orchestrator request is outside its contract."""


class OrchestratorOperation(StrEnum):
    SECURITY_OVERVIEW = "SECURITY_OVERVIEW"
    THREAT_LIST = "THREAT_LIST"
    THREAT_DETAIL = "THREAT_DETAIL"
    CORRELATION_LIST = "CORRELATION_LIST"
    CORRELATION_DETAIL = "CORRELATION_DETAIL"
    INCIDENT_LIST = "INCIDENT_LIST"
    INCIDENT_DETAIL = "INCIDENT_DETAIL"


@dataclass(frozen=True)
class OrchestratorRequest:
    operation: OrchestratorOperation
    arguments: Mapping[str, object] = field(default_factory=dict)

    def __post_init__(self):
        if not isinstance(self.operation, OrchestratorOperation):
            raise OrchestratorValidationError(
                "operation must be an OrchestratorOperation."
            )
        if not isinstance(self.arguments, Mapping):
            raise OrchestratorValidationError(
                "arguments must be a mapping."
            )
        object.__setattr__(self, "arguments", dict(self.arguments))


@dataclass(frozen=True)
class OrchestratorResult:
    operation: OrchestratorOperation
    data: object
    specialist_calls: tuple[str, ...]

    def __post_init__(self):
        if not isinstance(self.operation, OrchestratorOperation):
            raise OrchestratorValidationError(
                "result operation must be an OrchestratorOperation."
            )
        if (
            not isinstance(self.specialist_calls, tuple)
            or not all(
                isinstance(name, str) and name
                for name in self.specialist_calls
            )
        ):
            raise OrchestratorValidationError(
                "specialist_calls must be a tuple of names."
            )
