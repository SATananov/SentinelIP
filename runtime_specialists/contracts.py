"""Typed contracts for optional SentinelIP runtime specialists."""

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum


class SpecialistError(ValueError):
    """Base error for bounded runtime-specialist failures."""


class SpecialistValidationError(SpecialistError):
    """Raised when a specialist request does not satisfy its contract."""


class UnknownSpecialistError(SpecialistError):
    """Raised when a caller requests an unregistered specialist."""


class SpecialistIntent(StrEnum):
    LIST = "LIST"
    DETAIL = "DETAIL"


class SpecialistDomain(StrEnum):
    THREAT_REVIEW = "THREAT_REVIEW"
    CORRELATION_REVIEW = "CORRELATION_REVIEW"
    INCIDENT_REVIEW = "INCIDENT_REVIEW"


@dataclass(frozen=True)
class SpecialistRequest:
    specialist: str
    intent: SpecialistIntent
    arguments: Mapping[str, object] = field(default_factory=dict)

    def __post_init__(self):
        if not isinstance(self.specialist, str) or not self.specialist.strip():
            raise SpecialistValidationError(
                "Specialist name must be a non-empty string."
            )
        if not isinstance(self.intent, SpecialistIntent):
            raise SpecialistValidationError(
                "Specialist intent must be a SpecialistIntent."
            )
        if not isinstance(self.arguments, Mapping):
            raise SpecialistValidationError(
                "Specialist arguments must be a mapping."
            )
        object.__setattr__(self, "arguments", dict(self.arguments))


@dataclass(frozen=True)
class SpecialistResult:
    specialist: str
    domain: SpecialistDomain
    intent: SpecialistIntent
    tool_name: str
    data: object

    def __post_init__(self):
        if not isinstance(self.specialist, str) or not self.specialist.strip():
            raise SpecialistValidationError(
                "Specialist result name must be a non-empty string."
            )
        if not isinstance(self.domain, SpecialistDomain):
            raise SpecialistValidationError(
                "Specialist result domain must be a SpecialistDomain."
            )
        if not isinstance(self.intent, SpecialistIntent):
            raise SpecialistValidationError(
                "Specialist result intent must be a SpecialistIntent."
            )
        if not isinstance(self.tool_name, str) or not self.tool_name.strip():
            raise SpecialistValidationError(
                "Specialist result tool name must be a non-empty string."
            )
