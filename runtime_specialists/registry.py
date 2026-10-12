"""Explicit registry for optional SentinelIP runtime specialists."""

from database.db import DB_PATH
from runtime_specialists.contracts import (
    SpecialistRequest,
    SpecialistValidationError,
    UnknownSpecialistError,
)
from runtime_specialists.specialists import (
    SPECIALIST_SPECS,
    ReadOnlySpecialist,
)
from tool_layer.registry import ToolRegistry


class SpecialistRegistry:
    """Dispatch typed requests to a small explicit specialist catalog."""

    def __init__(self, db_path=DB_PATH, tool_registry=None):
        self.tool_registry = (
            tool_registry
            if tool_registry is not None
            else ToolRegistry(db_path=db_path)
        )
        if not isinstance(self.tool_registry, ToolRegistry):
            raise SpecialistValidationError(
                "ToolRegistry is required."
            )

        self._specs = {
            spec.name: spec
            for spec in SPECIALIST_SPECS
        }
        self._specialists = {
            name: ReadOnlySpecialist(
                spec,
                self.tool_registry,
            )
            for name, spec in self._specs.items()
        }

    def catalog(self):
        return tuple(
            self._specs[name]
            for name in sorted(self._specs)
        )

    def execute(self, request: SpecialistRequest):
        if not isinstance(request, SpecialistRequest):
            raise SpecialistValidationError(
                "SpecialistRequest is required."
            )

        specialist = self._specialists.get(
            request.specialist
        )

        if specialist is None:
            raise UnknownSpecialistError(
                "Requested specialist is not registered."
            )

        return specialist.run(request)
