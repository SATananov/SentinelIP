import pytest

from database.db import initialize_database
from runtime_specialists.contracts import (
    SpecialistDomain,
    SpecialistIntent,
    SpecialistRequest,
    UnknownSpecialistError,
)
from runtime_specialists.registry import SpecialistRegistry
from tool_layer.registry import ToolRegistry


@pytest.fixture
def runtime_db(tmp_path):
    path = tmp_path / "runtime-registry.db"
    initialize_database(path)
    return path


def test_specialist_catalog_is_small_and_explicit(
    runtime_db,
):
    registry = SpecialistRegistry(runtime_db)
    catalog = registry.catalog()

    assert [spec.name for spec in catalog] == [
        "correlation_review",
        "incident_review",
        "threat_review",
    ]

    assert [spec.domain for spec in catalog] == [
        SpecialistDomain.CORRELATION_REVIEW,
        SpecialistDomain.INCIDENT_REVIEW,
        SpecialistDomain.THREAT_REVIEW,
    ]


def test_registry_uses_supplied_tool_registry(
    runtime_db,
):
    tools = ToolRegistry(runtime_db)
    registry = SpecialistRegistry(
        tool_registry=tools,
    )

    assert registry.tool_registry is tools


def test_registry_rejects_unknown_specialist(
    runtime_db,
):
    registry = SpecialistRegistry(runtime_db)

    with pytest.raises(UnknownSpecialistError):
        registry.execute(
            SpecialistRequest(
                "shell_specialist",
                SpecialistIntent.LIST,
                {},
            )
        )
