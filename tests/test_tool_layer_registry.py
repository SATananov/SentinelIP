import pytest

from database.db import initialize_database
from test_security_read_api import seed_security_pipeline
from tool_layer.contracts import (
    ToolAccess,
    ToolCall,
    ToolValidationError,
    UnknownToolError,
)
from tool_layer.registry import ToolRegistry


@pytest.fixture
def registry_db(tmp_path):
    path = tmp_path / "registry.db"
    initialize_database(path)
    return path


def test_registry_catalog_is_small_explicit_and_read_only(registry_db):
    registry = ToolRegistry(registry_db)
    catalog = registry.catalog()

    assert [spec.name for spec in catalog] == [
        "get_correlation",
        "get_incident",
        "get_threat",
        "list_correlations",
        "list_incidents",
        "list_threats",
    ]
    assert all(spec.access is ToolAccess.READ for spec in catalog)


def test_registry_executes_registered_read_tool(registry_db):
    seeded = seed_security_pipeline(registry_db)
    registry = ToolRegistry(registry_db)

    result = registry.execute(
        ToolCall(
            "get_incident",
            {"incident_id": seeded["incident"]["id"]},
        )
    )

    assert result.ok is True
    assert result.tool_name == "get_incident"
    assert result.data["id"] == seeded["incident"]["id"]


def test_registry_rejects_unknown_tool(registry_db):
    registry = ToolRegistry(registry_db)
    with pytest.raises(UnknownToolError):
        registry.execute(ToolCall("shell", {"command": "id"}))


def test_registry_rejects_unexpected_arguments(registry_db):
    registry = ToolRegistry(registry_db)
    with pytest.raises(ToolValidationError):
        registry.execute(
            ToolCall(
                "list_threats",
                {"limit": 5, "command": "anything"},
            )
        )


def test_registry_rejects_missing_required_argument(registry_db):
    registry = ToolRegistry(registry_db)
    with pytest.raises(ToolValidationError):
        registry.execute(ToolCall("get_threat", {}))
