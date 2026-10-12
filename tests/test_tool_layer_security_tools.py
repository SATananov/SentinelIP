import pytest

from database.db import initialize_database
from test_security_read_api import seed_security_pipeline
from tool_layer.contracts import ToolValidationError
from tool_layer.security_tools import SecurityReadTools


@pytest.fixture
def tool_db(tmp_path):
    path = tmp_path / "tool-layer.db"
    initialize_database(path)
    return path


def test_security_tools_list_empty_collections(tool_db):
    tools = SecurityReadTools(tool_db)

    assert tools.list_threats() == {"total": 0, "count": 0, "items": []}
    assert tools.list_correlations() == {"total": 0, "count": 0, "items": []}
    assert tools.list_incidents() == {"total": 0, "count": 0, "items": []}


def test_security_tools_read_seeded_pipeline(tool_db):
    seeded = seed_security_pipeline(tool_db)
    tools = SecurityReadTools(tool_db)

    threats = tools.list_threats(limit=2)
    correlations = tools.list_correlations(limit=1)
    incidents = tools.list_incidents(limit=1)

    assert threats["total"] >= 3
    assert threats["count"] == 2
    assert correlations["total"] == 2
    assert correlations["count"] == 1
    assert incidents["total"] == 1
    assert incidents["count"] == 1

    assert tools.get_threat(seeded["brute"]["id"])["id"] == seeded["brute"]["id"]
    assert tools.get_correlation(seeded["ssh_correlation"]["id"])["id"] == seeded["ssh_correlation"]["id"]
    assert tools.get_incident(seeded["incident"]["id"])["id"] == seeded["incident"]["id"]


def test_security_tools_missing_records_return_none(tool_db):
    tools = SecurityReadTools(tool_db)
    assert tools.get_threat(999999) is None
    assert tools.get_correlation(999999) is None
    assert tools.get_incident(999999) is None


@pytest.mark.parametrize(
    ("method", "arguments"),
    [
        ("list_threats", {"limit": 0}),
        ("list_threats", {"limit": 101}),
        ("list_correlations", {"offset": -1}),
        ("list_incidents", {"limit": True}),
        ("get_threat", {"threat_id": 0}),
        ("get_correlation", {"correlation_id": -1}),
        ("get_incident", {"incident_id": True}),
    ],
)
def test_security_tools_validate_bounded_inputs(tool_db, method, arguments):
    tools = SecurityReadTools(tool_db)
    with pytest.raises(ToolValidationError):
        getattr(tools, method)(**arguments)
