import pytest

from database.db import initialize_database
from runtime_specialists.contracts import (
    SpecialistIntent,
    SpecialistRequest,
    SpecialistValidationError,
)
from runtime_specialists.registry import SpecialistRegistry
from test_security_read_api import seed_security_pipeline


@pytest.fixture
def specialist_db(tmp_path):
    path = tmp_path / "runtime-specialists.db"
    initialize_database(path)
    return path


def test_threat_specialist_lists_through_tool_layer(
    specialist_db,
):
    seed_security_pipeline(specialist_db)
    registry = SpecialistRegistry(specialist_db)

    result = registry.execute(
        SpecialistRequest(
            "threat_review",
            SpecialistIntent.LIST,
            {"limit": 2, "offset": 0},
        )
    )

    assert result.tool_name == "list_threats"
    assert result.data["count"] == 2


def test_correlation_specialist_reads_detail(
    specialist_db,
):
    seeded = seed_security_pipeline(specialist_db)
    registry = SpecialistRegistry(specialist_db)

    result = registry.execute(
        SpecialistRequest(
            "correlation_review",
            SpecialistIntent.DETAIL,
            {
                "correlation_id": (
                    seeded["ssh_correlation"]["id"]
                )
            },
        )
    )

    assert result.tool_name == "get_correlation"
    assert (
        result.data["id"]
        == seeded["ssh_correlation"]["id"]
    )


def test_incident_specialist_reads_detail(
    specialist_db,
):
    seeded = seed_security_pipeline(specialist_db)
    registry = SpecialistRegistry(specialist_db)

    result = registry.execute(
        SpecialistRequest(
            "incident_review",
            SpecialistIntent.DETAIL,
            {
                "incident_id": seeded["incident"]["id"]
            },
        )
    )

    assert result.tool_name == "get_incident"
    assert result.data["id"] == seeded["incident"]["id"]


@pytest.mark.parametrize(
    ("specialist", "arguments"),
    [
        (
            "threat_review",
            {"command": "id"},
        ),
        (
            "correlation_review",
            {"limit": 5, "source_ip": "192.168.1.5"},
        ),
        (
            "incident_review",
            {"incident_id": 1, "extra": True},
        ),
    ],
)
def test_specialists_reject_out_of_contract_arguments(
    specialist_db,
    specialist,
    arguments,
):
    registry = SpecialistRegistry(specialist_db)
    intent = (
        SpecialistIntent.DETAIL
        if "incident_id" in arguments
        else SpecialistIntent.LIST
    )

    with pytest.raises(SpecialistValidationError):
        registry.execute(
            SpecialistRequest(
                specialist,
                intent,
                arguments,
            )
        )


def test_specialists_do_not_create_security_records(
    specialist_db,
):
    seed_security_pipeline(specialist_db)
    registry = SpecialistRegistry(specialist_db)

    from database.db import get_connection

    def counts():
        with get_connection(specialist_db) as connection:
            return tuple(
                connection.execute(
                    f"SELECT COUNT(*) FROM {table}"
                ).fetchone()[0]
                for table in (
                    "threat_detections",
                    "correlations",
                    "incidents",
                )
            )

    before = counts()

    registry.execute(
        SpecialistRequest(
            "threat_review",
            SpecialistIntent.LIST,
            {},
        )
    )
    registry.execute(
        SpecialistRequest(
            "correlation_review",
            SpecialistIntent.LIST,
            {},
        )
    )
    registry.execute(
        SpecialistRequest(
            "incident_review",
            SpecialistIntent.LIST,
            {},
        )
    )

    assert counts() == before
