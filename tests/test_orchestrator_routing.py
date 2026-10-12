import pytest

from database.db import initialize_database
from sentinel_orchestrator.contracts import (
    OrchestratorOperation,
    OrchestratorRequest,
    OrchestratorValidationError,
)
from sentinel_orchestrator.orchestrator import SentinelIPOrchestrator
from test_security_read_api import seed_security_pipeline


@pytest.fixture
def orchestrator_db(tmp_path):
    path = tmp_path / "orchestrator.db"
    initialize_database(path)
    return path


def test_overview_coordinates_three_specialists(
    orchestrator_db,
):
    seed_security_pipeline(orchestrator_db)
    orchestrator = SentinelIPOrchestrator(
        db_path=orchestrator_db
    )

    result = orchestrator.execute(
        OrchestratorRequest(
            OrchestratorOperation.SECURITY_OVERVIEW,
            {"limit": 2},
        )
    )

    assert result.specialist_calls == (
        "threat_review",
        "correlation_review",
        "incident_review",
    )
    assert result.data["threats"]["count"] == 2
    assert result.data["correlations"]["count"] == 2
    assert result.data["incidents"]["count"] == 1


@pytest.mark.parametrize(
    ("operation", "id_field", "seed_key"),
    [
        (
            OrchestratorOperation.THREAT_DETAIL,
            "threat_id",
            "brute",
        ),
        (
            OrchestratorOperation.CORRELATION_DETAIL,
            "correlation_id",
            "ssh_correlation",
        ),
        (
            OrchestratorOperation.INCIDENT_DETAIL,
            "incident_id",
            "incident",
        ),
    ],
)
def test_detail_routes_to_expected_specialist(
    orchestrator_db,
    operation,
    id_field,
    seed_key,
):
    seeded = seed_security_pipeline(orchestrator_db)
    orchestrator = SentinelIPOrchestrator(
        db_path=orchestrator_db
    )
    record_id = seeded[seed_key]["id"]

    result = orchestrator.execute(
        OrchestratorRequest(
            operation,
            {id_field: record_id},
        )
    )

    assert result.data["id"] == record_id
    assert len(result.specialist_calls) == 1


@pytest.mark.parametrize(
    ("operation", "arguments"),
    [
        (
            OrchestratorOperation.THREAT_LIST,
            {"command": "id"},
        ),
        (
            OrchestratorOperation.CORRELATION_DETAIL,
            {},
        ),
        (
            OrchestratorOperation.INCIDENT_DETAIL,
            {"incident_id": 1, "extra": True},
        ),
        (
            OrchestratorOperation.SECURITY_OVERVIEW,
            {"source_ip": "192.168.1.10"},
        ),
    ],
)
def test_orchestrator_rejects_out_of_contract_arguments(
    orchestrator_db,
    operation,
    arguments,
):
    orchestrator = SentinelIPOrchestrator(
        db_path=orchestrator_db
    )

    with pytest.raises(OrchestratorValidationError):
        orchestrator.execute(
            OrchestratorRequest(
                operation,
                arguments,
            )
        )
