from database.db import get_connection, initialize_database
from runtime_specialists.registry import SpecialistRegistry
from sentinel_orchestrator.contracts import (
    OrchestratorOperation,
    OrchestratorRequest,
)
from sentinel_orchestrator.orchestrator import SentinelIPOrchestrator
from test_security_read_api import seed_security_pipeline


def test_orchestrator_uses_supplied_specialist_registry(tmp_path):
    path = tmp_path / "orchestrator-registry.db"
    initialize_database(path)

    specialists = SpecialistRegistry(path)
    orchestrator = SentinelIPOrchestrator(
        specialist_registry=specialists
    )

    assert orchestrator.specialists is specialists


def test_orchestrator_reads_do_not_mutate_security_state(tmp_path):
    path = tmp_path / "orchestrator-read-only.db"
    initialize_database(path)
    seed_security_pipeline(path)

    def counts():
        with get_connection(path) as connection:
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

    orchestrator = SentinelIPOrchestrator(db_path=path)
    orchestrator.execute(
        OrchestratorRequest(
            OrchestratorOperation.SECURITY_OVERVIEW,
            {},
        )
    )
    orchestrator.execute(
        OrchestratorRequest(
            OrchestratorOperation.THREAT_LIST,
            {"limit": 1},
        )
    )
    orchestrator.execute(
        OrchestratorRequest(
            OrchestratorOperation.CORRELATION_LIST,
            {"limit": 1},
        )
    )
    orchestrator.execute(
        OrchestratorRequest(
            OrchestratorOperation.INCIDENT_LIST,
            {"limit": 1},
        )
    )

    assert counts() == before
