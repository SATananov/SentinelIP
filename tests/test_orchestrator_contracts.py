import pytest

from sentinel_orchestrator.contracts import (
    OrchestratorOperation,
    OrchestratorRequest,
    OrchestratorResult,
    OrchestratorValidationError,
)


def test_request_copies_arguments():
    arguments = {"limit": 5}
    request = OrchestratorRequest(
        OrchestratorOperation.SECURITY_OVERVIEW,
        arguments,
    )

    arguments["limit"] = 99
    assert request.arguments == {"limit": 5}


def test_request_rejects_untyped_operation():
    with pytest.raises(OrchestratorValidationError):
        OrchestratorRequest(
            "SECURITY_OVERVIEW",
            {},
        )


def test_request_rejects_non_mapping_arguments():
    with pytest.raises(OrchestratorValidationError):
        OrchestratorRequest(
            OrchestratorOperation.THREAT_LIST,
            [],
        )


def test_result_requires_specialist_call_tuple():
    with pytest.raises(OrchestratorValidationError):
        OrchestratorResult(
            operation=OrchestratorOperation.THREAT_LIST,
            data={},
            specialist_calls=["threat_review"],
        )
