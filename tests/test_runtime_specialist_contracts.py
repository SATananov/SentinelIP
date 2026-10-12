import pytest

from runtime_specialists.contracts import (
    SpecialistDomain,
    SpecialistIntent,
    SpecialistRequest,
    SpecialistResult,
    SpecialistValidationError,
)


def test_specialist_request_copies_arguments():
    arguments = {"limit": 5}
    request = SpecialistRequest(
        "threat_review",
        SpecialistIntent.LIST,
        arguments,
    )
    arguments["limit"] = 99
    assert request.arguments == {"limit": 5}


def test_specialist_request_rejects_invalid_shapes():
    with pytest.raises(SpecialistValidationError):
        SpecialistRequest(
            "",
            SpecialistIntent.LIST,
            {},
        )

    with pytest.raises(SpecialistValidationError):
        SpecialistRequest(
            "threat_review",
            "LIST",
            {},
        )

    with pytest.raises(SpecialistValidationError):
        SpecialistRequest(
            "threat_review",
            SpecialistIntent.LIST,
            [],
        )


def test_specialist_result_is_typed():
    result = SpecialistResult(
        specialist="threat_review",
        domain=SpecialistDomain.THREAT_REVIEW,
        intent=SpecialistIntent.LIST,
        tool_name="list_threats",
        data={"total": 0, "count": 0, "items": []},
    )

    assert result.domain is SpecialistDomain.THREAT_REVIEW
    assert result.tool_name == "list_threats"
