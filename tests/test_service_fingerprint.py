import pytest

from services.service_fingerprint import (
    ServiceEvidenceError,
    has_service_evidence,
    normalize_service_evidence,
)


def test_fingerprint_normalizes_supplied_values_only():
    evidence = normalize_service_evidence(
        service_name=" http ",
        product=" nginx ",
        version=" 1.24.0 ",
        extra_info=" TLS ",
        confidence="medium",
    )

    assert evidence.service_name == "http"
    assert evidence.product == "nginx"
    assert evidence.version == "1.24.0"
    assert evidence.extra_info == "TLS"
    assert evidence.confidence == "MEDIUM"
    assert has_service_evidence(evidence) is True


def test_missing_evidence_is_not_guessed_from_port():
    evidence = normalize_service_evidence(
        service_name=None,
        product=None,
        version=None,
        extra_info=None,
        confidence="LOW",
    )

    assert has_service_evidence(evidence) is False


def test_empty_optional_values_become_none():
    evidence = normalize_service_evidence(
        service_name=" ",
        product="",
        version=None,
        extra_info="  ",
        confidence="LOW",
    )

    assert evidence.service_name is None
    assert evidence.product is None
    assert evidence.version is None
    assert evidence.extra_info is None


@pytest.mark.parametrize("confidence", ["", "unknown", None, 1])
def test_confidence_is_explicit_and_validated(confidence):
    with pytest.raises(ServiceEvidenceError):
        normalize_service_evidence(None, None, None, None, confidence)