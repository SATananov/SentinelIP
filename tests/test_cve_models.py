from datetime import datetime

import pytest

from services.cve_models import (
    CveMatch,
    CveMatchStatus,
    CveModelError,
    CveRecord,
    CveServiceEvidence,
    normalize_cve_id,
    normalize_product,
)


def test_cve_record_and_product_normalization():
    record = CveRecord(
        cve_id=" cve-2099-0001 ",
        source="local-test-feed",
        product=" OpenSSH ",
        affected_version_expression=">=9.0,<9.7",
    )

    assert record.cve_id == "CVE-2099-0001"
    assert record.product == "openssh"


@pytest.mark.parametrize("value", ["CVE-99-1", "not-a-cve", "CVE-2024-x"])
def test_invalid_cve_id_rejected(value):
    with pytest.raises(CveModelError):
        normalize_cve_id(value)


def test_service_evidence_and_match_validate():
    observed_at = datetime(2026, 10, 11, 12, 0, 0)
    evidence = CveServiceEvidence(
        service_id=1,
        device_id=2,
        port_id=3,
        product="OpenSSH",
        version="9.6",
        confidence="HIGH",
        source="nmap",
        observed_at=observed_at,
    )
    match = CveMatch(
        cve_record_id=4,
        cve_id="CVE-2099-0001",
        device_id=2,
        service_id=1,
        port_id=3,
        status="REVIEW",
        confidence="HIGH",
        observed_product=evidence.product,
        observed_version=evidence.version,
        evidence_source=evidence.source,
        evidence_observed_at=observed_at,
        match_reason="Version falls within the supplied range.",
        stable_key="service:1:cve:4:version:9.6",
        first_seen=observed_at,
        last_seen=observed_at,
    )

    assert evidence.product == "openssh"
    assert match.cve_id == "CVE-2099-0001"


def test_model_can_represent_confirmed_but_matcher_controls_emission():
    # The model can represent the future state; the matcher never emits it.
    assert CveMatchStatus.CONFIRMED_ISSUE.value == "CONFIRMED_ISSUE"