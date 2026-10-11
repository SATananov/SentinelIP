from datetime import datetime

from services.cve_matcher import CveMatcher, evaluate_version_constraint
from services.cve_models import CveRecord, CveServiceEvidence, CveMatchStatus


OBSERVED_AT = datetime(2026, 10, 11, 12, 0, 0)


def record(expression=">=9.0,<9.7", product="OpenSSH"):
    return CveRecord(
        cve_id="CVE-2099-0001",
        source="local-test-feed",
        product=product,
        affected_version_expression=expression,
    )


def evidence(product="OpenSSH", version="9.6"):
    return CveServiceEvidence(
        service_id=1,
        device_id=2,
        port_id=3,
        product=product,
        version=version,
        confidence="HIGH",
        source="nmap-service-discovery",
        observed_at=OBSERVED_AT,
    )


def test_version_constraints_support_exact_ranges_and_through():
    assert evaluate_version_constraint("1.2.3", "1.2.3").matches is True
    assert evaluate_version_constraint("1.2.4", "1.2.3").matches is False
    assert evaluate_version_constraint("2.4.3", ">=2.0,<2.5").matches is True
    assert evaluate_version_constraint("8.4", "8.0 through 8.4").matches is True
    assert evaluate_version_constraint("8.5", "8.0 through 8.4").matches is False


def test_unsupported_version_is_conservative():
    result = evaluate_version_constraint("9.6p1", ">=9.0,<9.7")

    assert result.supported is False
    assert result.matches is None


def test_strong_match_is_review_high_not_confirmed():
    match = CveMatcher().match(evidence(), record(), 4)

    assert match.status is CveMatchStatus.REVIEW
    assert match.confidence.value == "HIGH"


def test_missing_version_is_possible_low():
    match = CveMatcher().match(evidence(version=None), record(), 4)

    assert match.status is CveMatchStatus.POSSIBLE_MATCH
    assert match.confidence.value == "LOW"


def test_outside_range_is_not_affected():
    match = CveMatcher().match(evidence(version="9.7"), record(), 4)

    assert match.status is CveMatchStatus.NOT_AFFECTED
    assert match.confidence.value == "HIGH"


def test_unrelated_product_and_port_only_evidence_do_not_match():
    assert CveMatcher().match(evidence(product="nginx"), record(), 4) is None
    assert CveMatcher().match(
        CveServiceEvidence(
            service_id=1,
            device_id=2,
            port_id=3,
            product=None,
            version=None,
            confidence="HIGH",
            source="port-only",
            observed_at=OBSERVED_AT,
        ),
        record(),
        4,
    ) is None