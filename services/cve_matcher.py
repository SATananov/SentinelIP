import re
from dataclasses import dataclass
from datetime import datetime

from services.cve_models import (
    CveMatch,
    CveMatchConfidence,
    CveMatchStatus,
    CveRecord,
    CveServiceEvidence,
    compare_numeric_versions,
    normalize_product,
    parse_numeric_version,
)


MATCHER_ID = "cve.product_version.v1"
COMPARISON_PATTERN = re.compile(r"^(<=|>=|<|>)(\d+(?:\.\d+)*)$")


class CveMatcherError(ValueError):
    """Raised when CVE matching input cannot be evaluated safely."""


@dataclass(frozen=True)
class VersionConstraintResult:
    supported: bool
    matches: bool | None


def _compare_constraint(version: str, operator: str, bound: str) -> bool | None:
    comparison = compare_numeric_versions(version, bound)
    if comparison is None:
        return None

    return {
        "<": comparison < 0,
        "<=": comparison <= 0,
        ">": comparison > 0,
        ">=": comparison >= 0,
    }[operator]


def evaluate_version_constraint(
    version: str,
    expression: str,
) -> VersionConstraintResult:
    if parse_numeric_version(version) is None:
        return VersionConstraintResult(supported=False, matches=None)

    normalized_expression = expression.strip()
    through_match = re.fullmatch(
        r"(\d+(?:\.\d+)*)\s+through\s+(\d+(?:\.\d+)*)",
        normalized_expression,
        flags=re.IGNORECASE,
    )

    if through_match is not None:
        lower = _compare_constraint(version, ">=", through_match.group(1))
        upper = _compare_constraint(version, "<=", through_match.group(2))
        if lower is None or upper is None:
            return VersionConstraintResult(False, None)
        return VersionConstraintResult(True, lower and upper)

    if "," in normalized_expression:
        constraints = [part.strip() for part in normalized_expression.split(",")]
    else:
        constraints = [normalized_expression]

    results = []
    for constraint in constraints:
        comparison_match = COMPARISON_PATTERN.fullmatch(constraint)
        if comparison_match is not None:
            result = _compare_constraint(
                version,
                comparison_match.group(1),
                comparison_match.group(2),
            )
        elif parse_numeric_version(constraint) is not None:
            result = compare_numeric_versions(version, constraint) == 0
        else:
            return VersionConstraintResult(False, None)

        if result is None:
            return VersionConstraintResult(False, None)
        results.append(result)

    return VersionConstraintResult(True, all(results))


class CveMatcher:
    def match(
        self,
        evidence: CveServiceEvidence,
        record: CveRecord,
        cve_record_id: int,
    ) -> CveMatch | None:
        if evidence.product is None:
            return None

        if normalize_product(evidence.product) != record.product:
            return None

        now = evidence.observed_at
        stable_version = evidence.version or "missing"
        stable_key = (
            f"service:{evidence.service_id}:cve:{cve_record_id}"
            f":product:{record.product}:version:{stable_version}"
        )
        evidence_confidence = evidence.confidence.strip().upper()

        if evidence.version is None:
            status = CveMatchStatus.POSSIBLE_MATCH
            confidence = CveMatchConfidence.LOW
            reason = "Product evidence matches, but the observed version is missing."
        else:
            comparison = evaluate_version_constraint(
                evidence.version,
                record.affected_version_expression,
            )
            if not comparison.supported:
                status = CveMatchStatus.POSSIBLE_MATCH
                confidence = CveMatchConfidence.LOW
                reason = "Product matched, but the version could not be compared safely."
            elif comparison.matches is False:
                status = CveMatchStatus.NOT_AFFECTED
                confidence = CveMatchConfidence.HIGH
                reason = "Observed version is outside the supplied affected-version constraint."
            else:
                status = CveMatchStatus.REVIEW
                confidence = (
                    CveMatchConfidence.HIGH
                    if evidence_confidence == "HIGH"
                    else CveMatchConfidence.MEDIUM
                )
                reason = "Observed product and version fall within the supplied affected-version constraint."

        return CveMatch(
            cve_record_id=cve_record_id,
            cve_id=record.cve_id,
            device_id=evidence.device_id,
            service_id=evidence.service_id,
            port_id=evidence.port_id,
            status=status,
            confidence=confidence,
            observed_product=evidence.product,
            observed_version=evidence.version,
            evidence_source=evidence.source,
            evidence_observed_at=now,
            match_reason=reason,
            stable_key=stable_key,
            first_seen=now,
            last_seen=now,
            metadata={"matcher_id": MATCHER_ID, "matcher_version": "1"},
        )