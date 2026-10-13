from dataclasses import dataclass


PUBLIC_SCOPE_TYPES = frozenset({"PUBLIC_IPV4", "PUBLIC_CIDR", "HOSTNAME"})
ASSESSMENT_CLASSIFICATIONS = frozenset({"EXPECTED", "UNEXPECTED", "REVIEW"})
ASSESSMENT_RULE_VERSION = "12B-1"
MAX_EXPECTED_TCP_PORTS = 64


class ExternalExposureAssessmentModelError(ValueError):
    """Raised when exposure assessment policy input is not bounded and normalized."""


def normalize_expected_tcp_ports(values) -> tuple[int, ...]:
    if not isinstance(values, (list, tuple)):
        raise ExternalExposureAssessmentModelError("Expected TCP ports must be a list.")
    if len(values) > MAX_EXPECTED_TCP_PORTS:
        raise ExternalExposureAssessmentModelError(
            f"At most {MAX_EXPECTED_TCP_PORTS} expected TCP ports are supported."
        )
    normalized = []
    seen = set()
    for value in values:
        if type(value) is not int or not 1 <= value <= 65535:
            raise ExternalExposureAssessmentModelError(
                "Expected TCP ports must be integers from 1 through 65535."
            )
        if value in seen:
            raise ExternalExposureAssessmentModelError("Expected TCP ports must be unique.")
        seen.add(value)
        normalized.append(value)
    return tuple(sorted(normalized))


@dataclass(frozen=True)
class ExternalExposureAssessmentDecision:
    classification: str
    reason: str
    rule_id: str
    rule_version: str = ASSESSMENT_RULE_VERSION

    def __post_init__(self):
        if self.classification not in ASSESSMENT_CLASSIFICATIONS:
            raise ExternalExposureAssessmentModelError("Invalid exposure assessment classification.")
        if not isinstance(self.reason, str) or not self.reason.strip() or len(self.reason) > 500:
            raise ExternalExposureAssessmentModelError("Exposure assessment reason is invalid.")
        if not isinstance(self.rule_id, str) or not self.rule_id.strip() or len(self.rule_id) > 120:
            raise ExternalExposureAssessmentModelError("Exposure assessment rule ID is invalid.")
