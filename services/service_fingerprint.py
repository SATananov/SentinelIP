from dataclasses import dataclass

from services.scan_models import normalize_optional_text


CONFIDENCE_VALUES = frozenset({"LOW", "MEDIUM", "HIGH"})


class ServiceEvidenceError(ValueError):
    """Raised when supplied service evidence is not normalized safely."""


@dataclass(frozen=True)
class NormalizedServiceEvidence:
    service_name: str | None
    product: str | None
    version: str | None
    extra_info: str | None
    confidence: str


def normalize_service_evidence(
    service_name: str | None,
    product: str | None,
    version: str | None,
    extra_info: str | None,
    confidence: str,
) -> NormalizedServiceEvidence:
    if not isinstance(confidence, str):
        raise ServiceEvidenceError("Service confidence is required.")

    normalized_confidence = confidence.strip().upper()

    if normalized_confidence not in CONFIDENCE_VALUES:
        raise ServiceEvidenceError("Service confidence must be LOW, MEDIUM, or HIGH.")

    values = (service_name, product, version, extra_info)

    if any(value is not None and not isinstance(value, str) for value in values):
        raise ServiceEvidenceError("Service evidence values must be strings.")

    return NormalizedServiceEvidence(
        service_name=normalize_optional_text(service_name),
        product=normalize_optional_text(product),
        version=normalize_optional_text(version),
        extra_info=normalize_optional_text(extra_info),
        confidence=normalized_confidence,
    )


def has_service_evidence(evidence: NormalizedServiceEvidence) -> bool:
    return any(
        value is not None
        for value in (
            evidence.service_name,
            evidence.product,
            evidence.version,
            evidence.extra_info,
        )
    )