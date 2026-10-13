from database import external_exposure_classifications as classification_db
from database.db import DB_PATH
from services.external_exposure_classification_models import CLASSIFICATION_RULE_VERSION
from services.external_exposure_classification_rules import classify_exposure_rule


class ExternalExposureClassificationError(ValueError):
    """Raised when persisted exposure evidence cannot be classified safely."""


def classify_exposure(exposure: dict, db_path=DB_PATH):
    if not isinstance(exposure, dict) or type(exposure.get("id")) is not int or exposure["id"] <= 0:
        raise ExternalExposureClassificationError("Persisted external exposure is required.")
    if exposure.get("scope_type") not in {"PUBLIC_IPV4", "PUBLIC_CIDR", "HOSTNAME"}:
        raise ExternalExposureClassificationError("Only authorized public exposure evidence is classifiable.")
    if exposure.get("transport") != "tcp":
        raise ExternalExposureClassificationError("Only normalized TCP exposure evidence is classifiable.")
    decision = classify_exposure_rule(exposure)
    return classification_db.upsert_classification(
        exposure_id=exposure["id"], scope_id=exposure["scope_id"],
        service_role=decision.service_role, exposure_profile=decision.exposure_profile,
        rule_id=decision.rule_id, rule_version=CLASSIFICATION_RULE_VERSION,
        reason=decision.reason, db_path=db_path,
    )
