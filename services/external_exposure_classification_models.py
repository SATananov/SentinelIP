from dataclasses import dataclass

SERVICE_ROLES = frozenset({
    "REMOTE_ADMIN", "WEB", "FILE_SHARING", "DATABASE", "MAIL", "DNS", "VPN", "OTHER", "UNKNOWN",
})
EXPOSURE_PROFILES = frozenset({
    "COMMON_PUBLIC_SERVICE", "SENSITIVE_ADMIN_SERVICE", "INTERNAL_STYLE_SERVICE", "UNKNOWN_SERVICE",
})
CLASSIFICATION_RULE_VERSION = "12C-1"


class ExternalExposureClassificationModelError(ValueError):
    """Raised when a service exposure classification is invalid."""


@dataclass(frozen=True)
class ExternalExposureClassificationDecision:
    service_role: str
    exposure_profile: str
    rule_id: str
    reason: str

    def __post_init__(self):
        if self.service_role not in SERVICE_ROLES:
            raise ExternalExposureClassificationModelError("Unsupported service role.")
        if self.exposure_profile not in EXPOSURE_PROFILES:
            raise ExternalExposureClassificationModelError("Unsupported exposure profile.")
        if not self.rule_id or not self.reason:
            raise ExternalExposureClassificationModelError("Classification evidence is required.")
