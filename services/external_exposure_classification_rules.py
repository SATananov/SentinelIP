from services.external_exposure_classification_models import ExternalExposureClassificationDecision

ROLE_BY_PORT = {
    20: "FILE_SHARING", 21: "FILE_SHARING", 22: "REMOTE_ADMIN", 23: "REMOTE_ADMIN",
    25: "MAIL", 53: "DNS", 80: "WEB", 110: "MAIL", 139: "FILE_SHARING", 143: "MAIL",
    443: "WEB", 445: "FILE_SHARING", 465: "MAIL", 500: "VPN", 587: "MAIL",
    993: "MAIL", 995: "MAIL", 1194: "VPN", 1433: "DATABASE", 1521: "DATABASE",
    1701: "VPN", 1723: "VPN", 2049: "FILE_SHARING", 3306: "DATABASE", 3389: "REMOTE_ADMIN",
    4500: "VPN", 5432: "DATABASE", 5900: "REMOTE_ADMIN", 5985: "REMOTE_ADMIN",
    5986: "REMOTE_ADMIN", 6379: "DATABASE", 8080: "WEB", 8443: "WEB", 27017: "DATABASE",
    51820: "VPN",
}

ROLE_BY_SERVICE_NAME = {
    "ssh": "REMOTE_ADMIN", "telnet": "REMOTE_ADMIN", "rdp": "REMOTE_ADMIN", "vnc": "REMOTE_ADMIN",
    "http": "WEB", "https": "WEB", "http-alt": "WEB", "https-alt": "WEB",
    "ftp": "FILE_SHARING", "smb": "FILE_SHARING", "microsoft-ds": "FILE_SHARING", "nfs": "FILE_SHARING",
    "mysql": "DATABASE", "postgresql": "DATABASE", "postgres": "DATABASE", "ms-sql-s": "DATABASE",
    "oracle": "DATABASE", "redis": "DATABASE", "mongodb": "DATABASE",
    "smtp": "MAIL", "submission": "MAIL", "imap": "MAIL", "imaps": "MAIL", "pop3": "MAIL", "pop3s": "MAIL",
    "domain": "DNS", "dns": "DNS", "openvpn": "VPN", "wireguard": "VPN",
}


def classify_role(port_number: int, service_name: str | None):
    role = ROLE_BY_PORT.get(port_number)
    if role is not None:
        return role, "PORT_ROLE_MAP"
    normalized = (service_name or "").strip().lower()
    role = ROLE_BY_SERVICE_NAME.get(normalized)
    if role is not None:
        return role, "SERVICE_NAME_ROLE_MAP"
    if normalized:
        return "OTHER", "KNOWN_UNMAPPED_SERVICE"
    return "UNKNOWN", "NO_SERVICE_IDENTITY"


def classify_exposure_rule(exposure: dict) -> ExternalExposureClassificationDecision:
    role, rule_id = classify_role(exposure["port_number"], exposure.get("service_name"))
    if role == "REMOTE_ADMIN":
        profile = "SENSITIVE_ADMIN_SERVICE"
    elif role in {"DATABASE", "FILE_SHARING"}:
        profile = "INTERNAL_STYLE_SERVICE"
    elif role in {"WEB", "MAIL", "DNS", "VPN"}:
        profile = "COMMON_PUBLIC_SERVICE"
    else:
        profile = "UNKNOWN_SERVICE"
    reason = (
        f"Observed TCP service is deterministically classified as {role} from its port/service identity; "
        f"the exposure profile is {profile}. This is an operational classification, not a vulnerability finding."
    )
    return ExternalExposureClassificationDecision(role, profile, rule_id, reason)
