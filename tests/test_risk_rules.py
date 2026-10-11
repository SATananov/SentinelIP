from datetime import datetime

from services.risk_rules import (
    CacheExposureRule,
    DatabaseExposureRule,
    FtpRule,
    LegacyProtocolRule,
    NewServiceExposureRule,
    RemoteAdminRule,
    RiskContext,
    TelnetRule,
    UnknownServiceRule,
)
from services.finding_models import FindingType


def context(service=None, port=None, change=None):
    return RiskContext(
        device={"id": 1},
        network_id=1,
        port=port,
        service=service,
        change=change,
    )


def test_explicit_telnet_produces_high_plaintext_candidate():
    candidate = TelnetRule().evaluate(
        context(
            service={"id": 5, "service_name": "Telnet", "product": None},
            port={"id": 4},
        )
    )

    assert candidate.finding_type is FindingType.PLAINTEXT_SERVICE
    assert candidate.severity.value == "HIGH"
    assert candidate.confidence.value == "HIGH"


def test_port_number_without_service_does_not_assume_database_or_telnet():
    assert TelnetRule().evaluate(context(port={"id": 4, "port_number": 23})) is None
    assert DatabaseExposureRule().evaluate(context(port={"id": 4, "port_number": 3306})) is None


def test_explicit_ftp_and_legacy_protocols_produce_evidence_findings():
    ftp = FtpRule().evaluate(
        context(service={"id": 5, "service_name": "ftp", "product": None})
    )
    legacy = LegacyProtocolRule().evaluate(
        context(service={"id": 5, "service_name": "rlogin", "product": None})
    )

    assert ftp.finding_type is FindingType.PLAINTEXT_SERVICE
    assert ftp.severity.value == "MEDIUM"
    assert legacy.finding_type is FindingType.LEGACY_PROTOCOL


def test_remote_admin_database_and_cache_rules_require_explicit_evidence():
    remote_admin = RemoteAdminRule().evaluate(
        context(service={"id": 5, "service_name": "rdp", "product": None})
    )
    database = DatabaseExposureRule().evaluate(
        context(service={"id": 5, "service_name": "mysql", "product": None})
    )
    cache = CacheExposureRule().evaluate(
        context(service={"id": 5, "service_name": "redis", "product": None})
    )

    assert remote_admin.finding_type is FindingType.EXPOSED_REMOTE_ADMIN
    assert database.finding_type is FindingType.DATABASE_SERVICE_EXPOSED
    assert cache.finding_type is FindingType.CACHE_SERVICE_EXPOSED


def test_new_service_change_produces_review_candidate():
    candidate = NewServiceExposureRule().evaluate(
        context(
            port={"id": 4},
            change={"id": 7, "change_type": "NEW_PORT"},
        )
    )

    assert candidate.finding_type is FindingType.NEW_SERVICE_EXPOSURE
    assert candidate.severity.value == "LOW"


def test_unknown_open_port_produces_review_candidate():
    candidate = UnknownServiceRule().evaluate(
        context(port={"id": 4, "port_number": 8443})
    )

    assert candidate.finding_type is FindingType.UNKNOWN_SERVICE_REVIEW
    assert candidate.confidence.value == "LOW"