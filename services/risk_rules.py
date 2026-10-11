from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from services.finding_models import (
    FindingConfidence,
    FindingSeverity,
    FindingType,
)


@dataclass(frozen=True)
class RiskContext:
    device: dict
    network_id: int
    port: dict | None = None
    service: dict | None = None
    change: dict | None = None


@dataclass(frozen=True)
class FindingCandidate:
    finding_type: FindingType
    device_id: int
    network_id: int
    severity: FindingSeverity
    confidence: FindingConfidence
    title: str
    reason: str
    recommendation: str
    evidence_type: str
    source: str
    rule_id: str
    rule_version: str
    stable_key: str
    port_id: int | None = None
    service_id: int | None = None
    change_id: int | None = None
    metadata: dict | None = None


@runtime_checkable
class RiskRule(Protocol):
    rule_id: str
    version: str

    def evaluate(self, context: RiskContext) -> FindingCandidate | None:
        """Return an evidence-backed candidate or None."""


def _service_text(context: RiskContext) -> set[str]:
    if context.service is None:
        return set()

    return {
        str(value).strip().casefold()
        for value in (
            context.service.get("service_name"),
            context.service.get("product"),
        )
        if value
    }


def _candidate(
    context: RiskContext,
    finding_type: FindingType,
    severity: FindingSeverity,
    confidence: FindingConfidence,
    title: str,
    reason: str,
    recommendation: str,
    rule_id: str,
    evidence_type: str = "SERVICE_OBSERVATION",
) -> FindingCandidate:
    port_id = context.port.get("id") if context.port else None
    service_id = context.service.get("id") if context.service else None
    change_id = context.change.get("id") if context.change else None
    scope = f"device:{context.device['id']}"

    if port_id is not None:
        scope += f":port:{port_id}"

    return FindingCandidate(
        finding_type=finding_type,
        device_id=context.device["id"],
        network_id=context.network_id,
        severity=severity,
        confidence=confidence,
        title=title,
        reason=reason,
        recommendation=recommendation,
        evidence_type=evidence_type,
        source="risk-engine",
        rule_id=rule_id,
        rule_version="1",
        stable_key=f"{scope}:{rule_id}:1",
        service_id=service_id,
        port_id=port_id,
        change_id=change_id,
    )


@dataclass(frozen=True)
class TelnetRule:
    rule_id: str = "risk.plaintext.telnet"
    version: str = "1"

    def evaluate(self, context: RiskContext):
        if not any("telnet" in value for value in _service_text(context)):
            return None

        return _candidate(
            context,
            FindingType.PLAINTEXT_SERVICE,
            FindingSeverity.HIGH,
            FindingConfidence.HIGH,
            "Plaintext Telnet service",
            "Explicit service evidence identifies Telnet without transport encryption.",
            "Disable Telnet and use SSH where possible.",
            self.rule_id,
        )


@dataclass(frozen=True)
class FtpRule:
    rule_id: str = "risk.plaintext.ftp"
    version: str = "1"

    def evaluate(self, context: RiskContext):
        values = _service_text(context)
        if not any(
            value == "ftp"
            or value.startswith("vsftpd")
            or value.startswith("pure-ftpd")
            for value in values
        ):
            return None

        return _candidate(
            context,
            FindingType.PLAINTEXT_SERVICE,
            FindingSeverity.MEDIUM,
            FindingConfidence.HIGH,
            "Plaintext FTP service",
            "Explicit service evidence identifies FTP without an encrypted transport guarantee.",
            "Use SFTP, SCP, FTPS, or another encrypted alternative as appropriate.",
            self.rule_id,
        )


@dataclass(frozen=True)
class LegacyProtocolRule:
    rule_id: str = "risk.legacy.rlogin"
    version: str = "1"

    def evaluate(self, context: RiskContext):
        values = _service_text(context)
        legacy = next(
            (name for name in ("rlogin", "rsh", "rexec") if any(name in value for value in values)),
            None,
        )
        if legacy is None:
            return None

        return _candidate(
            context,
            FindingType.LEGACY_PROTOCOL,
            FindingSeverity.HIGH,
            FindingConfidence.HIGH,
            "Legacy remote login protocol",
            f"Explicit service evidence identifies the legacy {legacy} protocol.",
            "Disable the legacy protocol and replace it with a supported secure alternative.",
            self.rule_id,
        )


@dataclass(frozen=True)
class RemoteAdminRule:
    rule_id: str = "risk.remote_admin.review"
    version: str = "1"

    def evaluate(self, context: RiskContext):
        values = _service_text(context)
        if not any(
            any(token in value for token in ("rdp", "vnc", "remote desktop"))
            for value in values
        ):
            return None

        return _candidate(
            context,
            FindingType.EXPOSED_REMOTE_ADMIN,
            FindingSeverity.MEDIUM,
            FindingConfidence.HIGH,
            "Remote administration exposure",
            "An explicit remote administration service is exposed on the device.",
            "Review exposure, restrict access, require strong authentication, and segment where appropriate.",
            self.rule_id,
        )


@dataclass(frozen=True)
class DatabaseExposureRule:
    rule_id: str = "risk.database.service"
    version: str = "1"

    def evaluate(self, context: RiskContext):
        values = _service_text(context)
        products = ("mysql", "postgres", "sql server", "oracle")
        if not any(product in value for value in values for product in products):
            return None

        return _candidate(
            context,
            FindingType.DATABASE_SERVICE_EXPOSED,
            FindingSeverity.MEDIUM,
            FindingConfidence.HIGH,
            "Database service exposure",
            "An explicit database service is reachable on the device.",
            "Review network exposure and database access controls.",
            self.rule_id,
        )


@dataclass(frozen=True)
class CacheExposureRule:
    rule_id: str = "risk.cache.service"
    version: str = "1"

    def evaluate(self, context: RiskContext):
        values = _service_text(context)
        if not any("redis" in value or "memcached" in value for value in values):
            return None

        return _candidate(
            context,
            FindingType.CACHE_SERVICE_EXPOSED,
            FindingSeverity.MEDIUM,
            FindingConfidence.HIGH,
            "Cache or datastore service exposure",
            "An explicit Redis or Memcached service is reachable on the device.",
            "Review network binding, authentication, and segmentation.",
            self.rule_id,
        )


@dataclass(frozen=True)
class WebAdminRule:
    rule_id: str = "risk.web_admin.review"
    version: str = "1"

    def evaluate(self, context: RiskContext):
        values = _service_text(context)
        if not any(
            any(token in value for token in ("webmin", "admin panel", "tomcat manager"))
            for value in values
        ):
            return None

        return _candidate(
            context,
            FindingType.WEB_ADMIN_REVIEW,
            FindingSeverity.MEDIUM,
            FindingConfidence.HIGH,
            "Web administration interface",
            "Explicit service evidence identifies a web administration interface.",
            "Review exposure and restrict administrative access where appropriate.",
            self.rule_id,
        )


@dataclass(frozen=True)
class NewServiceExposureRule:
    rule_id: str = "risk.change.new_service"
    version: str = "1"

    def evaluate(self, context: RiskContext):
        if context.change is None or context.change.get("change_type") not in {
            "NEW_PORT",
            "SERVICE_IDENTIFIED",
            "SERVICE_CHANGED",
        }:
            return None

        severity = FindingSeverity.LOW
        if any(
            candidate.evaluate(context) is not None
            for candidate in (
                TelnetRule(),
                FtpRule(),
                LegacyProtocolRule(),
                RemoteAdminRule(),
                DatabaseExposureRule(),
                CacheExposureRule(),
            )
        ):
            severity = FindingSeverity.MEDIUM

        return _candidate(
            context,
            FindingType.NEW_SERVICE_EXPOSURE,
            severity,
            FindingConfidence.HIGH if context.service else FindingConfidence.LOW,
            "New service exposure",
            "A new port or explicit service exposure was observed and should be reviewed.",
            "Confirm that the service is expected and appropriately restricted.",
            self.rule_id,
            evidence_type="PORT_OBSERVATION" if context.service is None else "SERVICE_OBSERVATION",
        )


@dataclass(frozen=True)
class UnknownServiceRule:
    rule_id: str = "risk.unknown_service"
    version: str = "1"

    def evaluate(self, context: RiskContext):
        if context.port is None or context.service is not None:
            return None

        return _candidate(
            context,
            FindingType.UNKNOWN_SERVICE_REVIEW,
            FindingSeverity.LOW,
            FindingConfidence.LOW,
            "Unknown service review",
            "An open TCP port was observed without service-identification evidence.",
            "Identify the service and confirm whether it is expected.",
            self.rule_id,
            evidence_type="PORT_OBSERVATION",
        )


DEFAULT_RULES = (
    TelnetRule(),
    FtpRule(),
    LegacyProtocolRule(),
    RemoteAdminRule(),
    DatabaseExposureRule(),
    CacheExposureRule(),
    WebAdminRule(),
    NewServiceExposureRule(),
    UnknownServiceRule(),
)