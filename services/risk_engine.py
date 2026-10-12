from datetime import datetime

from database import changes as changes_db
from database import findings as findings_db
from database import services as services_db
from database.db import DB_PATH
from services.finding_models import FindingRecord, FindingStatus
from services.risk_rules import DEFAULT_RULES, FindingCandidate, RiskContext, RiskRule


class RiskEngineError(ValueError):
    """Raised when deterministic risk evaluation context is invalid."""


class RiskEngine:
    def __init__(self, db_path=DB_PATH, rules: tuple[RiskRule, ...] = DEFAULT_RULES):
        self.db_path = db_path
        self.rules = rules

    def evaluate_device(self, device: dict, network_id: int) -> list[dict]:
        return self._evaluate_device(device, network_id, None)

    def evaluate_scope_device(self, device: dict, scope_id: int) -> list[dict]:
        if type(scope_id) is not int or scope_id <= 0:
            raise RiskEngineError("Scope ID must be positive.")
        if not isinstance(device, dict):
            raise RiskEngineError("A persisted device is required.")
        if device.get("network_id") is not None or device.get("scope_id") != scope_id:
            raise RiskEngineError("Device does not belong to the public scope.")
        return self._evaluate_device(device, None, scope_id)

    def _evaluate_device(
        self, device: dict, network_id: int | None, scope_id: int | None
    ) -> list[dict]:
        if not isinstance(device, dict) or type(device.get("id")) is not int:
            raise RiskEngineError("A persisted device is required.")

        ports = services_db.list_ports(device["id"], self.db_path)
        services = services_db.list_services(device["id"], self.db_path)
        service_by_port = {service["port_id"]: service for service in services}
        changes = changes_db.list_device_changes(device["id"], self.db_path)
        candidates = []

        for port in ports:
            context = RiskContext(
                device=device,
                network_id=network_id,
                scope_id=scope_id,
                port=port,
                service=service_by_port.get(port["id"]),
                change=None,
            )
            candidates.extend(self._evaluate_context(context))

        for change in changes:
            if change["change_type"] not in {
                "NEW_PORT",
                "SERVICE_IDENTIFIED",
                "SERVICE_CHANGED",
            }:
                continue

            port = next(
                (item for item in ports if item["id"] == change["port_id"]),
                None,
            )
            service = service_by_port.get(change["port_id"])
            context = RiskContext(
                device=device,
                network_id=network_id,
                scope_id=scope_id,
                port=port,
                service=service,
                change=change,
            )
            candidates.extend(self._evaluate_context(context))

        unique = {}
        for candidate in candidates:
            unique[candidate.stable_key] = candidate

        return [self._upsert(candidate) for candidate in unique.values()]

    def _evaluate_context(self, context: RiskContext) -> list[FindingCandidate]:
        candidates = []
        for rule in self.rules:
            candidate = rule.evaluate(context)
            if candidate is not None:
                candidates.append(candidate)
        return candidates

    def _upsert(self, candidate: FindingCandidate) -> dict:
        now = datetime.now()
        existing = findings_db.get_finding_by_stable_key(
            candidate.stable_key,
            self.db_path,
        )

        if existing is not None:
            return findings_db.touch_finding(existing["id"], now, self.db_path)

        finding = FindingRecord(
            finding_type=candidate.finding_type,
            device_id=candidate.device_id,
            network_id=candidate.network_id,
            scope_id=candidate.scope_id,
            port_id=candidate.port_id,
            service_id=candidate.service_id,
            change_id=candidate.change_id,
            severity=candidate.severity,
            confidence=candidate.confidence,
            status=FindingStatus.OPEN,
            title=candidate.title,
            reason=candidate.reason,
            recommendation=candidate.recommendation,
            evidence_type=candidate.evidence_type,
            source=candidate.source,
            rule_id=candidate.rule_id,
            rule_version=candidate.rule_version,
            stable_key=candidate.stable_key,
            first_seen=now,
            last_seen=now,
            metadata=candidate.metadata,
        )
        return findings_db.create_finding(finding, self.db_path)
