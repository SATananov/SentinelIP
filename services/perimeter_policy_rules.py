"""Pure deterministic rules for allowed-vs-blocked perimeter correlations."""
from __future__ import annotations

from datetime import timedelta

from services.perimeter_policy_models import PerimeterPolicyCorrelation, PerimeterPolicyCorrelationError


WINDOW = timedelta(minutes=5)
RULE_VERSION = "1"
ELIGIBLE_EVENT_TYPES = frozenset({"CONNECTION_ATTEMPT", "POLICY_DECISION"})
BLOCKED_ACTIONS = frozenset({"BLOCK", "REJECT"})


def evaluate_policy_transition(primary: dict, history: tuple[dict, ...]):
    if not isinstance(primary, dict) or not isinstance(history, tuple):
        raise PerimeterPolicyCorrelationError("Persisted perimeter evidence is required.")
    if primary.get("direction") != "INBOUND" or primary.get("event_type") not in ELIGIBLE_EVENT_TYPES:
        return None
    if primary.get("action") not in {"ALLOW", *BLOCKED_ACTIONS}:
        return None

    required = {
        "id", "site_id", "sensor_id", "source_type", "source_key", "source_ip", "destination_ip",
        "destination_port", "protocol", "action", "observed_at",
    }
    if not required.issubset(primary):
        raise PerimeterPolicyCorrelationError("Perimeter evidence is incomplete.")

    def same_flow(row):
        return (
            row.get("direction") == "INBOUND"
            and row.get("event_type") in ELIGIBLE_EVENT_TYPES
            and row.get("site_id") == primary["site_id"]
            and row.get("source_type") == primary["source_type"]
            and row.get("source_key") == primary["source_key"]
            and row.get("source_ip") == primary["source_ip"]
            and row.get("destination_ip") == primary["destination_ip"]
            and row.get("destination_port") == primary["destination_port"]
            and row.get("protocol") == primary["protocol"]
            and row.get("action") in {"ALLOW", *BLOCKED_ACTIONS}
        )

    matching = tuple(sorted((row for row in history if same_flow(row)), key=lambda row: (row["observed_at"], row["id"])))
    if not matching or primary["id"] not in {row["id"] for row in matching}:
        raise PerimeterPolicyCorrelationError("Primary perimeter evidence is missing from its history window.")

    first = matching[0]["observed_at"]
    if primary["observed_at"] - first > WINDOW:
        raise PerimeterPolicyCorrelationError("Perimeter correlation history exceeds the rule window.")

    allowed = tuple(row for row in matching if row["action"] == "ALLOW")
    blocked = tuple(row for row in matching if row["action"] in BLOCKED_ACTIONS)
    if not allowed or not blocked:
        return None

    if primary["action"] == "ALLOW":
        prior_blocked = tuple(row for row in blocked if (row["observed_at"], row["id"]) < (primary["observed_at"], primary["id"]))
        if not prior_blocked:
            return None
        correlation_type = "BLOCK_THEN_ALLOW"
        rule_id = "perimeter.policy.block-then-allow"
        reason = (
            f"Inbound perimeter evidence for {primary['source_ip']} to {primary['destination_ip']} changed from "
            f"BLOCK/REJECT to ALLOW within five minutes. Review the firewall policy and destination service context; "
            "this correlation does not establish intrusion or compromise."
        )
    else:
        prior_allowed = tuple(row for row in allowed if (row["observed_at"], row["id"]) < (primary["observed_at"], primary["id"]))
        if not prior_allowed:
            return None
        correlation_type = "ALLOW_THEN_BLOCK"
        rule_id = "perimeter.policy.allow-then-block"
        reason = (
            f"Inbound perimeter evidence for {primary['source_ip']} to {primary['destination_ip']} changed from "
            f"ALLOW to BLOCK/REJECT within five minutes. Review the firewall policy and destination service context; "
            "this correlation does not establish intrusion or compromise."
        )

    evidence = tuple(
        row for row in matching
        if (row["observed_at"], row["id"]) <= (primary["observed_at"], primary["id"])
    )
    return PerimeterPolicyCorrelation(
        correlation_type=correlation_type,
        site_id=primary["site_id"],
        sensor_id=primary["sensor_id"],
        primary_event_id=primary["id"],
        event_ids=tuple(row["id"] for row in evidence),
        allowed_event_ids=tuple(row["id"] for row in evidence if row["action"] == "ALLOW"),
        blocked_event_ids=tuple(row["id"] for row in evidence if row["action"] in BLOCKED_ACTIONS),
        source_type=primary["source_type"],
        source_key=primary["source_key"],
        source_ip=primary["source_ip"],
        destination_ip=primary["destination_ip"],
        destination_port=primary["destination_port"],
        protocol=primary["protocol"],
        primary_action=primary["action"],
        first_seen=evidence[0]["observed_at"],
        last_seen=primary["observed_at"],
        rule_id=rule_id,
        rule_version=RULE_VERSION,
        reason=reason,
    )
