"""Pure deterministic rules for factual inbound perimeter activity."""
from __future__ import annotations

from datetime import timedelta

from services.perimeter_detection_models import PerimeterDetection, PerimeterDetectionError


WINDOW = timedelta(minutes=5)
REPEATED_THRESHOLD = 5
RULE_VERSION = "1"
ELIGIBLE_EVENT_TYPES = frozenset({"CONNECTION_ATTEMPT", "POLICY_DECISION"})


def evaluate_inbound_attempt(primary: dict, history: tuple[dict, ...]):
    if not isinstance(primary, dict) or not isinstance(history, tuple):
        raise PerimeterDetectionError("Persisted perimeter evidence is required.")
    if primary.get("direction") != "INBOUND" or primary.get("event_type") not in ELIGIBLE_EVENT_TYPES:
        return None

    required = {
        "id", "site_id", "sensor_id", "source_type", "source_key", "source_ip", "destination_ip", "source_port",
        "destination_port", "protocol", "action", "observed_at",
    }
    if not required.issubset(primary):
        raise PerimeterDetectionError("Perimeter evidence is incomplete.")

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
            and row.get("action") == primary["action"]
        )

    matching = tuple(row for row in history if same_flow(row))
    if not matching or primary["id"] not in {row["id"] for row in matching}:
        raise PerimeterDetectionError("Primary perimeter evidence is missing from its history window.")

    matching = tuple(sorted(matching, key=lambda row: (row["observed_at"], row["id"])))
    first = matching[0]["observed_at"]
    last = primary["observed_at"]
    if last - first > WINDOW:
        raise PerimeterDetectionError("Perimeter history exceeds the rule window.")

    repeated = len(matching) >= REPEATED_THRESHOLD
    if repeated:
        detection_type = "REPEATED_INBOUND_ATTEMPTS"
        evidence = matching
        reason = (
            f"{len(matching)} matching inbound perimeter events from {primary['source_ip']} to "
            f"{primary['destination_ip']} were observed within five minutes; policy action was "
            f"{primary['action']}. Review the source and destination service context."
        )
        rule_id = "perimeter.inbound.repeated"
    else:
        detection_type = "INBOUND_ATTEMPT"
        evidence = (primary,)
        reason = (
            f"Inbound perimeter evidence records a {primary['action']} {primary['protocol']} attempt "
            f"from {primary['source_ip']} to {primary['destination_ip']}. Review is recommended; "
            "this record does not by itself establish an attack or compromise."
        )
        rule_id = "perimeter.inbound.attempt"

    return PerimeterDetection(
        detection_type=detection_type,
        site_id=primary["site_id"],
        sensor_id=primary["sensor_id"],
        primary_event_id=primary["id"],
        event_ids=tuple(row["id"] for row in evidence),
        source_ip=primary["source_ip"],
        destination_ip=primary["destination_ip"],
        source_port=primary["source_port"],
        destination_port=primary["destination_port"],
        protocol=primary["protocol"],
        action=primary["action"],
        first_seen=evidence[0]["observed_at"],
        last_seen=primary["observed_at"],
        rule_id=rule_id,
        rule_version=RULE_VERSION,
        reason=reason,
    )
