"""Pure relationship rules; never create incident or consequence verdicts."""
from datetime import timedelta
from services.correlation_models import Correlation, EntityType

SSH_WINDOW = timedelta(minutes=5)
WEB_WINDOW = timedelta(minutes=5)
RULE_VERSION = "1"


def _within(a, b, window):
    if (a.utcoffset() is None) != (b.utcoffset() is None):
        return False
    return abs(a - b) <= window


def correlate_ssh(left, right, evaluated_at):
    if (left.entity_type != EntityType.THREAT or right.entity_type != EntityType.THREAT
            or {left.signal_type, right.signal_type} != {"SUSPICIOUS_AUTH_ACTIVITY", "SSH_BRUTE_FORCE_THREAT"}
            or not left.source_ip or left.source_ip != right.source_ip
            or (left.device_id, left.sensor_id) != (right.device_id, right.sensor_id)
            or not _within(left.entity_timestamp, right.entity_timestamp, SSH_WINDOW)):
        return None
    brute = left if left.signal_type == "SSH_BRUTE_FORCE_THREAT" else right
    if brute.confidence != "HIGH":
        return None
    return Correlation(
        correlation_type="SSH_AUTH_ACTIVITY_PATTERN", state="PATTERN", severity="MEDIUM", confidence="HIGH",
        primary_entity_type="THREAT", primary_entity_id=brute.entity_id, entities=(left, right),
        reason="Two persisted SSH threat signals share an observed network source within five minutes; their authentication evidence forms a reviewable pattern, not an actor or access conclusion.",
        rule_id="correlation.ssh_auth_activity", rule_version=RULE_VERSION,
        first_seen=evaluated_at, last_seen=evaluated_at,
    )


def correlate_web(threat, linked_web, evaluated_at):
    # linked_web must be loaded through persisted threat_evidence links, never proximity search.
    if (threat.entity_type != EntityType.THREAT or threat.signal_type != "WEB_CREDENTIAL_FLOW_THREAT"
            or threat.web_context is None):
        return None
    eligible = tuple(e for e in linked_web if e.entity_type == EntityType.WEB_DETECTION
                     and e.web_context == threat.web_context
                     and _within(e.entity_timestamp, threat.entity_timestamp, WEB_WINDOW))
    anchor = next((e for e in eligible if e.entity_id == threat.source_evidence_id
                   and e.signal_type == "CROSS_DOMAIN_LOGIN_REDIRECT"
                   and e.primary_observation_id == threat.primary_observation_id), None)
    if anchor is None:
        return None
    downloads = tuple(e for e in eligible if e.signal_type == "SUSPICIOUS_DOWNLOAD_FLOW"
                      and threat.primary_observation_id in e.observation_ids
                      and e.entity_timestamp >= anchor.entity_timestamp)
    return Correlation(
        correlation_type="WEB_CREDENTIAL_ACTIVITY_CHAIN", state="CHAIN_REVIEW", severity="MEDIUM", confidence="MEDIUM",
        primary_entity_type="THREAT", primary_entity_id=threat.entity_id, entities=(threat, anchor, *downloads),
        reason="A credential-flow threat is linked to its persisted web review evidence in the same explicit browser context within five minutes; this records provenance and related activity, not an independent confirmation.",
        rule_id="correlation.web_credential_activity", rule_version=RULE_VERSION,
        first_seen=evaluated_at, last_seen=evaluated_at,
    )
