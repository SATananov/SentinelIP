"""Pure interpretation of existing local detectors; no active response."""
from datetime import timedelta

from services.detector import SSHDetector
from services.threat_models import ThreatDetection, ThreatError, SSHThreatEvidence, WebThreatEvidence

WEB_WINDOW = timedelta(minutes=5)
RULE_VERSION = "1"


def evaluate_ssh(primary: SSHThreatEvidence, history: tuple[SSHThreatEvidence, ...], evaluated_at):
    if not isinstance(primary, SSHThreatEvidence) or not all(isinstance(e, SSHThreatEvidence) for e in history):
        raise ThreatError("Authentication evidence is required.")
    if primary.event_type not in {"LOGIN_FAILED", "SSH_PREAUTH"}:
        return None
    detector = SSHDetector()  # Existing default threshold, window and username policy.
    rows = {primary.evidence_id: primary}
    for item in history:
        if (item.source_ip != primary.source_ip or item.event_type != primary.event_type
                or (item.timestamp.utcoffset() is None) != (primary.timestamp.utcoffset() is None)):
            continue
        if (item.timestamp, item.evidence_id) > (primary.timestamp, primary.evidence_id):
            continue
        if primary.timestamp - detector.window <= item.timestamp <= primary.timestamp:
            if item.evidence_id in rows and rows[item.evidence_id] != item:
                raise ThreatError("Conflicting authentication evidence.")
            rows[item.evidence_id] = item
    ordered = tuple(sorted(rows.values(), key=lambda e: (e.timestamp, e.evidence_id)))
    for item in ordered:
        result = detector.analyze(item.event_type, item.source_ip, item.timestamp, item.username)
    if result.severity == "INFO":
        return None
    brute = primary.event_type == "LOGIN_FAILED" and result.severity == "ALERT"
    kind = "SSH_BRUTE_FORCE_THREAT" if brute else "SUSPICIOUS_AUTH_ACTIVITY"
    reason = ("Repeated failed SSH authentication attempts observed from this source; the existing detector threshold was met."
              if brute else "SSH authentication activity met the existing detector's repeated-activity or username-review condition.")
    return ThreatDetection(
        threat_type=kind, state="SUSPECTED" if brute else "ANOMALOUS",
        severity="MEDIUM" if brute or result.count >= 3 else "LOW",
        confidence="HIGH" if brute else "MEDIUM", evidence=ordered,
        primary_evidence_id=primary.evidence_id, anchor_id=primary.evidence_id,
        reason=reason, recommendation="Review the observed source activity and verify expected login attempts; manually assess authentication controls if appropriate.",
        rule_id="threat." + kind.lower(), rule_version=RULE_VERSION,
        first_seen=evaluated_at, last_seen=evaluated_at,
    )


def strengthens(anchor: WebThreatEvidence, download: WebThreatEvidence):
    return (anchor.detection_type == "CROSS_DOMAIN_LOGIN_REDIRECT"
            and download.detection_type == "SUSPICIOUS_DOWNLOAD_FLOW"
            and anchor.primary.context is not None
            and anchor.primary.context == download.primary.context
            and anchor.primary_observation_id in {e.observation_id for e in download.observations}
            and (anchor.primary.observed_at, anchor.primary_observation_id) <
                (download.primary.observed_at, download.primary_observation_id)
            and timedelta(0) <= download.primary.observed_at - anchor.primary.observed_at <= WEB_WINDOW)


def evaluate_web(anchor: WebThreatEvidence, related: tuple[WebThreatEvidence, ...], evaluated_at):
    if anchor.detection_type != "CROSS_DOMAIN_LOGIN_REDIRECT":
        return None
    evidence = {anchor.evidence_id: anchor}
    for item in related:
        if strengthens(anchor, item):
            evidence[item.evidence_id] = item
    return ThreatDetection(
        threat_type="WEB_CREDENTIAL_FLOW_THREAT", state="SUSPECTED", severity="MEDIUM", confidence="MEDIUM",
        evidence=tuple(evidence[key] for key in sorted(evidence)), primary_evidence_id=anchor.evidence_id,
        anchor_id=anchor.primary_observation_id,
        reason="An observed cross-domain credential-entry flow deserves threat review; legitimate sign-in flows can produce this pattern.",
        recommendation="Review the destination and user context and verify whether the credential-entry flow was expected.",
        rule_id="threat.web_credential_flow", rule_version=RULE_VERSION,
        first_seen=evaluated_at, last_seen=evaluated_at,
    )
