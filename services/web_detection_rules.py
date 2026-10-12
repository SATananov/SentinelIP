"""Pure rules over explicit persisted evidence; every result means REVIEW only."""
from datetime import timedelta

from services.web_detection_models import WebDetection, WebDetectionError, WebEvidence

REDIRECT_WINDOW = timedelta(minutes=2)
DOWNLOAD_WINDOW = timedelta(minutes=5)
REDIRECT_HOST_THRESHOLD = 3
RULE_VERSION = "1"


def _order(item):
    return item.observed_at, item.observation_id


def _redirect(item):
    return (item.event_type == "REDIRECT" and item.redirect_from_domain is not None
            and item.redirect_to_domain == item.hostname)


def _cross(item):
    return _redirect(item) and item.redirect_from_domain != item.redirect_to_domain


def _credential(item):
    return item.has_password_form or item.has_login_form


def _candidate(kind, primary, evidence, now, reason):
    evidence = tuple(sorted({e.observation_id: e for e in (*evidence, primary)}.values(), key=_order))
    return WebDetection(
        detection_type=kind, severity="LOW" if kind in {"LOGIN_DOMAIN_REVIEW", "REDIRECT_CHAIN_REVIEW"} else "MEDIUM",
        confidence="MEDIUM", state="REVIEW", sensor_id=primary.sensor_id, device_id=primary.device_id,
        primary_observation_id=primary.observation_id, hostname=primary.hostname, reason=reason,
        evidence=evidence, rule_id="web." + kind.lower(), rule_version=RULE_VERSION,
        first_seen=now, last_seen=now,
    )


def evaluate_rules(primary: WebEvidence, history: tuple[WebEvidence, ...], evaluated_at) -> tuple[WebDetection, ...]:
    if not isinstance(primary, WebEvidence) or not all(isinstance(e, WebEvidence) for e in history):
        raise WebDetectionError("Normalized persisted evidence is required.")
    ids = [e.observation_id for e in history]
    if len(set(ids)) != len(ids):
        raise WebDetectionError("Duplicate history IDs are not allowed.")
    prior = sorted((e for e in history if primary.context is not None and e.context == primary.context
                    and _order(e) < _order(primary)
                    and primary.observed_at - e.observed_at <= DOWNLOAD_WINDOW), key=_order)
    recent = [e for e in prior if primary.observed_at - e.observed_at <= REDIRECT_WINDOW]
    results = []
    if _credential(primary):
        redirect = primary if _cross(primary) else None
        if redirect is None:
            for item in reversed(recent):
                # Do not jump across observed navigation away from the landing hostname.
                if item.event_type in {"NAVIGATION", "REDIRECT"} and item.hostname != primary.hostname:
                    break
                if _cross(item) and item.redirect_to_domain == primary.hostname:
                    redirect = item
                    break
        if redirect is not None:
            results.append(_candidate("CROSS_DOMAIN_LOGIN_REDIRECT", primary, (redirect,), evaluated_at,
                                     "Different-hostname redirect into an observed credential-entry flow deserves review; legitimate sign-in flows can do this."))
        elif primary.has_password_form:
            results.append(_candidate("LOGIN_DOMAIN_REVIEW", primary, (), evaluated_at,
                                     "A password-entry form was observed; retain for credential-flow review or inventory, without a threat verdict."))

    if _redirect(primary) and primary.context is not None:
        chain = [primary]
        for item in reversed(recent):
            if item.event_type == "REDIRECT":
                if not _redirect(item) or item.redirect_to_domain != chain[0].redirect_from_domain:
                    break
                chain.insert(0, item)
            elif item.event_type == "NAVIGATION" and item.hostname != chain[0].redirect_from_domain:
                break
        hosts = {host for e in chain for host in (e.redirect_from_domain, e.redirect_to_domain)}
        if len(chain) >= 2 and len(hosts) >= REDIRECT_HOST_THRESHOLD:
            results.append(_candidate("REDIRECT_CHAIN_REVIEW", primary, tuple(chain), evaluated_at,
                                     "At least three distinct hostnames occurred in a linked redirect sequence within two minutes; review the observed flow."))

    if primary.event_type == "DOWNLOAD_SIGNAL" and primary.download_detected:
        context = next((e for e in reversed(prior) if _credential(e) or _cross(e)), None)
        if context is not None:
            results.append(_candidate("SUSPICIOUS_DOWNLOAD_FLOW", primary, (context,), evaluated_at,
                                     "A download signal followed credential-entry or a different-hostname redirect within five minutes in the same explicit browser context; review only, with no file-content verdict."))
    return tuple(results)
