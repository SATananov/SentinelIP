from dataclasses import replace
from datetime import datetime, timedelta, timezone

from database import telemetry as telemetry_db
from services.telemetry_models import (
    DnsObservation,
    DnsQueryType,
    DnsResponseStatus,
    PrivacyMode,
    SensorType,
    WebEventType,
    WebObservation,
    normalize_timestamp,
)


class TelemetryIngestionError(ValueError):
    """Raised for invalid or unauthorized telemetry ingestion."""

    def __init__(self, message: str, status_code: int = 422):
        super().__init__(message)
        self.status_code = status_code


def _authenticate(sensor_id: int, token: str | None, expected_type: SensorType, db_path):
    if token is None or not token.strip():
        raise TelemetryIngestionError("Telemetry authentication failed.", 401)

    sensor = telemetry_db.authenticate_sensor(sensor_id, token, db_path)
    if sensor is None:
        raise TelemetryIngestionError("Telemetry authentication failed.", 401)
    if not sensor["enabled"]:
        raise TelemetryIngestionError("Telemetry sensor is disabled.", 403)
    if sensor["sensor_type"] != expected_type.value:
        raise TelemetryIngestionError("Telemetry sensor type is not permitted.", 403)
    return sensor


def _timestamp_and_retention(sensor: dict, observed_at: datetime):
    received_at = datetime.now(timezone.utc)
    normalized_observed = normalize_timestamp(observed_at, received_at)
    retention_until = received_at + timedelta(days=sensor["retention_days"])
    return normalized_observed, received_at, retention_until


def ingest_web(
    sensor_id: int,
    token: str | None,
    payload: dict,
    db_path,
):
    sensor = _authenticate(sensor_id, token, SensorType.BROWSER, db_path)
    if "device_id" in payload:
        raise TelemetryIngestionError("Device identity comes from sensor registration.")

    try:
        privacy_mode = PrivacyMode(sensor["privacy_mode"])
        event_type = WebEventType(payload["event_type"])
        observed_at, received_at, retention_until = _timestamp_and_retention(
            sensor,
            payload["observed_at"],
        )
        observation = WebObservation(
            external_event_id=payload["external_event_id"],
            sensor_id=str(sensor_id),
            device_id=sensor["device_id"],
            observed_at=observed_at,
            event_type=event_type,
            url=payload["url"],
            privacy_mode=privacy_mode,
            referrer_domain=payload.get("referrer_domain"),
            redirect_from_domain=payload.get("redirect_from_domain"),
            redirect_to_domain=payload.get("redirect_to_domain"),
            browser_session_id=payload.get("browser_session_id"),
            tab_id=payload.get("tab_id"),
            has_login_form=payload.get("has_login_form", False),
            has_password_form=payload.get("has_password_form", False),
            download_detected=payload.get("download_detected", False),
            metadata=payload.get("metadata"),
            received_at=received_at,
            retention_until=retention_until,
        )
    except (KeyError, TypeError, ValueError) as exc:
        if isinstance(exc, TelemetryIngestionError):
            raise
        raise TelemetryIngestionError("Web telemetry payload is invalid.") from exc

    existing = telemetry_db.get_web_observation_by_event(
        sensor_id,
        observation.external_event_id,
        db_path,
    )
    if existing is not None:
        telemetry_db.touch_sensor_last_seen(sensor_id, received_at, db_path)
        return {"id": existing["id"], "idempotent": True, "received_at": existing["received_at"]}

    stored = telemetry_db.create_web_observation(observation, db_path)
    telemetry_db.touch_sensor_last_seen(sensor_id, received_at, db_path)
    return {"id": stored["id"], "idempotent": False, "received_at": stored["received_at"]}


def ingest_dns(
    sensor_id: int,
    token: str | None,
    payload: dict,
    db_path,
):
    sensor = _authenticate(sensor_id, token, SensorType.DNS, db_path)
    if "device_id" in payload:
        raise TelemetryIngestionError("Device identity comes from sensor registration.")

    try:
        observed_at, received_at, retention_until = _timestamp_and_retention(
            sensor,
            payload["observed_at"],
        )
        observation = DnsObservation(
            external_event_id=payload["external_event_id"],
            sensor_id=str(sensor_id),
            device_id=sensor["device_id"],
            observed_at=observed_at,
            queried_domain=payload["queried_domain"],
            query_type=payload["query_type"],
            response_status=payload["response_status"],
            resolved_addresses=tuple(payload.get("resolved_addresses", ())),
            resolver=payload.get("resolver"),
            ttl=payload.get("ttl"),
            metadata=payload.get("metadata"),
            received_at=received_at,
            retention_until=retention_until,
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise TelemetryIngestionError("DNS telemetry payload is invalid.") from exc

    existing = telemetry_db.get_dns_observation_by_event(
        sensor_id,
        observation.external_event_id,
        db_path,
    )
    if existing is not None:
        telemetry_db.touch_sensor_last_seen(sensor_id, received_at, db_path)
        return {"id": existing["id"], "idempotent": True, "received_at": existing["received_at"]}

    stored = telemetry_db.create_dns_observation(observation, db_path)
    telemetry_db.touch_sensor_last_seen(sensor_id, received_at, db_path)
    return {"id": stored["id"], "idempotent": False, "received_at": stored["received_at"]}