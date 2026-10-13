"""Platform-neutral headers for future sensor HTTP clients; no scanner behavior."""
from datetime import datetime, timezone
import re
import secrets
from uuid import UUID

from services.remote_sensor_models import RemoteSensorError

_NONCE_PATTERN = re.compile(r'^[A-Za-z0-9_-]{43}$')


def authenticated_sensor_headers(sensor_uuid, credential, *, now=None, nonce=None):
    """Build transport headers; callers must use HTTPS and verify Core's TLS certificate."""
    try:
        canonical_uuid = str(UUID(str(sensor_uuid)))
    except (ValueError, TypeError, AttributeError) as exc:
        raise RemoteSensorError('A valid sensor UUID is required.') from exc
    if not isinstance(credential, str) or not 40 <= len(credential) <= 128:
        raise RemoteSensorError('A valid sensor credential is required.')
    now = now or datetime.now(timezone.utc)
    if not isinstance(now, datetime) or now.tzinfo is None:
        raise RemoteSensorError('An aware client clock is required.')
    nonce = nonce or secrets.token_urlsafe(32)
    if not isinstance(nonce, str) or not _NONCE_PATTERN.fullmatch(nonce):
        raise RemoteSensorError('A 256-bit URL-safe nonce is required.')
    return {
        'Authorization': f'Bearer {credential}',
        'X-Sensor-UUID': canonical_uuid,
        'X-Sentinel-Timestamp': str(int(now.timestamp())),
        'X-Sentinel-Nonce': nonce,
    }
