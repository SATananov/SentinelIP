"""Bounded runtime configuration loaded from JSON and environment variables."""
from dataclasses import dataclass, field
import ipaddress
import json
import os
from pathlib import Path
import platform
import re
from urllib.parse import urlsplit
from uuid import UUID

from services.remote_sensor_models import RemoteSensorError
from .version import RUNTIME_VERSION

_ALLOWED_CAPABILITIES = frozenset({'HOST_DISCOVERY', 'SERVICE_DISCOVERY'})
_VERSION = re.compile(r'^[A-Za-z0-9._+-]{1,64}$')


def _validate_core_url(value: object, *, development_mode: bool) -> str:
    if not isinstance(value, str) or len(value) > 2048:
        raise RemoteSensorError('Invalid Core URL.')
    try:
        parsed = urlsplit(value)
        host = parsed.hostname
        parsed.port  # Validate the port syntax/range.
    except (ValueError, TypeError) as exc:
        raise RemoteSensorError('Invalid Core URL.') from exc
    if (parsed.username is not None or parsed.password is not None or not host
            or parsed.query or parsed.fragment or parsed.scheme not in {'http', 'https'}):
        raise RemoteSensorError('Invalid Core URL.')
    try:
        loopback = host.lower() == 'localhost' or ipaddress.ip_address(host).is_loopback
    except ValueError:
        loopback = host.lower() == 'localhost'
    if parsed.scheme == 'http' and not (development_mode and loopback):
        raise RemoteSensorError('Remote Core URLs must use HTTPS; HTTP requires explicit loopback development mode.')
    if parsed.scheme == 'http' and not loopback:
        raise RemoteSensorError('HTTP is allowed only for loopback development.')
    path = parsed.path.rstrip('/')
    return f'{parsed.scheme}://{parsed.netloc}{path}'


@dataclass(frozen=True)
class SensorConfig:
    core_url: str
    sensor_uuid: str
    sensor_credential: str = field(repr=False)
    grant_file: Path
    poll_interval: int = 10
    heartbeat_interval: int = 45
    request_timeout: int = 15
    development_mode: bool = False
    platform_name: str = 'linux'
    version: str = RUNTIME_VERSION
    capabilities: tuple[str, ...] = ('HOST_DISCOVERY', 'SERVICE_DISCOVERY')


def _read_config(path: Path) -> dict:
    if os.name != 'nt':
        try:
            mode = path.stat().st_mode & 0o777
        except OSError as exc:
            raise RemoteSensorError('Sensor config file could not be read.') from exc
        if mode & 0o077:
            raise RemoteSensorError('Sensor config file permissions must not grant group or other access.')
    try:
        value = json.loads(path.read_text(encoding='utf-8'))
    except (OSError, json.JSONDecodeError) as exc:
        raise RemoteSensorError('Sensor config file could not be read.') from exc
    if not isinstance(value, dict):
        raise RemoteSensorError('Sensor config must be a JSON object.')
    allowed = {'core_url', 'sensor_uuid', 'sensor_credential', 'grant_file', 'poll_interval',
               'heartbeat_interval', 'request_timeout', 'development_mode', 'platform', 'version',
               'capabilities'}
    if set(value) - allowed:
        raise RemoteSensorError('Sensor config contains unsupported fields.')
    return value


def load_config(path: str | Path | None = None, *, environ=None) -> SensorConfig:
    """Load a protected JSON config; credential environment variable overrides its value."""
    env = os.environ if environ is None else environ
    selected = Path(path or env.get('SENTINEL_SENSOR_CONFIG', 'sensor-config.json')).expanduser()
    raw = _read_config(selected)
    credential = env.get('SENTINEL_SENSOR_CREDENTIAL', raw.get('sensor_credential'))
    if not isinstance(credential, str) or not 40 <= len(credential) <= 128:
        raise RemoteSensorError('Sensor credential is missing or invalid.')
    try:
        sensor_uuid = str(UUID(str(raw['sensor_uuid'])))
    except (KeyError, ValueError, TypeError, AttributeError) as exc:
        raise RemoteSensorError('Sensor UUID is missing or invalid.') from exc
    development = raw.get('development_mode', False)
    if type(development) is not bool:
        raise RemoteSensorError('development_mode must be boolean.')
    core_url = _validate_core_url(raw.get('core_url'), development_mode=development)
    grant_value = raw.get('grant_file')
    if not isinstance(grant_value, str) or not grant_value:
        raise RemoteSensorError('grant_file must be an absolute path.')
    grant_file = Path(grant_value).expanduser()
    if not grant_file.is_absolute():
        raise RemoteSensorError('grant_file must be an absolute path.')
    poll = raw.get('poll_interval', 10)
    heartbeat = raw.get('heartbeat_interval', 45)
    timeout = raw.get('request_timeout', 15)
    if type(poll) is not int or not 5 <= poll <= 15:
        raise RemoteSensorError('poll_interval must be between 5 and 15 seconds.')
    if type(heartbeat) is not int or not 30 <= heartbeat <= 60:
        raise RemoteSensorError('heartbeat_interval must be between 30 and 60 seconds.')
    if type(timeout) is not int or not 1 <= timeout <= 60:
        raise RemoteSensorError('request_timeout must be between 1 and 60 seconds.')
    platform_name = raw.get('platform', platform.system().lower())
    version = raw.get('version', RUNTIME_VERSION)
    if not isinstance(platform_name, str) or not 1 <= len(platform_name) <= 64:
        raise RemoteSensorError('platform must be 1–64 characters.')
    if not isinstance(version, str) or not _VERSION.fullmatch(version):
        raise RemoteSensorError('version contains unsupported characters.')
    capabilities = raw.get('capabilities', sorted(_ALLOWED_CAPABILITIES))
    if (not isinstance(capabilities, list) or not capabilities
            or any(not isinstance(item, str) or item not in _ALLOWED_CAPABILITIES for item in capabilities)
            or len(capabilities) != len(set(capabilities))):
        raise RemoteSensorError('Only unique HOST_DISCOVERY and SERVICE_DISCOVERY capabilities are supported.')
    return SensorConfig(core_url, sensor_uuid, credential, grant_file, poll, heartbeat, timeout,
                        development, platform_name, version, tuple(sorted(capabilities)))
