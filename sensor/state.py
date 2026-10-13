"""Load the independently provisioned, bounded local sensor assignment grants."""
import json
import os
from pathlib import Path
import tempfile
from uuid import UUID

from services.remote_sensor_models import LocalExecutorGrant, RemoteSensorError


def _normalize_grants(sensor_uuid: str, grants, capabilities: tuple[str, ...]) -> list[dict]:
    try:
        canonical_uuid = str(UUID(sensor_uuid))
    except (ValueError, TypeError, AttributeError) as exc:
        raise RemoteSensorError('Sensor UUID is invalid.') from exc
    if canonical_uuid != sensor_uuid or not isinstance(grants, list) or len(grants) > 100:
        raise RemoteSensorError('Server grant response is invalid.')
    normalized = []
    seen = set()
    for item in grants:
        if (not isinstance(item, dict) or set(item) != {'scope_id', 'scope_type', 'cidr', 'capabilities'}
                or type(item['scope_id']) is not int or item['scope_id'] < 1
                or item['scope_type'] != 'PRIVATE_NETWORK' or not isinstance(item['capabilities'], list)
                or len(item['capabilities']) > 2
                or any(not isinstance(cap, str) or cap not in capabilities for cap in item['capabilities'])
                or len(set(item['capabilities'])) != len(item['capabilities'])):
            raise RemoteSensorError('Server grant response contains an invalid assignment.')
        scope_id = item['scope_id']
        if scope_id in seen:
            raise RemoteSensorError('Server grant response contains duplicate assignments.')
        seen.add(scope_id)
        grant = LocalExecutorGrant(sensor_uuid=canonical_uuid, scope_id=scope_id,
                                   cidr=item['cidr'], capabilities=frozenset(item['capabilities']))
        normalized.append({'scope_id': scope_id, 'scope_type': 'PRIVATE_NETWORK',
                           'cidr': grant.cidr, 'capabilities': sorted(grant.capabilities)})
    return normalized


def _atomic_write(path: str | Path, data: bytes, *, replace: bool):
    target = Path(path)
    if not target.is_absolute():
        raise RemoteSensorError('Provisioning paths must be absolute.')
    try:
        if os.name == 'nt':
            from .windows_security import assert_secret, protect_secret
            assert_secret(target.parent)
        else:
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd, temporary = tempfile.mkstemp(prefix='.sentinel-sensor-', dir=target.parent)
        try:
            with os.fdopen(fd, 'wb') as stream:
                if os.name == 'nt':
                    protect_secret(temporary)
                else:
                    os.fchmod(stream.fileno(), 0o600)
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            if replace:
                os.replace(temporary, target)
            elif os.name == 'nt':
                os.rename(temporary, target)  # Windows rename never overwrites an existing file.
            else:
                # A hard link provides an atomic no-overwrite create on the same filesystem.
                os.link(temporary, target)
                os.unlink(temporary)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
    except FileExistsError as exc:
        raise RemoteSensorError('Refusing to overwrite an existing provisioning file.') from exc
    except OSError as exc:
        raise RemoteSensorError('Could not securely write sensor provisioning data.') from exc


def write_grants(path: str | Path, sensor_uuid: str, grants, capabilities: tuple[str, ...], *, replace=True):
    normalized = _normalize_grants(sensor_uuid, grants, capabilities)
    raw = {'sensor_uuid': sensor_uuid, 'grants': normalized}
    _atomic_write(path, (json.dumps(raw, sort_keys=True, separators=(',', ':')) + '\n').encode(), replace=replace)


def write_config(path: str | Path, value: dict, *, replace=False):
    if not isinstance(value, dict) or set(value) - {
        'core_url', 'sensor_uuid', 'sensor_credential', 'grant_file', 'poll_interval',
        'heartbeat_interval', 'request_timeout', 'development_mode', 'platform', 'version', 'capabilities',
    }:
        raise RemoteSensorError('Sensor config contains unsupported fields.')
    if not isinstance(value.get('sensor_credential'), str) or not 40 <= len(value['sensor_credential']) <= 128:
        raise RemoteSensorError('Sensor credential is missing or invalid.')
    _atomic_write(path, (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode(), replace=replace)


def load_grants(path: str | Path, sensor_uuid: str, capabilities: tuple[str, ...]) -> dict[int, LocalExecutorGrant]:
    grant_path = Path(path)
    if os.name == 'nt':
        from .windows_security import assert_secret
        assert_secret(grant_path)
    else:
        try:
            mode = grant_path.stat().st_mode & 0o777
        except OSError as exc:
            raise RemoteSensorError('Local grant file could not be read.') from exc
        if mode & 0o077:
            raise RemoteSensorError('Local grant file permissions must not grant group or other access.')
    try:
        value = json.loads(grant_path.read_text(encoding='utf-8'))
    except (OSError, json.JSONDecodeError) as exc:
        raise RemoteSensorError('Local grant file could not be read.') from exc
    if not isinstance(value, dict) or set(value) != {'sensor_uuid', 'grants'}:
        raise RemoteSensorError('Local grant file has an unsupported format.')
    if value['sensor_uuid'] != sensor_uuid or not isinstance(value['grants'], list) or len(value['grants']) > 100:
        raise RemoteSensorError('Local grants do not match this sensor identity.')
    grants = {}
    for raw in value['grants']:
        if (not isinstance(raw, dict) or set(raw) != {'scope_id', 'scope_type', 'cidr', 'capabilities'}
                or raw['scope_type'] != 'PRIVATE_NETWORK' or type(raw['scope_id']) is not int
                or not isinstance(raw['capabilities'], list)):
            raise RemoteSensorError('Local grant record is malformed.')
        if raw['scope_id'] in grants:
            raise RemoteSensorError('Local grant scope IDs must be unique.')
        if any(cap not in capabilities for cap in raw['capabilities']):
            raise RemoteSensorError('Local grant requests an unsupported capability.')
        grants[raw['scope_id']] = LocalExecutorGrant(
            sensor_uuid=sensor_uuid, scope_id=raw['scope_id'], cidr=raw['cidr'],
            capabilities=frozenset(raw['capabilities']),
        )
    return grants
