"""Load the independently provisioned, bounded local sensor assignment grants."""
import json
import os
from pathlib import Path

from services.remote_sensor_models import LocalExecutorGrant, RemoteSensorError


def load_grants(path: str | Path, sensor_uuid: str, capabilities: tuple[str, ...]) -> dict[int, LocalExecutorGrant]:
    grant_path = Path(path)
    if os.name != 'nt':
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
