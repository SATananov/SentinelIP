"""Linux sensor CLI: enroll, check-config, refresh-grant, self-test, run."""
import argparse
import getpass
import logging
from pathlib import Path
import platform
import shutil
import signal
import sys
from threading import Event
from uuid import UUID, uuid4

from services.remote_sensor_executor import LinuxRemoteSensorExecutor
from services.remote_sensor_models import LocalExecutorGrant, RemoteSensorError

from .client import CoreClient, EnrollmentClient, SensorClientError
from .config import SensorConfig, load_config
from .runtime import SensorRuntime, _json_log
from .state import _normalize_grants, load_grants, write_config, write_grants
from .version import RUNTIME_VERSION

DEFAULT_CONFIG = Path('/etc/sentinelip-sensor/config.json')
DEFAULT_GRANTS = Path('/etc/sentinelip-sensor/grants.json')
_CAPABILITIES = ('HOST_DISCOVERY', 'SERVICE_DISCOVERY')


def _parser():
    parser = argparse.ArgumentParser(prog='sentinelip-sensor')
    parser.add_argument('--version', action='version', version=f'%(prog)s {RUNTIME_VERSION}')
    parser.add_argument('--config', help='protected JSON config path (or SENTINEL_SENSOR_CONFIG)')
    subparsers = parser.add_subparsers(dest='command', required=True)
    for name in ('run', 'check-config', 'self-test', 'refresh-grant'):
        sub = subparsers.add_parser(name)
        sub.add_argument('--config', dest='sub_config', help=argparse.SUPPRESS)
    enroll = subparsers.add_parser('enroll')
    enroll.add_argument('--config', default=str(DEFAULT_CONFIG), help='new protected config path')
    enroll.add_argument('--grant-file', default=str(DEFAULT_GRANTS), help='protected grant file path')
    enroll.add_argument('--core-url', required=True)
    enroll.add_argument('--development-mode', action='store_true', help='allow HTTP only for loopback development')
    enroll.add_argument('--sensor-uuid', help='canonical UUID; generated when omitted')
    enroll.add_argument('--name', required=True)
    enroll.add_argument('--platform', default='linux')
    enroll.add_argument('--capability', action='append', choices=_CAPABILITIES,
                        help='repeat to select supported capabilities (defaults to both)')
    enroll.add_argument('--request-timeout', type=int, default=15)
    return parser


def _assert_identity(config, client):
    identity = client.get_self()
    if identity.get('sensor_uuid') != config.sensor_uuid or identity.get('enabled') is not True:
        raise RemoteSensorError('Core identity is disabled or does not match this sensor.')
    return identity


def _sync_grants(config, client, *, replace=True):
    response = client.get_grant()
    if set(response) != {'grants'} or not isinstance(response['grants'], list):
        raise RemoteSensorError('Core grant response is malformed.')
    write_grants(config.grant_file, config.sensor_uuid, response['grants'], config.capabilities,
                 replace=replace)
    return load_grants(config.grant_file, config.sensor_uuid, config.capabilities)


def _check_dependencies(config):
    if sys.version_info < (3, 10):
        raise RemoteSensorError('Python 3.10 or newer is required.')
    _check_nmap()
    if not config.sensor_credential:
        raise RemoteSensorError('Sensor credential is missing.')
    return True


def _check_nmap():
    if not shutil.which('nmap'):
        raise RemoteSensorError('Nmap is required for bounded discovery but was not found.')


def _self_test(config, client, logger):
    _check_dependencies(config)
    grants = load_grants(config.grant_file, config.sensor_uuid, config.capabilities)
    _assert_identity(config, client)
    response = client.get_grant()
    if set(response) != {'grants'} or not isinstance(response['grants'], list):
        raise RemoteSensorError('Core grant response is malformed.')
    # Compare normalized server state with the protected local state without writing.
    remote_records = _normalize_grants(config.sensor_uuid, response['grants'], config.capabilities)
    remote = {item['scope_id']: LocalExecutorGrant(
        sensor_uuid=config.sensor_uuid, scope_id=item['scope_id'], cidr=item['cidr'],
        capabilities=frozenset(item['capabilities'])) for item in remote_records}
    if grants != remote:
        raise RemoteSensorError('Local grant is stale; run refresh-grant before starting the service.')
    _json_log(logger, sensor_uuid=config.sensor_uuid, status='SELF_TEST_OK')


def _enroll(args, logger):
    config_path = Path(args.config).expanduser()
    grant_path = Path(args.grant_file).expanduser()
    if not config_path.is_absolute() or not grant_path.is_absolute() or config_path == grant_path:
        raise RemoteSensorError('Config and grant paths must be distinct absolute paths.')
    if config_path.exists() or grant_path.exists():
        raise RemoteSensorError('Refusing enrollment because a config or grant file already exists.')
    if type(args.request_timeout) is not int or not 1 <= args.request_timeout <= 60:
        raise RemoteSensorError('request-timeout must be between 1 and 60 seconds.')
    _check_nmap()
    sensor_uuid = str(UUID(args.sensor_uuid)) if args.sensor_uuid else str(uuid4())
    caps = sorted(set(args.capability or _CAPABILITIES))
    token = getpass.getpass('One-time enrollment token: ')
    if not 40 <= len(token) <= 128:
        raise RemoteSensorError('Enrollment token is missing or invalid.')
    client = EnrollmentClient(args.core_url, development_mode=args.development_mode,
                              timeout=args.request_timeout)
    machine = None
    registration_completed = False
    try:
        result = client.register(enrollment_token=token, sensor_uuid=sensor_uuid,
                                 sensor_name=args.name, platform=args.platform,
                                 version=RUNTIME_VERSION, capabilities=caps)
        registration_completed = True
        credential = result['credential']
        config_value = {
            'core_url': client.core_url, 'sensor_uuid': sensor_uuid,
            'sensor_credential': credential, 'grant_file': str(grant_path),
            'poll_interval': 10, 'heartbeat_interval': 45,
            'request_timeout': args.request_timeout,
            'development_mode': args.development_mode,
            'platform': args.platform, 'version': RUNTIME_VERSION, 'capabilities': caps,
        }
        machine_config = SensorConfig(client.core_url, sensor_uuid, credential, grant_path,
                                      request_timeout=args.request_timeout,
                                      development_mode=args.development_mode,
                                      platform_name=args.platform, version=RUNTIME_VERSION,
                                      capabilities=tuple(caps))
        machine = CoreClient(machine_config)
        _assert_identity(machine_config, machine)
        grant_response = machine.get_grant()
        if set(grant_response) != {'grants'} or not isinstance(grant_response['grants'], list):
            raise RemoteSensorError('Core grant response is malformed.')
        _normalize_grants(sensor_uuid, grant_response['grants'], tuple(caps))
        # Persist only after all server responses are validated. Roll back a partially
        # written pair if the second protected file cannot be created.
        write_grants(grant_path, sensor_uuid, grant_response['grants'], tuple(caps), replace=False)
        try:
            write_config(config_path, config_value, replace=False)
        except Exception:
            try:
                grant_path.unlink()
            except OSError:
                pass
            raise
    except (RemoteSensorError, SensorClientError, ValueError, OSError) as exc:
        if registration_completed:
            raise RemoteSensorError(
                'Core registration succeeded but local provisioning did not complete; revoke that sensor in Core before retrying.'
            ) from exc
        raise
    finally:
        client.close()
        if machine is not None:
            machine.close()
    _json_log(logger, sensor_uuid=sensor_uuid, status='ENROLLMENT_COMPLETE')
    print(f'Sensor enrolled. Protected configuration saved to {config_path}.')
    print('No scanning was started. Run self-test, assign a private scope in Core, then refresh-grant.')


def main(argv=None):
    logging.basicConfig(level=logging.INFO, format='%(message)s')
    logger = logging.getLogger('sentinelip.sensor')
    args = _parser().parse_args(argv)
    if args.command == 'enroll':
        try:
            _enroll(args, logger)
            return 0
        except (RemoteSensorError, SensorClientError, ValueError, OSError) as exc:
            print(f'sensor error: {exc}', file=sys.stderr)
            return 1
    client = None
    try:
        config = load_config(getattr(args, 'sub_config', None) or args.config)
        if args.command == 'check-config':
            _check_dependencies(config)
            load_grants(config.grant_file, config.sensor_uuid, config.capabilities)
            _json_log(logger, sensor_uuid=config.sensor_uuid, status='CONFIG_OK')
            return 0
        client = CoreClient(config)
        if args.command == 'refresh-grant':
            _assert_identity(config, client)
            grants = _sync_grants(config, client)
            _json_log(logger, sensor_uuid=config.sensor_uuid, status='GRANT_REFRESHED')
            print(f'Current grant synchronized ({len(grants)} assigned private network(s)).')
            return 0
        if args.command == 'self-test':
            _self_test(config, client, logger)
            return 0
        if platform.system().lower() != 'linux':
            raise RemoteSensorError('This installation requires the Linux executor adapter.')
        _check_dependencies(config)
        _assert_identity(config, client)
        grants = _sync_grants(config, client)
        stop_event = Event()
        def stop(signum, frame):
            stop_event.set()
            _json_log(logger, sensor_uuid=config.sensor_uuid, status='SHUTDOWN_REQUESTED')
        signal.signal(signal.SIGINT, stop)
        signal.signal(signal.SIGTERM, stop)
        runtime = SensorRuntime(config, grants, client, LinuxRemoteSensorExecutor(),
                                stop_event=stop_event, logger=logger)
        runtime.run()
        _json_log(logger, sensor_uuid=config.sensor_uuid, status='SHUTDOWN_COMPLETE')
        return 0
    except (RemoteSensorError, SensorClientError, ValueError, OSError) as exc:
        print(f'sensor error: {exc}', file=sys.stderr)
        return 1
    finally:
        if client is not None:
            client.close()


if __name__ == '__main__':
    raise SystemExit(main())
