"""CLI entry point: python -m sensor {run,check-config,self-test}."""
import argparse
import logging
import platform
import signal
import sys
from threading import Event

from services.remote_sensor_executor import LinuxRemoteSensorExecutor
from services.remote_sensor_models import RemoteSensorError

from .client import CoreClient, SensorClientError
from .config import load_config
from .runtime import SensorRuntime, _json_log
from .state import load_grants


def _parser():
    parser = argparse.ArgumentParser(prog='python -m sensor')
    parser.add_argument('--config', help='protected JSON config path (or SENTINEL_SENSOR_CONFIG)')
    subparsers = parser.add_subparsers(dest='command', required=True)
    for name in ('run', 'check-config', 'self-test'):
        subparsers.add_parser(name)
    return parser


def _self_test(config, client, logger):
    identity = client.get_self()
    if identity.get('sensor_uuid') != config.sensor_uuid:
        raise RemoteSensorError('Core identity did not match the configured sensor UUID.')
    _json_log(logger, sensor_uuid=config.sensor_uuid, status='SELF_TEST_OK')


def main(argv=None):
    logging.basicConfig(level=logging.INFO, format='%(message)s')
    logger = logging.getLogger('sentinelip.sensor')
    args = _parser().parse_args(argv)
    client = None
    try:
        config = load_config(args.config)
        grants = load_grants(config.grant_file, config.sensor_uuid, config.capabilities)
        if args.command == 'check-config':
            _json_log(logger, sensor_uuid=config.sensor_uuid, status='CONFIG_OK')
            return 0
        client = CoreClient(config)
        if args.command == 'self-test':
            _self_test(config, client, logger)
            return 0
        if platform.system().lower() != 'linux':
            raise RemoteSensorError('This runtime installation requires the Linux executor adapter.')
        _self_test(config, client, logger)
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
    except (RemoteSensorError, SensorClientError) as exc:
        # These messages contain bounded status text only; never print request headers or config repr.
        print(f'sensor error: {exc}', file=sys.stderr)
        return 1
    finally:
        if client is not None:
            client.close()


if __name__ == '__main__':
    raise SystemExit(main())
