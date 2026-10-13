"""SCM's fixed Python class entrypoint; no generic command execution."""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from sensor.windows_service import SentinelIPSensorService, install_service

if __name__ == '__main__':
    if sys.argv[1:] != ['install']:
        raise SystemExit('Only install is supported; use Windows Service Control for lifecycle operations.')
    install_service(str(Path(__file__).resolve().with_suffix('')) + '.SentinelIPSensorService')
