"""OS selection and OS-owned storage locations; Core metadata never selects execution."""
from pathlib import Path
import platform

from services.remote_sensor_models import RemoteSensorError


def windows_data_directory():
    # Native Known Folder lookup is independent of a caller-controlled ProgramData variable.
    try:
        from win32com.shell import shell, shellcon
        value = shell.SHGetFolderPath(0, shellcon.CSIDL_COMMON_APPDATA, None, 0)
    except ImportError as exc:
        raise RemoteSensorError('Windows sensor requires the operator-installed pywin32 package.') from exc
    from .windows_security import validate_local_path
    return validate_local_path(value) / 'SentinelIP' / 'Sensor'


def default_paths():
    if platform.system() == 'Windows':
        base = windows_data_directory()
        return Path(str(base / 'config.json')), Path(str(base / 'grants.json'))
    return Path('/etc/sentinelip-sensor/config.json'), Path('/etc/sentinelip-sensor/grants.json')


def select_executor():
    system = platform.system()
    if system == 'Linux':
        from services.remote_sensor_executor import LinuxRemoteSensorExecutor
        return LinuxRemoteSensorExecutor()
    if system == 'Windows':
        from services.windows_sensor_executor import WindowsRemoteSensorExecutor
        return WindowsRemoteSensorExecutor()
    raise RemoteSensorError('Unsupported sensor platform; only Linux and Windows are supported.')
