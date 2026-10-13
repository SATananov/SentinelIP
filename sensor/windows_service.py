"""Windows SCM adapter. The task loop remains sensor.runtime.SensorRuntime."""
import json
import logging
import os
from pathlib import Path
import re
from threading import Event
import sys

import servicemanager
import win32service
import win32serviceutil

from sensor.__main__ import run_sensor
from sensor.client import CoreClient
from sensor.config import load_config
from sensor.platforms import default_paths

SERVICE_NAME = 'SentinelIPSensor'


class EventLogHandler(logging.Handler):
    def emit(self, record):
        # Only existing structured runtime fields reach Event Log. Never exception text.
        try:
            value = json.loads(record.getMessage())
            safe = {key: value[key] for key in ('timestamp', 'sensor_uuid', 'task_id', 'task_type', 'status', 'error_code')
                    if key in value and isinstance(value[key], str)
                    and re.fullmatch(r'[A-Za-z0-9_.:+-]{1,80}', value[key])}
            if 'status' in safe:
                servicemanager.LogInfoMsg(json.dumps(safe, sort_keys=True))
        except (ValueError, TypeError):
            pass


class SentinelIPSensorService(win32serviceutil.ServiceFramework):
    _svc_name_ = SERVICE_NAME
    _svc_display_name_ = 'SentinelIP Remote Sensor'
    _svc_description_ = 'Bounded private-network discovery using Core-assigned typed tasks.'

    def __init__(self, args):
        super().__init__(args)
        self.stop_event = Event()

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING, waitHint=120000)
        self.stop_event.set()

    def SvcShutdown(self):
        self.SvcStop()

    def SvcDoRun(self):
        logger = logging.getLogger('sentinelip.sensor')
        handler = EventLogHandler()
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        logger.propagate = False
        client = None
        try:
            # Parameters are admin-owned SCM configuration, not a task payload.
            import winreg
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                    r'SYSTEM\CurrentControlSet\Services\SentinelIPSensor\Parameters') as key:
                nmap, _ = winreg.QueryValueEx(key, 'NmapPath')
            os.environ['SENTINEL_SENSOR_NMAP'] = nmap
            config = load_config(default_paths()[0])
            client = CoreClient(config)
            run_sensor(config, client, self.stop_event, logger)
        except Exception:
            servicemanager.LogErrorMsg('SentinelIP sensor stopped: configuration, dependency, or Core startup check failed.')
            self.ReportServiceStatus(win32service.SERVICE_STOPPED, win32ExitCode=1066, svcExitCode=1)
        finally:
            if client is not None:
                client.close()
            logger.removeHandler(handler)


def install_service(class_string):
    from services.windows_sensor_executor import resolve_nmap
    from sensor.windows_security import assert_code
    assert_code(sys.executable)
    assert_code(Path(__file__))
    nmap = resolve_nmap()
    try:
        win32serviceutil.QueryServiceStatus(SERVICE_NAME)
    except win32service.error as exc:
        if exc.winerror != 1060:
            raise
        install = win32serviceutil.InstallService
    else:
        install = win32serviceutil.ChangeServiceConfig
    install(class_string, SERVICE_NAME, displayName='SentinelIP Remote Sensor',
            startType=win32service.SERVICE_DEMAND_START, userName=r'NT AUTHORITY\LocalService',
            description=SentinelIPSensorService._svc_description_)
    win32serviceutil.SetServiceCustomOption(SERVICE_NAME, 'NmapPath', nmap)
    manager = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_CONNECT)
    try:
        service = win32service.OpenService(manager, SERVICE_NAME, win32service.SERVICE_CHANGE_CONFIG)
        try:
            win32service.ChangeServiceConfig2(service, win32service.SERVICE_CONFIG_FAILURE_ACTIONS,
                {'ResetPeriod': 86400, 'RebootMsg': '', 'Command': '',
                 'Actions': [(win32service.SC_ACTION_RESTART, 10000),
                             (win32service.SC_ACTION_RESTART, 30000),
                             (win32service.SC_ACTION_RESTART, 60000), (win32service.SC_ACTION_NONE, 0)]})
            win32service.ChangeServiceConfig2(service, win32service.SERVICE_CONFIG_FAILURE_ACTIONS_FLAG, True)
        finally:
            win32service.CloseServiceHandle(service)
    finally:
        win32service.CloseServiceHandle(manager)
