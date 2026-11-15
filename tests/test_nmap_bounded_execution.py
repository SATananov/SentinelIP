import sys
import threading
import time
import io

import pytest

from services.scanner_adapters import nmap_adapter
from services.scanner_adapters.nmap_adapter import (
    ScannerCapacityError,
    ScannerExecutionError,
    ScannerTimeoutError,
    ScannerUnavailableError,
    _run_nmap,
)


def test_bounded_output_drains_stdout_and_stderr_and_rejects_overflow():
    with pytest.raises(ScannerExecutionError, match="size limit"):
        _run_nmap(
            [sys.executable, "-c", "import sys; sys.stdout.write('x'*200000); sys.stderr.write('y'*200000)"],
            5,
            32768,
        )


def test_stderr_has_its_own_lower_ceiling():
    with pytest.raises(ScannerExecutionError, match="size limit"):
        _run_nmap(
            [sys.executable, "-c", "import sys; sys.stderr.write('e'*100000)"],
            5,
            131072,
        )


def test_aggregate_output_ceiling_is_enforced():
    with pytest.raises(ScannerExecutionError, match="size limit"):
        _run_nmap(
            [sys.executable, "-c", "import sys; sys.stdout.write('o'*20000); sys.stderr.write('e'*20000)"],
            5,
            32768,
        )


def test_process_timeout_kills_child():
    started = time.monotonic()
    with pytest.raises(ScannerTimeoutError):
        _run_nmap([sys.executable, "-c", "import time; time.sleep(3)"], 0.1, 4096)
    assert time.monotonic() - started < 2
    assert _run_nmap([sys.executable, "-c", "print('released')"], 1, 4096).stdout.strip() == "released"


def test_process_start_failure_releases_execution_slot():
    with pytest.raises(ScannerUnavailableError):
        _run_nmap(["/missing/nmap-for-test"], 1, 4096)
    assert nmap_adapter._NMAP_EXECUTION_SLOTS.acquire(blocking=False)
    nmap_adapter._NMAP_EXECUTION_SLOTS.release()


def test_process_local_concurrency_rejects_excess_and_releases_permit(monkeypatch):
    semaphore = threading.BoundedSemaphore(1)
    monkeypatch.setattr(nmap_adapter, "_NMAP_EXECUTION_SLOTS", semaphore)
    ready = threading.Event()
    result = []

    def occupy():
        ready.set()
        result.append(_run_nmap(
            [sys.executable, "-c", "import time; time.sleep(.35); print('ok')"],
            2,
            4096,
        ))

    worker = threading.Thread(target=occupy)
    worker.start()
    ready.wait(1)
    time.sleep(.08)
    with pytest.raises(ScannerCapacityError):
        _run_nmap([sys.executable, "-c", "print('no')"], 1, 4096)
    worker.join(3)
    assert not worker.is_alive()
    assert result[0].stdout.strip() == "ok"
    assert _run_nmap([sys.executable, "-c", "print('released')"], 1, 4096).stdout.strip() == "released"


def test_cancellation_terminates_process_and_closes_streams(monkeypatch):
    class FakeProcess:
        pid = 991

        def __init__(self, *args, **kwargs):
            self.stdout = io.BytesIO(b"")
            self.stderr = io.BytesIO(b"")
            self.returncode = None
            self.killed = False
            self.waits = 0

        def wait(self, timeout=None):
            self.waits += 1
            if self.waits == 1:
                raise KeyboardInterrupt
            self.returncode = -9
            return self.returncode

        def poll(self):
            return self.returncode

        def kill(self):
            self.killed = True
            self.returncode = -9

    process = FakeProcess()
    monkeypatch.setattr(nmap_adapter.subprocess, "Popen", lambda *args, **kwargs: process)
    monkeypatch.setattr(nmap_adapter.os, "killpg", lambda *args: setattr(process, "killed", True))
    with pytest.raises(KeyboardInterrupt):
        _run_nmap(["nmap"], 1, 4096)
    assert process.killed
    assert process.stdout.closed and process.stderr.closed
