import io
import locale
import subprocess
import sys
from collections.abc import Iterator
from typing import BinaryIO

from services.ssh_input_limits import MAX_SSH_LOG_LINE_BYTES

DEFAULT_HOST = "192.168.122.25"
DEFAULT_USER = "tanashi"
DEFAULT_KEY = "/home/tanashi/.ssh/sentinelip_ed25519"
SSH_READ_CHUNK_BYTES = 1024
TERMINATE_WAIT_SECONDS = 2.0
KILL_WAIT_SECONDS = 2.0


class SSHCollectorStartError(RuntimeError):
    """A fixed safe error raised when the local SSH process cannot start."""

    def __init__(self):
        super().__init__("Unable to start SSH log collector.")


class SSHInputRejectionReporter:
    """Bounded rejection counters and one fixed warning per input category."""

    _MESSAGES = {
        "oversized_line": "SSH input rejected: raw log line exceeded the byte limit.",
        "invalid_encoding": "SSH input rejected: raw log line had invalid text encoding.",
        "oversized_username": "SSH input rejected: username exceeded the byte limit.",
    }

    def __init__(self):
        self.counts = {category: 0 for category in self._MESSAGES}
        self._warned: set[str] = set()

    def record(self, category: str) -> None:
        if category not in self._MESSAGES:
            raise ValueError("Unknown SSH input rejection category.")
        self.counts[category] += 1
        if category not in self._warned:
            print(self._MESSAGES[category])
            self._warned.add(category)

    def report_summary(self) -> None:
        rejected = [
            f"{category}={count}"
            for category, count in self.counts.items()
            if count
        ]
        if rejected:
            print("SSH input rejection totals: " + ", ".join(rejected))


def _default_text_encoding() -> str:
    # Match subprocess text mode: UTF-8 mode takes precedence, otherwise the
    # active locale encoding is used.
    if sys.flags.utf8_mode:
        return "utf-8"
    return locale.getencoding()


class _BoundedSSHLineReader:
    """Read bounded raw logical lines and yield only strictly decoded text."""

    def __init__(
        self,
        stream: BinaryIO,
        reporter: SSHInputRejectionReporter,
        chunk_size: int = SSH_READ_CHUNK_BYTES,
    ):
        if chunk_size <= 0:
            raise ValueError("SSH read chunk size must be positive.")
        self._stream = stream
        self._reporter = reporter
        self._chunk_size = chunk_size
        self.max_candidate_bytes_seen = 0

    def __iter__(self) -> Iterator[str]:
        candidate = bytearray()
        discarding = False
        pending_cr = False
        read_chunk = (
            self._stream.read1
            if hasattr(self._stream, "read1")
            else self._stream.read
        )

        def append_segment(segment: bytes) -> None:
            nonlocal discarding
            if discarding or not segment:
                return
            if len(candidate) + len(segment) > MAX_SSH_LOG_LINE_BYTES:
                candidate.clear()
                discarding = True
                self._reporter.record("oversized_line")
                return
            candidate.extend(segment)
            self.max_candidate_bytes_seen = max(
                self.max_candidate_bytes_seen, len(candidate)
            )

        def complete_line() -> str | None:
            nonlocal discarding
            if discarding:
                candidate.clear()
                discarding = False
                return None
            decoded = self._decode_candidate(candidate)
            candidate.clear()
            if decoded is None:
                return None
            return decoded.rstrip()

        while True:
            chunk = read_chunk(self._chunk_size)
            if not chunk:
                if pending_cr or candidate or discarding:
                    decoded = complete_line()
                    if decoded is not None:
                        yield decoded
                return

            offset = 0
            while offset < len(chunk):
                if pending_cr:
                    if chunk[offset] == 0x0A:
                        append_segment(chunk[offset : offset + 1])
                        offset += 1
                    decoded = complete_line()
                    pending_cr = False
                    if decoded is not None:
                        yield decoded
                    if offset == len(chunk):
                        break
                    if chunk[offset - 1] == 0x0A:
                        continue

                cr = chunk.find(b"\r", offset)
                lf = chunk.find(b"\n", offset)
                delimiters = [position for position in (cr, lf) if position >= 0]
                if not delimiters:
                    append_segment(chunk[offset:])
                    break

                delimiter = min(delimiters)
                is_cr = chunk[delimiter] == 0x0D
                append_segment(chunk[offset : delimiter + 1])
                offset = delimiter + 1
                if is_cr:
                    pending_cr = True
                    continue

                decoded = complete_line()
                if decoded is not None:
                    yield decoded

    def _decode_candidate(self, candidate: bytearray) -> str | None:
        try:
            # TextIOWrapper preserves the previous text-mode newline conversion
            # and strict decoding behavior, but only for an already bounded line.
            with io.TextIOWrapper(
                io.BytesIO(candidate),
                encoding=_default_text_encoding(),
                errors="strict",
                newline=None,
            ) as decoded_stream:
                return decoded_stream.read()
        except UnicodeDecodeError:
            self._reporter.record("invalid_encoding")
            return None


def _wait_for_child(process, timeout: float | None):
    try:
        if timeout is None:
            return process.wait(), True, False
        return process.wait(timeout=timeout), True, False
    except subprocess.TimeoutExpired:
        return None, False, True
    except Exception:
        return None, False, False


def _cleanup_child(process):
    """Terminate, escalate once if needed, and attempt to reap the child."""
    cleanup_failed = False
    terminate_requested = False
    kill_requested = False

    try:
        returncode = process.poll()
    except Exception:
        returncode = None
        cleanup_failed = True

    if returncode is not None:
        waited_returncode, waited, _timed_out = _wait_for_child(process, None)
        if waited:
            returncode = waited_returncode
        else:
            cleanup_failed = True
        # Popen.poll() has already collected the exit status on the normal
        # implementation; wait() is still attempted for the ownership contract.
        return returncode, True, False, False, cleanup_failed

    try:
        process.terminate()
        terminate_requested = True
    except ProcessLookupError:
        # The process may have exited after poll(). Still attempt wait below.
        pass
    except Exception:
        cleanup_failed = True

    returncode, waited, _timed_out = _wait_for_child(
        process, TERMINATE_WAIT_SECONDS
    )
    if waited:
        return returncode, True, terminate_requested, kill_requested, cleanup_failed
    # A timeout means the child remained alive. If wait itself failed, kill is
    # also the safest bounded cleanup attempt because its state is unknown.
    try:
        process.kill()
        kill_requested = True
    except ProcessLookupError:
        pass
    except Exception:
        cleanup_failed = True

    returncode, waited, timed_out = _wait_for_child(process, KILL_WAIT_SECONDS)
    if not waited:
        cleanup_failed = True
    return (
        returncode,
        waited,
        terminate_requested,
        kill_requested,
        cleanup_failed,
    )


def stream_ssh_logs(
    host: str = DEFAULT_HOST,
    user: str = DEFAULT_USER,
    key_path: str = DEFAULT_KEY,
    rejection_reporter: SSHInputRejectionReporter | None = None,
) -> Iterator[str]:
    command = [
        "ssh",
        "-i",
        key_path,
        "-o",
        "BatchMode=yes",
        "-o",
        "ConnectTimeout=5",
        f"{user}@{host}",
        "journalctl",
        "-u",
        "ssh",
        "-f",
        "-n",
        "0",
        "--no-pager",
    ]

    try:
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            bufsize=0,
        )
    except OSError:
        raise SSHCollectorStartError() from None

    owns_reporter = rejection_reporter is None
    reporter = rejection_reporter or SSHInputRejectionReporter()
    normal_eof = False
    try:
        if process.stdout is None:
            raise RuntimeError("Unable to read SSH log stream.")
        yield from _BoundedSSHLineReader(process.stdout, reporter)
        normal_eof = True
    finally:
        returncode, reaped, terminate_requested, kill_requested, cleanup_failed = (
            _cleanup_child(process)
        )
        try:
            if process.stdout is not None:
                process.stdout.close()
        except Exception:
            cleanup_failed = True

        # All process and pipe cleanup occurs before console reporting, so a
        # broken output stream cannot leave the child running or unreaped.
        if kill_requested:
            print("SSH log collector required forced termination.")
        if cleanup_failed or not reaped:
            print("SSH log collector cleanup failed; child exit could not be confirmed.")

        if normal_eof:
            if returncode == 0:
                print("SSH log stream ended.")
            elif returncode is not None:
                print(f"SSH log collector exited unexpectedly (code {returncode}).")
            else:
                print("SSH log collector exited unexpectedly.")

        if owns_reporter:
            reporter.report_summary()
