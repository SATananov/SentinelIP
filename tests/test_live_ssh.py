import subprocess
from types import SimpleNamespace

import pytest

import app
from collectors.live_ssh import (
    SSHInputRejectionReporter,
    _BoundedSSHLineReader,
    stream_ssh_logs,
)


class ChunkedBytes:
    def __init__(self, data):
        self.data = data
        self.offset = 0
        self.maximum_requested = 0
        self.closed = False

    def read1(self, size):
        self.maximum_requested = max(self.maximum_requested, size)
        chunk = self.data[self.offset : self.offset + size]
        self.offset += len(chunk)
        return chunk

    def close(self):
        self.closed = True


class FakeProcess:
    def __init__(self, data=b"", returncode=0, wait_outcomes=None):
        self.stdout = ChunkedBytes(data)
        self.returncode = returncode
        self.wait_outcomes = list(wait_outcomes or [])
        self.calls = []

    def poll(self):
        self.calls.append(("poll",))
        return self.returncode

    def wait(self, timeout=None):
        self.calls.append(("wait", timeout))
        outcome = self.wait_outcomes.pop(0) if self.wait_outcomes else None
        if isinstance(outcome, BaseException):
            raise outcome
        if outcome is not None:
            self.returncode = outcome
        return self.returncode

    def terminate(self):
        self.calls.append(("terminate",))
        self.returncode = -15

    def kill(self):
        self.calls.append(("kill",))
        self.returncode = -9


class ReadOnlyChunkedBytes:
    def __init__(self, data):
        self.data = data
        self.offset = 0

    def read(self, size):
        chunk = self.data[self.offset : self.offset + size]
        self.offset += len(chunk)
        return chunk


class GeneratedOversizeLine:
    def __init__(self, byte_count):
        self.remaining = byte_count
        self.suffix = b"\nvalid\n"
        self.maximum_returned = 0

    def read1(self, size):
        if self.remaining:
            count = min(size, self.remaining)
            self.remaining -= count
            chunk = b"x" * count
        elif self.suffix:
            chunk = self.suffix[:size]
            self.suffix = self.suffix[size:]
        else:
            return b""
        self.maximum_returned = max(self.maximum_returned, len(chunk))
        return chunk


def read_lines(data, chunk_size=1024):
    stream = ChunkedBytes(data)
    reporter = SSHInputRejectionReporter()
    reader = _BoundedSSHLineReader(stream, reporter, chunk_size=chunk_size)
    return list(reader), reader, reporter, stream


def test_short_exact_limit_and_over_limit_lines(capsys):
    exact = b"x" * 8191 + b"\n"
    lines, reader, reporter, _ = read_lines(b"short\n" + exact + b"y" * 8192 + b"\n")

    assert lines == ["short", "x" * 8191]
    assert reader.max_candidate_bytes_seen == 8192
    assert reporter.counts["oversized_line"] == 1
    assert "raw log line exceeded" in capsys.readouterr().out


def test_crlf_bytes_count_toward_limit():
    lines, _reader, reporter, _stream = read_lines(
        b"a" * 8190 + b"\r\n" + b"b" * 8191 + b"\r\n"
    )

    assert lines == ["a" * 8190]
    assert reporter.counts["oversized_line"] == 1


@pytest.mark.parametrize(
    ("data", "expected_line", "oversized"),
    [
        (b"x" * 8191 + b"\n", "x" * 8191, False),
        (b"x" * 8192 + b"\n", None, True),
        (b"x" * 8190 + b"\r\n", "x" * 8190, False),
        (b"x" * 8191 + b"\r\n", None, True),
        (b"x" * 8191 + b"\r", "x" * 8191, False),
        (b"x" * 8192 + b"\r", None, True),
        (b"x" * 8192, "x" * 8192, False),
        (b"x" * 8193, None, True),
    ],
)
def test_exact_raw_limit_for_all_terminators(data, expected_line, oversized):
    lines, reader, reporter, stream = read_lines(data)

    assert lines == ([] if oversized else [expected_line])
    assert reporter.counts["oversized_line"] == int(oversized)
    assert reader.max_candidate_bytes_seen <= 8192
    assert stream.maximum_requested <= 1024


def test_crlf_spanning_chunks_and_lone_cr_preserve_universal_newlines():
    lines, _reader, reporter, _stream = read_lines(
        b"one\r\ntwo\rthree\n", chunk_size=4
    )

    assert lines == ["one", "two", "three"]
    assert reporter.counts["oversized_line"] == 0


def test_split_oversized_line_is_discarded_and_next_line_is_recovered():
    data = b"z" * 8192 + b"\nvalid\n"
    lines, reader, reporter, stream = read_lines(data, chunk_size=1024)

    assert lines == ["valid"]
    assert reader.max_candidate_bytes_seen == 8192
    assert reporter.counts["oversized_line"] == 1
    assert stream.maximum_requested == 1024


def test_in_bound_newline_can_span_read_chunks():
    data = b"a" * 8191 + b"\n"
    lines, reader, reporter, _stream = read_lines(data, chunk_size=8191)

    assert lines == ["a" * 8191]
    assert reader.max_candidate_bytes_seen == 8192
    assert reporter.counts["oversized_line"] == 0


def test_raw_file_read_fallback_keeps_bounded_chunking():
    stream = ReadOnlyChunkedBytes(b"one\ntwo\n")
    reader = _BoundedSSHLineReader(stream, SSHInputRejectionReporter(), chunk_size=3)

    assert list(reader) == ["one", "two"]
    assert reader.max_candidate_bytes_seen == 4


def test_overflow_newline_and_valid_line_in_same_chunk_resynchronize():
    # The first 8192-byte chunk leaves a candidate exactly at the cap. The
    # next chunk contains its overflow newline followed by a valid line.
    data = b"x" * 8192 + b"\nvalid\n"
    lines, reader, reporter, _stream = read_lines(data, chunk_size=8192)

    assert lines == ["valid"]
    assert reader.max_candidate_bytes_seen == 8192
    assert reporter.counts["oversized_line"] == 1


def test_consecutive_oversized_lines_then_valid_line():
    lines, _reader, reporter, _stream = read_lines(
        b"a" * 8193 + b"\n" + b"b" * 9000 + b"\nlast\n"
    )

    assert lines == ["last"]
    assert reporter.counts["oversized_line"] == 2


@pytest.mark.parametrize(
    ("oversized", "valid", "rejected_count"),
    [
        (b"x" * 8192 + b"\n", b"good\r\n", 1),
        (b"x" * 8191 + b"\r\n", b"good\n", 1),
        (b"x" * 8192 + b"\r", b"good\n", 1),
        (
            b"x" * 8192 + b"\n" + b"y" * 8191 + b"\r\n"
            + b"z" * 8192 + b"\r",
            b"good\n",
            3,
        ),
    ],
)
def test_mixed_oversize_terminators_resynchronize(oversized, valid, rejected_count):
    lines, _reader, reporter, _stream = read_lines(oversized + valid, chunk_size=7)

    assert lines == ["good"]
    assert reporter.counts["oversized_line"] == rejected_count


def test_large_generated_line_does_not_grow_candidate_and_recovers():
    stream = GeneratedOversizeLine(2 * 1024 * 1024)
    reporter = SSHInputRejectionReporter()
    reader = _BoundedSSHLineReader(stream, reporter)

    assert list(reader) == ["valid"]
    assert reader.max_candidate_bytes_seen <= 8192
    assert stream.maximum_returned <= 1024
    assert reporter.counts["oversized_line"] == 1


def test_eof_emits_only_in_bound_unterminated_final_line():
    lines, _reader, reporter, _stream = read_lines(b"valid final")
    assert lines == ["valid final"]
    assert reporter.counts["oversized_line"] == 0

    lines, reader, reporter, _stream = read_lines(b"u" * 8193)
    assert lines == []
    assert reader.max_candidate_bytes_seen == 8192
    assert reporter.counts["oversized_line"] == 1


def test_multiple_lines_in_one_chunk_and_invalid_decode_recovery(capsys):
    lines, _reader, reporter, _stream = read_lines(
        "é\n".encode("utf-8") + b"\xffbad\n" + b"next\n",
        chunk_size=1024,
    )

    assert lines == ["é", "next"]
    assert reporter.counts["invalid_encoding"] == 1
    output = capsys.readouterr().out
    assert "invalid text encoding" in output
    assert "bad" not in output


@pytest.mark.parametrize("terminator", [b"\n", b"\r\n", b"\r"])
def test_invalid_decode_line_is_rejected_for_each_terminator(terminator):
    lines, _reader, reporter, _stream = read_lines(
        b"\xffbad" + terminator + b"good\n", chunk_size=1
    )

    assert lines == ["good"]
    assert reporter.counts["invalid_encoding"] == 1


def test_rejection_warnings_are_once_per_category_and_counts_are_cumulative(capsys):
    reporter = SSHInputRejectionReporter()
    reporter.record("oversized_line")
    reporter.record("oversized_line")
    reporter.record("invalid_encoding")
    reporter.record("oversized_username")
    reporter.report_summary()
    output = capsys.readouterr().out

    assert output.count("raw log line exceeded") == 1
    assert output.count("invalid text encoding") == 1
    assert output.count("username exceeded") == 1
    assert "oversized_line=2" in output
    assert "invalid_encoding=1" in output
    assert "oversized_username=1" in output
    assert "bad" not in output


def test_stream_keeps_text_generator_contract_with_binary_subprocess_stdout(
    monkeypatch, capsys
):
    process = FakeProcess(
        b"valid\n" + b"x" * 8193 + b"\nnext\n", returncode=0
    )
    popen_options = {}
    popen_command = []
    popen_count = 0

    def popen(command, **kwargs):
        nonlocal popen_count
        popen_count += 1
        popen_command.extend(command)
        popen_options.update(kwargs)
        return process

    monkeypatch.setattr("collectors.live_ssh.subprocess.Popen", popen)
    reporter = SSHInputRejectionReporter()

    assert list(stream_ssh_logs(rejection_reporter=reporter)) == ["valid", "next"]
    assert popen_options["stdout"] is subprocess.PIPE
    assert popen_options["stderr"] is subprocess.DEVNULL
    assert popen_options["bufsize"] == 0
    assert "stdin" not in popen_options
    assert "shell" not in popen_options
    assert "text" not in popen_options
    assert "encoding" not in popen_options
    assert popen_command == [
        "ssh", "-i", "/home/tanashi/.ssh/sentinelip_ed25519",
        "-o", "BatchMode=yes", "-o", "ConnectTimeout=5",
        "-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=3",
        "tanashi@192.168.122.25", "journalctl", "-u", "ssh", "-f",
        "-n", "0", "--no-pager",
    ]
    assert not any(call[0] in {"terminate", "kill"} for call in process.calls)
    assert popen_count == 1
    assert ("wait", None) in process.calls
    assert process.stdout.closed
    assert reporter.counts["oversized_line"] == 1
    output = capsys.readouterr().out
    assert "SSH log stream ended." in output
    assert "x" * 20 not in output


def test_standalone_stream_reports_once_on_generator_finalization(monkeypatch, capsys):
    process = FakeProcess(b"x" * 8192 + b"\n", returncode=0)

    monkeypatch.setattr(
        "collectors.live_ssh.subprocess.Popen",
        lambda *_args, **_kwargs: process,
    )

    assert list(stream_ssh_logs()) == []
    output = capsys.readouterr().out
    assert output.count("raw log line exceeded") == 1
    assert output.count("SSH input rejection totals:") == 1
    assert "x" * 20 not in output
    assert process.stdout.closed


def test_nonzero_child_exit_is_reaped_and_reported_safely(monkeypatch, capsys):
    process = FakeProcess(b"", returncode=255)
    popen_count = 0

    def popen(*_args, **_kwargs):
        nonlocal popen_count
        popen_count += 1
        return process

    monkeypatch.setattr(
        "collectors.live_ssh.subprocess.Popen",
        popen,
    )

    assert list(stream_ssh_logs()) == []
    output = capsys.readouterr().out
    assert "SSH log collector exited unexpectedly (code 255)." in output
    assert "stderr" not in output
    assert ("wait", None) in process.calls
    assert not any(call[0] in {"terminate", "kill"} for call in process.calls)
    assert popen_count == 1
    assert process.stdout.closed


def test_generator_close_terminates_waits_and_closes_stdout(monkeypatch, capsys):
    process = FakeProcess(b"first\nsecond\n", returncode=None)
    monkeypatch.setattr(
        "collectors.live_ssh.subprocess.Popen",
        lambda *_args, **_kwargs: process,
    )

    stream = stream_ssh_logs(rejection_reporter=SSHInputRejectionReporter())
    assert next(stream) == "first"
    stream.close()

    assert process.calls.index(("terminate",)) < process.calls.index(
        ("wait", 2.0)
    )
    assert process.stdout.closed
    assert "unexpectedly" not in capsys.readouterr().out


def test_terminate_timeout_escalates_once_to_kill(monkeypatch, capsys):
    process = FakeProcess(
        b"first\n",
        returncode=None,
        wait_outcomes=[subprocess.TimeoutExpired("ssh", 2.0), -9],
    )
    monkeypatch.setattr(
        "collectors.live_ssh.subprocess.Popen",
        lambda *_args, **_kwargs: process,
    )

    stream = stream_ssh_logs(rejection_reporter=SSHInputRejectionReporter())
    assert next(stream) == "first"
    stream.close()

    assert process.calls.count(("terminate",)) == 1
    assert process.calls.count(("kill",)) == 1
    assert process.calls.count(("wait", 2.0)) == 2
    assert process.stdout.closed
    assert "forced termination" in capsys.readouterr().out


def test_final_kill_wait_timeout_is_reported_without_looping(monkeypatch, capsys):
    process = FakeProcess(
        b"first\n",
        returncode=None,
        wait_outcomes=[
            subprocess.TimeoutExpired("ssh", 2.0),
            subprocess.TimeoutExpired("ssh", 2.0),
        ],
    )
    monkeypatch.setattr(
        "collectors.live_ssh.subprocess.Popen",
        lambda *_args, **_kwargs: process,
    )

    stream = stream_ssh_logs(rejection_reporter=SSHInputRejectionReporter())
    assert next(stream) == "first"
    stream.close()

    output = capsys.readouterr().out
    assert "cleanup failed" in output
    assert process.calls.count(("kill",)) == 1
    assert process.calls.count(("wait", 2.0)) == 2
    assert process.stdout.closed


def test_process_lookup_race_still_attempts_wait(monkeypatch, capsys):
    process = FakeProcess(b"first\n", returncode=None)

    def terminate_race():
        process.calls.append(("terminate",))
        raise ProcessLookupError()

    process.terminate = terminate_race
    process.wait_outcomes = [0]
    monkeypatch.setattr(
        "collectors.live_ssh.subprocess.Popen",
        lambda *_args, **_kwargs: process,
    )

    stream = stream_ssh_logs(rejection_reporter=SSHInputRejectionReporter())
    assert next(stream) == "first"
    stream.close()

    assert ("wait", 2.0) in process.calls
    assert process.stdout.closed
    assert "cleanup failed" not in capsys.readouterr().out


def test_start_failure_uses_fixed_safe_error(monkeypatch):
    def fail_start(*_args, **_kwargs):
        raise OSError("secret key path or host details")

    monkeypatch.setattr("collectors.live_ssh.subprocess.Popen", fail_start)
    with pytest.raises(RuntimeError, match="^Unable to start SSH log collector\\.$"):
        next(stream_ssh_logs(key_path="/secret/private-key"))


def test_stdout_close_failure_happens_after_reap_and_is_best_effort(
    monkeypatch, capsys
):
    process = FakeProcess(b"", returncode=0)

    def fail_close():
        process.calls.append(("close",))
        raise OSError("descriptor close failed")

    process.stdout.close = fail_close
    monkeypatch.setattr(
        "collectors.live_ssh.subprocess.Popen",
        lambda *_args, **_kwargs: process,
    )

    assert list(stream_ssh_logs(rejection_reporter=SSHInputRejectionReporter())) == []
    assert process.calls.index(("wait", None)) < process.calls.index(("close",))
    assert "cleanup failed" in capsys.readouterr().out


def test_report_failure_cannot_skip_child_cleanup(monkeypatch):
    process = FakeProcess(b"", returncode=0)
    monkeypatch.setattr(
        "collectors.live_ssh.subprocess.Popen",
        lambda *_args, **_kwargs: process,
    )

    def report_failure(_self):
        raise RuntimeError("report failed")

    monkeypatch.setattr(SSHInputRejectionReporter, "report_summary", report_failure)
    with pytest.raises(RuntimeError, match="report failed"):
        list(stream_ssh_logs())

    assert ("wait", None) in process.calls
    assert process.stdout.closed


@pytest.mark.parametrize("consumer_error", [ValueError("consumer failure"), KeyboardInterrupt()])
def test_app_closes_stream_after_consumer_failure_or_keyboard_interrupt(
    monkeypatch, capsys, consumer_error
):
    process = FakeProcess(b"valid\n", returncode=None)
    monkeypatch.setattr(
        "collectors.live_ssh.subprocess.Popen",
        lambda *_args, **_kwargs: process,
    )
    monkeypatch.setattr(app, "initialize_database", lambda: None)

    def parse_then_fail(_line):
        raise consumer_error

    monkeypatch.setattr(app, "parse_ssh_line", parse_then_fail)

    app.main()

    assert ("terminate",) in process.calls
    assert ("wait", 2.0) in process.calls
    assert process.stdout.closed
    output = capsys.readouterr().out
    assert "unexpectedly" not in output
    if isinstance(consumer_error, KeyboardInterrupt):
        assert "SentinelIP stopped." in output


@pytest.mark.parametrize("failure_stage", ["detector", "persistence"])
def test_app_closes_stream_after_detector_or_persistence_failure(
    monkeypatch, capsys, failure_stage
):
    process = FakeProcess(b"valid\n", returncode=None)
    monkeypatch.setattr(
        "collectors.live_ssh.subprocess.Popen",
        lambda *_args, **_kwargs: process,
    )
    monkeypatch.setattr(app, "initialize_database", lambda: None)
    monkeypatch.setattr(
        app,
        "parse_ssh_line",
        lambda _line: SimpleNamespace(
            event_type="LOGIN_FAILED", source_ip="203.0.113.7", username="admin"
        ),
    )

    class Detector:
        def __init__(self, **_kwargs):
            pass

        def analyze(self, **_kwargs):
            if failure_stage == "detector":
                raise RuntimeError("detector failed")
            return SimpleNamespace(
                severity="INFO", count=1, message="SSH login failed"
            )

    monkeypatch.setattr(app, "SSHDetector", Detector)
    save_calls = []

    def save(**kwargs):
        save_calls.append(kwargs)
        if failure_stage == "persistence":
            raise RuntimeError("save failed")

    monkeypatch.setattr(app, "save_event", save)

    app.main()

    assert ("terminate",) in process.calls
    assert ("wait", 2.0) in process.calls
    assert process.stdout.closed
    assert len(save_calls) == int(failure_stage == "persistence")
    output = capsys.readouterr().out
    assert "unexpectedly" not in output
