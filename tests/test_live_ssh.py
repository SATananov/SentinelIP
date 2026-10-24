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

    def read1(self, size):
        self.maximum_requested = max(self.maximum_requested, size)
        chunk = self.data[self.offset : self.offset + size]
        self.offset += len(chunk)
        return chunk


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
    class Process:
        stdout = ChunkedBytes(b"valid\n" + b"x" * 8193 + b"\nnext\n")
        terminated = False

        def terminate(self):
            self.terminated = True

    process = Process()
    popen_options = {}

    def popen(_command, **kwargs):
        popen_options.update(kwargs)
        return process

    monkeypatch.setattr("collectors.live_ssh.subprocess.Popen", popen)
    reporter = SSHInputRejectionReporter()

    assert list(stream_ssh_logs(rejection_reporter=reporter)) == ["valid", "next"]
    assert popen_options["stdout"] is not None
    assert popen_options["bufsize"] == 0
    assert "text" not in popen_options
    assert "encoding" not in popen_options
    assert process.terminated
    assert reporter.counts["oversized_line"] == 1
    capsys.readouterr()  # warnings are fixed; no line content is included


def test_standalone_stream_reports_once_on_generator_finalization(monkeypatch, capsys):
    class Process:
        stdout = ChunkedBytes(b"x" * 8192 + b"\n")

        def terminate(self):
            pass

    monkeypatch.setattr(
        "collectors.live_ssh.subprocess.Popen",
        lambda *_args, **_kwargs: Process(),
    )

    assert list(stream_ssh_logs()) == []
    output = capsys.readouterr().out
    assert output.count("raw log line exceeded") == 1
    assert output.count("SSH input rejection totals:") == 1
    assert "x" * 20 not in output
