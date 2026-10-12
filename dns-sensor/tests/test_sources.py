from io import StringIO
from sentinelip_dns.sources import JsonLineSource


def test_lines_are_untouched():
    source = JsonLineSource(StringIO("first\nsecond\n"), "file-jsonl")
    assert list(source.events()) == ["first\n", "second\n"]
    assert source.source == "file-jsonl"


def test_oversized_record_stops_without_splitting():
    source = JsonLineSource(StringIO("x"*70000 + "\n{}\n"))
    assert list(map(len, source.events())) == [65537]


def test_record_limit():
    assert len(list(JsonLineSource(StringIO("{}\n"*10001)).events())) == 10000
