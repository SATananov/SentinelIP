"""Collection only: adapters yield unparsed JSON lines, never fabricate DNS facts."""
from typing import Protocol, Iterable, TextIO
from .parser import MAX_LINE


class DnsEventSource(Protocol):
    source: str

    def events(self) -> Iterable[str]: ...


class JsonLineSource:
    def __init__(self, stream: TextIO, source="stdin-jsonl"):
        self.stream = stream
        self.source = source

    def events(self):
        # Finite work per invocation; oversized records terminate this source.
        for _ in range(10000):
            line = self.stream.readline(MAX_LINE + 1)
            if not line:
                return
            yield line
            if len(line) > MAX_LINE:
                return
