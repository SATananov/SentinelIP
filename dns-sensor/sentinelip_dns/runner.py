import argparse
import sys
from dataclasses import dataclass

from .api import DnsClient
from .config import ConfigError, load_config
from .normalize import EvidenceError
from .parser import parse
from .sources import JsonLineSource


@dataclass
class RunResult:
    accepted: int = 0
    malformed: int = 0
    failed: int = 0
    stopped: bool = False


def run(config, source, client, report=lambda message: None):
    result = RunResult()
    if not config.enabled:
        return result
    try:
        for line in source.events():
            try:
                event = parse(line, source.source)
            except EvidenceError:
                result.malformed += 1
                report("Invalid DNS record skipped.")
                continue
            sent = client.send(event)
            if sent.ok:
                result.accepted += 1
            else:
                result.failed += 1
                report("DNS submission failed; stopping source. Event dropped.")
                # Avoid retry storms across a stream when the API is unavailable.
                break
    except KeyboardInterrupt:
        result.stopped = True
    return result


def main(argv=None):
    args_parser = argparse.ArgumentParser(description="Submit structured local DNS evidence.")
    args_parser.add_argument("--config", required=True)
    args_parser.add_argument("--file", help="JSON-lines evidence file; defaults to stdin")
    args = args_parser.parse_args(argv)
    try:
        config = load_config(args.config)
        if not config.enabled:
            print("DNS sensor disabled.")
            return 0
        client = DnsClient(config)
        report = lambda message: print(message, file=sys.stderr)
        if args.file:
            with open(args.file, encoding="utf-8") as stream:
                result = run(config, JsonLineSource(stream, "file-jsonl"), client, report)
        else:
            result = run(config, JsonLineSource(sys.stdin), client, report)
        print(f"Accepted: {result.accepted}; malformed: {result.malformed}; failed: {result.failed}")
        return 130 if result.stopped else int(bool(result.failed or result.malformed))
    except KeyboardInterrupt:
        return 130
    except (ConfigError, OSError, UnicodeError):
        print("Cannot read sensor configuration or evidence.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
