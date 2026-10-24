import ipaddress
import re
from dataclasses import dataclass


@dataclass
class SSHEvent:
    event_type: str
    source_ip: str
    username: str | None
    raw_line: str


_LOGIN_PATTERNS = (
    (
        "LOGIN_SUCCESS",
        re.compile(
            r"Accepted (?:password|publickey) for (?P<username>\S+) from "
            r"(?P<source_ip>\S+) port (?P<port>[0-9]+)(?=\s|$)"
        ),
    ),
    (
        "LOGIN_FAILED",
        re.compile(
            r"Failed password for (?:invalid user )?(?P<username>\S+) from "
            r"(?P<source_ip>\S+) port (?P<port>[0-9]+)(?=\s|$)"
        ),
    ),
)
_PREAUTH_PATTERN = re.compile(
    r"Unable to negotiate with (?P<source_ip>\S+) port (?P<port>[0-9]+):"
    r"(?P<details>[^\r\n]*\[preauth\])"
)
_CONNECTION_CLOSED_PATTERN = re.compile(
    r"Connection closed by (?P<source_ip>\S+) port (?P<port>[0-9]+)(?=\s|$)"
)


def _validated_source_and_port(match: re.Match[str]) -> tuple[str, int] | None:
    try:
        source_ip = str(ipaddress.IPv4Address(match.group("source_ip")))
        port = int(match.group("port"), 10)
    except (ipaddress.AddressValueError, ValueError):
        return None

    if not 1 <= port <= 65535:
        return None

    return source_ip, port


def _event_from_match(
    line: str,
    event_type: str,
    match: re.Match[str],
    username: str | None,
) -> SSHEvent | None:
    validated = _validated_source_and_port(match)
    if validated is None:
        return None

    source_ip, _port = validated
    return SSHEvent(event_type, source_ip, username, line.strip())


def parse_ssh_line(line: str) -> SSHEvent | None:
    """Parse supported sshd forms, taking source only from their source field."""
    for event_type, pattern in _LOGIN_PATTERNS:
        match = pattern.search(line)
        if match is not None:
            return _event_from_match(
                line, event_type, match, match.group("username")
            )

    match = _PREAUTH_PATTERN.search(line)
    if match is not None:
        return _event_from_match(line, "SSH_PREAUTH", match, None)

    match = _CONNECTION_CLOSED_PATTERN.search(line)
    if match is not None:
        return _event_from_match(line, "CONNECTION_CLOSED", match, None)

    return None
