import re
from dataclasses import dataclass


@dataclass
class SSHEvent:
    event_type: str
    source_ip: str
    username: str | None
    raw_line: str


IP_PATTERN = r"(?:\d{1,3}\.){3}\d{1,3}"


def parse_ssh_line(line: str) -> SSHEvent | None:
    ip_match = re.search(IP_PATTERN, line)

    if not ip_match:
        return None

    source_ip = ip_match.group(0)

    if "Accepted password for" in line or "Accepted publickey for" in line:
        user_match = re.search(r"Accepted \w+ for (\S+) from", line)

        return SSHEvent(
            event_type="LOGIN_SUCCESS",
            source_ip=source_ip,
            username=user_match.group(1) if user_match else None,
            raw_line=line.strip(),
        )

    if "Failed password for" in line:
        user_match = re.search(
            r"Failed password for (?:invalid user )?(\S+) from",
            line,
        )

        return SSHEvent(
            event_type="LOGIN_FAILED",
            source_ip=source_ip,
            username=user_match.group(1) if user_match else None,
            raw_line=line.strip(),
        )

    if "[preauth]" in line or "Unable to negotiate with" in line:
        return SSHEvent(
            event_type="SSH_PREAUTH",
            source_ip=source_ip,
            username=None,
            raw_line=line.strip(),
        )

    if "Connection closed by" in line:
        return SSHEvent(
            event_type="CONNECTION_CLOSED",
            source_ip=source_ip,
            username=None,
            raw_line=line.strip(),
        )

    return None
