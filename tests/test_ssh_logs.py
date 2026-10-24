from dataclasses import fields

import pytest

from collectors.ssh_logs import parse_ssh_line


def test_login_success_password():
    line = (
        "Oct 10 08:07:59 ubuntu-lab sshd[883]: "
        "Accepted password for tanashi from 192.168.122.1 port 41872 ssh2"
    )

    event = parse_ssh_line(line)

    assert event is not None
    assert event.event_type == "LOGIN_SUCCESS"
    assert event.source_ip == "192.168.122.1"
    assert event.username == "tanashi"


def test_login_success_publickey():
    line = (
        "Oct 11 04:28:43 ubuntu-lab sshd[1056]: "
        "Accepted publickey for tanashi from 192.168.122.1 port 46192 ssh2"
    )

    event = parse_ssh_line(line)

    assert event is not None
    assert event.event_type == "LOGIN_SUCCESS"
    assert event.source_ip == "192.168.122.1"
    assert event.username == "tanashi"


def test_failed_password_invalid_user():
    line = (
        "Oct 10 08:40:00 ubuntu-lab sshd[1200]: "
        "Failed password for invalid user admin from 10.10.10.50 port 55555 ssh2"
    )

    event = parse_ssh_line(line)

    assert event is not None
    assert event.event_type == "LOGIN_FAILED"
    assert event.source_ip == "10.10.10.50"
    assert event.username == "admin"


def test_ssh_preauth():
    line = (
        "Oct 10 08:33:42 ubuntu-lab sshd[1068]: "
        "Unable to negotiate with 192.168.122.1 port 34572: "
        "no matching host key type found [preauth]"
    )

    event = parse_ssh_line(line)

    assert event is not None
    assert event.event_type == "SSH_PREAUTH"
    assert event.source_ip == "192.168.122.1"


def test_connection_closed():
    line = (
        "Oct 10 08:33:42 ubuntu-lab sshd[1063]: "
        "Connection closed by 192.168.122.1 port 34540"
    )

    event = parse_ssh_line(line)

    assert event is not None
    assert event.event_type == "CONNECTION_CLOSED"
    assert event.source_ip == "192.168.122.1"


def test_irrelevant_line_returns_none():
    line = "Oct 10 08:00:00 ubuntu-lab systemd[1]: Started some service"

    event = parse_ssh_line(line)

    assert event is None


def test_ip_shaped_invalid_username_does_not_replace_source():
    line = (
        "Failed password for invalid user 192.0.2.99 from "
        "203.0.113.7 port 55555 ssh2"
    )

    event = parse_ssh_line(line)

    assert event is not None
    assert event.username == "192.0.2.99"
    assert event.source_ip == "203.0.113.7"


@pytest.mark.parametrize(
    ("line", "expected_type", "expected_user", "expected_source"),
    [
        (
            "Failed password for alice from 192.0.2.8 port 22 ssh2",
            "LOGIN_FAILED",
            "alice",
            "192.0.2.8",
        ),
        (
            "Failed password for invalid user host.name from 203.0.113.9 "
            "port 65535 ssh2",
            "LOGIN_FAILED",
            "host.name",
            "203.0.113.9",
        ),
        (
            "Accepted password for 192.0.2.99 from 203.0.113.7 port 22 ssh2",
            "LOGIN_SUCCESS",
            "192.0.2.99",
            "203.0.113.7",
        ),
        (
            "Accepted publickey for tanashi from 0.0.0.0 port 1 ssh2",
            "LOGIN_SUCCESS",
            "tanashi",
            "0.0.0.0",
        ),
        (
            "Accepted password for admin from 255.255.255.255 port 65535 ssh2",
            "LOGIN_SUCCESS",
            "admin",
            "255.255.255.255",
        ),
        (
            "Unable to negotiate with 203.0.113.4 port 22: no matching key [preauth]",
            "SSH_PREAUTH",
            None,
            "203.0.113.4",
        ),
        (
            "Connection closed by 203.0.113.5 port 22 [preauth]",
            "CONNECTION_CLOSED",
            None,
            "203.0.113.5",
        ),
    ],
)
def test_supported_forms_use_structural_source(
    line, expected_type, expected_user, expected_source
):
    event = parse_ssh_line(line)

    assert event is not None
    assert event.event_type == expected_type
    assert event.username == expected_user
    assert event.source_ip == expected_source


@pytest.mark.parametrize(
    "line",
    [
        "Failed password for admin from 999.999.999.999 port 22 ssh2",
        "Failed password for admin from 256.1.1.1 port 22 ssh2",
        "Failed password for admin from 1.2.3 port 22 ssh2",
        "Failed password for admin source 203.0.113.7 port 22 ssh2",
        "Failed password for admin from port 22 ssh2",
        "Failed password for admin from 203.0.113.7 ssh2",
        "Failed password for admin from 203.0.113.7 port nope ssh2",
        "Failed password for admin from 203.0.113.7 port 0 ssh2",
        "Failed password for admin from 203.0.113.7 port 65536 ssh2",
        "Failed password for from 203.0.113.7 port 22 ssh2",
        "Accepted keyboard-interactive for admin from 203.0.113.7 port 22 ssh2",
        "Unable to negotiate with 999.1.1.1 port 22: error [preauth]",
        "Unable to negotiate with invalid-address port 22: error [preauth]",
        "Unable to negotiate with 203.0.113.4 port nope: error [preauth]",
        "Unable to negotiate with 203.0.113.4 port 0: error [preauth]",
        "Unable to negotiate with 203.0.113.4 port 65536: error [preauth]",
        "Unable to negotiate with port 22: error [preauth]",
        "Unable to negotiate with 2001:db8::1 port 22: error [preauth]",
        "Unable to negotiate with ::ffff:192.0.2.1 port 22: error [preauth]",
        "random text [preauth] 203.0.113.7",
        "Invalid user admin from 203.0.113.7 port 22",
        "Connection closed by 203.0.113.7 port 65536",
        "Connection closed by 203.0.113.7 port nope",
        "Connection closed by 999.999.999.999 port 22",
        "Connection closed by 2001:db8::1 port 22",
    ],
)
def test_malformed_or_unsupported_forms_return_none(line):
    assert parse_ssh_line(line) is None


def test_prefix_and_other_address_tokens_do_not_affect_source():
    line = (
        "192.0.2.44 host sshd[123]: Failed password for 198.51.100.8 "
        "from 203.0.113.7 port 22 ssh2 note=192.0.2.12"
    )

    event = parse_ssh_line(line)

    assert event is not None
    assert event.username == "198.51.100.8"
    assert event.source_ip == "203.0.113.7"


def test_malformed_expected_source_does_not_fall_back_to_other_ip():
    line = (
        "Failed password for 192.0.2.99 from 999.999.999.999 "
        "port 22 extra=203.0.113.7"
    )
    assert parse_ssh_line(line) is None


def test_preauth_source_comes_only_from_negotiate_with_field():
    line = (
        "192.0.2.44 host sshd[123]: Unable to negotiate with 203.0.113.7 "
        "port 22: peer 198.51.100.5 offered no matching key [preauth]"
    )

    event = parse_ssh_line(line)

    assert event is not None
    assert event.event_type == "SSH_PREAUTH"
    assert event.source_ip == "203.0.113.7"


def test_parser_output_shape_and_raw_line_behavior_are_unchanged():
    original = "  Accepted password for user from 203.0.113.1 port 22 ssh2  "
    event = parse_ssh_line(original)

    assert event is not None
    assert [field.name for field in fields(event)] == [
        "event_type",
        "source_ip",
        "username",
        "raw_line",
    ]
    assert event.raw_line == original.strip()
