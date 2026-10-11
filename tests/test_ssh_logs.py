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
