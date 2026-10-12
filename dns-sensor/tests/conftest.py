import sys
from pathlib import Path
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


@pytest.fixture
def record():
    return {"observed_at": "2026-01-01T00:00:00Z", "queried_domain": "Login.Example.test.",
            "query_type": "A", "response_status": "NOERROR", "resolved_addresses": ["192.0.2.10"]}


@pytest.fixture(autouse=True)
def forbid_network(monkeypatch):
    import socket

    def forbidden(*args, **kwargs):
        raise AssertionError("Network access is forbidden in DNS sensor tests.")

    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
