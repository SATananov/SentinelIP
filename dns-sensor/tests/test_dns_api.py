import json
from http.client import BadStatusLine
from unittest.mock import Mock
from urllib.error import HTTPError, URLError
from urllib.request import Request
import pytest
from sentinelip_dns.api import DnsClient, _NoRedirect
from sentinelip_dns.config import Config
from sentinelip_dns.parser import parse


def response(status):
    result = Mock()
    result.__enter__ = Mock(return_value=Mock(status=status))
    result.__exit__ = Mock(return_value=False)
    return result


def test_authenticated_payload(record):
    opener = Mock()
    opener.open.return_value = response(202)
    client = DnsClient(Config(7, "secret-token", enabled=True), opener=opener)
    event = parse(json.dumps(record), "fixture-jsonl")
    assert client.send(event).ok
    request = opener.open.call_args.args[0]
    assert request.full_url == "http://127.0.0.1:8000/telemetry/dns"
    assert request.method == "POST"
    assert request.get_header("Content-type") == "application/json"
    assert request.get_header("X-sentinelip-sensor-id") == "7"
    assert request.get_header("X-sentinelip-sensor-token") == "secret-token"
    assert b"secret-token" not in request.data
    assert json.loads(request.data) == event.payload()
    assert opener.open.call_args.kwargs == {"timeout": 5}


@pytest.mark.parametrize("status,attempts", [(401, 1), (403, 1), (422, 1), (500, 3), (503, 3), (302, 1), (429, 1)])
def test_http_errors(record, status, attempts, capsys):
    opener, sleep = Mock(), Mock()
    opener.open.side_effect = lambda *a, **k: (_ for _ in ()).throw(HTTPError("http://localhost", status, "secret-token", {}, None))
    result = DnsClient(Config(1, "secret-token", enabled=True), opener=opener, sleep=sleep).send(parse(json.dumps(record), "fixture-jsonl"))
    assert not result.ok and result.status == status and result.attempts == attempts
    assert sleep.call_count == attempts - 1
    assert "secret-token" not in repr(result) + capsys.readouterr().err


@pytest.mark.parametrize("error", [TimeoutError("secret-token"), URLError("secret-token"), ConnectionError("secret-token"), BadStatusLine("secret-token")])
def test_connection_failure(record, error):
    opener, sleep = Mock(), Mock()
    opener.open.side_effect = error
    result = DnsClient(Config(1, "secret-token", enabled=True), opener=opener, sleep=sleep).send(parse(json.dumps(record), "fixture-jsonl"))
    assert result.attempts == 3 and result.code == "connection_failure"
    assert len({call.args[0].data for call in opener.open.call_args_list}) == 1
    assert [c.args[0] for c in sleep.call_args_list] == [1, 2]
    assert "secret-token" not in repr(result)


def test_retry_success(record):
    opener = Mock()
    opener.open.side_effect = [response(500), response(202)]
    result = DnsClient(Config(1, "token", enabled=True), opener=opener, sleep=Mock()).send(parse(json.dumps(record), "fixture-jsonl"))
    assert result.ok and result.attempts == 2
    assert opener.open.call_args_list[0].args[0].data == opener.open.call_args_list[1].args[0].data


def test_disabled(record):
    opener = Mock()
    assert DnsClient(Config(1, "token"), opener=opener).send(parse(json.dumps(record), "fixture-jsonl")).code == "disabled"
    opener.open.assert_not_called()


def test_redirect_and_environment_proxy_disabled(monkeypatch):
    monkeypatch.setenv("http_proxy", "http://example.test:8888")
    client = DnsClient(Config(1, "token"))
    assert all(not getattr(handler, "proxies", {}) for handler in client._opener.handlers)
    handler = next(h for h in client._opener.handlers if isinstance(h, _NoRedirect))
    for code in [301, 302, 303, 307, 308]:
        assert handler.redirect_request(Request("http://127.0.0.1"), None, code, "", {}, "http://example.test") is None
