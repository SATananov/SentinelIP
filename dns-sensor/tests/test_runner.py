import json
from io import StringIO
from unittest.mock import Mock
from sentinelip_dns.api import DnsClient, SendResult
from sentinelip_dns.config import Config
from sentinelip_dns.runner import run, main
from sentinelip_dns.sources import JsonLineSource


def test_mocked_integration(record):
    opener = Mock()
    response = Mock(status=202)
    opener.open.return_value.__enter__ = Mock(return_value=response)
    opener.open.return_value.__exit__ = Mock(return_value=False)
    config = Config(1, "secret", enabled=True)
    result = run(config, JsonLineSource(StringIO(json.dumps(record)), "fixture-jsonl"), DnsClient(config, opener=opener))
    assert result.accepted == 1
    request = opener.open.call_args.args[0]
    payload = json.loads(request.data)
    assert (payload["queried_domain"], payload["query_type"], payload["response_status"], payload["resolved_addresses"], payload["metadata"]) == (
        "login.example.test", "A", "NOERROR", ["192.0.2.10"], {"source": "fixture-jsonl"})
    assert request.get_header("X-sentinelip-sensor-token") == "secret"


def test_disabled_does_not_read_or_send():
    source, client = Mock(), Mock()
    assert run(Config(1, "secret"), source, client).accepted == 0
    source.events.assert_not_called()
    client.send.assert_not_called()


def test_bad_record_continues(record):
    client = Mock()
    client.send.return_value = SendResult(True, "accepted")
    result = run(Config(1, "secret", enabled=True), JsonLineSource(StringIO("bad\n" + json.dumps(record))), client)
    assert result.accepted == 1 and result.malformed == 1


def test_failure_stops_stream(record):
    client = Mock()
    client.send.return_value = SendResult(False, "http_error", 401, 1)
    result = run(Config(1, "secret", enabled=True), JsonLineSource(StringIO((json.dumps(record)+"\n")*100)), client)
    assert result.failed == 1 and client.send.call_count == 1


def test_interrupt():
    source = Mock()
    source.events.side_effect = KeyboardInterrupt
    assert run(Config(1, "secret", enabled=True), source, Mock()).stopped


def test_cli_disabled_and_errors(tmp_path, capsys):
    path = tmp_path / "config.json"
    path.write_text('{"sensor_id":1,"sensor_token":"secret"}')
    assert main(["--config", str(path), "--file", "missing"]) == 0
    path.write_text('secret')
    assert main(["--config", str(path)]) == 1
    assert "secret" not in str(capsys.readouterr())
