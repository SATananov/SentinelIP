import pytest
from sentinelip_dns.config import Config, ConfigError, api_url, load_config


@pytest.mark.parametrize("url", ["http://localhost:8000", "http://127.0.0.1:8000/", "https://localhost:8000"])
def test_loopback(url):
    assert "127.0.0.1:8000" in api_url(url)


@pytest.mark.parametrize("url", ["file:///tmp/x", "data:x", "javascript:x", "ftp://localhost", "http://example.test",
    "http://127.0.0.1.evil.test", "http://user:secret@localhost", "http://localhost/path", "http://localhost?x=1",
    "http://localhost#x", "http://localhost:0", "http://localhost:65536", "http://localhost:", "http://local\nhost"])
def test_bad_urls(url):
    with pytest.raises(ConfigError):
        api_url(url)


@pytest.mark.parametrize("kwargs", [{}, {"sensor_id": 1}, {"sensor_token": "secret"},
    {"sensor_id": True, "sensor_token": "secret"}, {"sensor_id": 1, "sensor_token": "secret\nheader"},
    {"sensor_id": 1, "sensor_token": "secret", "enabled": "false"}])
def test_bad_config(kwargs):
    with pytest.raises((ConfigError, TypeError)):
        Config(**kwargs)


def test_repr_and_file(tmp_path):
    assert "secret" not in repr(Config(1, "secret"))
    path = tmp_path / "config.json"
    path.write_text('{"sensor_id":1,"sensor_token":"secret"}')
    assert load_config(path).enabled is False
    for content in ['{"sensor_token":"secret",', '[]', '{"unknown":"secret"}']:
        path.write_text(content)
        with pytest.raises(ConfigError) as error:
            load_config(path)
        assert "secret" not in str(error.value)
