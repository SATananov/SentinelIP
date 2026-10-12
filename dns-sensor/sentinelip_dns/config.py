import json
import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit


class ConfigError(ValueError):
    pass


def api_url(value):
    try:
        if not isinstance(value, str) or any(c.isspace() for c in value):
            raise ValueError
        parsed = urlsplit(value)
        if (parsed.scheme not in {"http", "https"} or parsed.hostname not in {"localhost", "127.0.0.1"}
                or parsed.username is not None or parsed.password is not None
                or parsed.path not in {"", "/"} or parsed.query or parsed.fragment
                or "?" in value or "#" in value or parsed.netloc.endswith(":")):
            raise ValueError
        port = parsed.port
        if port is not None and not 1 <= port <= 65535:
            raise ValueError
        # Pin localhost to literal loopback without a hostname lookup.
        return f"{parsed.scheme}://127.0.0.1" + (f":{port}" if port else "")
    except (ValueError, TypeError):
        raise ConfigError("API URL must be an HTTP(S) loopback origin.") from None


@dataclass(frozen=True)
class Config:
    sensor_id: int
    sensor_token: str = field(repr=False)
    api_base_url: str = "http://127.0.0.1:8000"
    enabled: bool = False

    def __post_init__(self):
        if type(self.sensor_id) is not int or self.sensor_id <= 0:
            raise ConfigError("Positive numeric sensor ID is required.")
        if not isinstance(self.sensor_token, str) or not re.fullmatch(r"[!-~]{1,512}", self.sensor_token):
            raise ConfigError("Sensor token is required and must be printable ASCII without spaces.")
        if type(self.enabled) is not bool:
            raise ConfigError("Enabled must be boolean.")
        object.__setattr__(self, "api_base_url", api_url(self.api_base_url))


def load_config(path):
    try:
        with open(path, encoding="utf-8") as stream:
            raw = stream.read(8193)
        if len(raw) > 8192:
            raise ValueError
        data = json.loads(raw)
        if not isinstance(data, dict):
            raise ValueError
        return Config(**data)
    except (OSError, ValueError, TypeError, RecursionError):
        raise ConfigError("Invalid sensor configuration.") from None
