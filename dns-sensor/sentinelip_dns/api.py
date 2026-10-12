import json
import time
from dataclasses import dataclass
from http.client import HTTPException
from urllib.error import HTTPError, URLError
from urllib.request import Request, build_opener, ProxyHandler, HTTPRedirectHandler


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


@dataclass(frozen=True)
class SendResult:
    ok: bool
    code: str
    status: int | None = None
    attempts: int = 0


class DnsClient:
    def __init__(self, config, *, opener=None, sleep=time.sleep):
        self.config = config
        self._opener = opener if opener is not None else build_opener(ProxyHandler({}), _NoRedirect())
        self._sleep = sleep

    def send(self, event):
        if not self.config.enabled:
            return SendResult(False, "disabled")
        body = json.dumps(event.payload(), allow_nan=False).encode("utf-8")
        for attempt in range(1, 4):
            request = Request(
                self.config.api_base_url + "/telemetry/dns", data=body, method="POST",
                headers={"Content-Type": "application/json",
                         "X-SentinelIP-Sensor-ID": str(self.config.sensor_id),
                         "X-SentinelIP-Sensor-Token": self.config.sensor_token},
            )
            status = None
            try:
                with self._opener.open(request, timeout=5) as response:
                    status = response.status
            except HTTPError as exc:
                status = exc.code
                exc.close()
            except (URLError, OSError, HTTPException):
                pass  # Never echo exception text, credentials or response bodies.
            if status == 202:
                return SendResult(True, "accepted", status, attempt)
            retry = status is None or 500 <= status <= 599
            result = SendResult(False, "connection_failure" if status is None else "http_error", status, attempt)
            if not retry or attempt == 3:
                return result
            self._sleep(attempt)
