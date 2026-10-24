from collections import deque
from dataclasses import dataclass
from datetime import timedelta
from time import monotonic
from typing import Callable


DEFAULT_SUSPICIOUS_USERNAMES = frozenset(
    {
        "root",
        "admin",
        "administrator",
        "guest",
        "test",
        "oracle",
        "postgres",
        "mysql",
    }
)


@dataclass
class DetectionResult:
    severity: str
    message: str
    count: int


class SSHDetector:
    def __init__(
        self,
        threshold: int = 5,
        window_seconds: int = 60,
        suspicious_usernames: set[str] | None = None,
        clock: Callable[[], float] = monotonic,
    ):
        self.threshold = threshold
        self.window_seconds = window_seconds
        # Retained for historical threat-evidence queries. In-memory rolling
        # expiry uses only the monotonic clock.
        self.window = timedelta(seconds=window_seconds)
        self._clock = clock

        # Counts are separate by event class; the queue holds one expiry record
        # per rolling event so stale sources can be reclaimed without a map scan.
        self.events: dict[str, int] = {}
        self.failed_logins: dict[str, int] = {}
        self._rolling_events: deque[tuple[float, str, str]] = deque()

        usernames = (
            DEFAULT_SUSPICIOUS_USERNAMES
            if suspicious_usernames is None
            else suspicious_usernames
        )

        self.suspicious_usernames = {
            username.strip().casefold()
            for username in usernames
        }

    def _add_event(
        self,
        history_map: dict[str, int],
        event_class: str,
        source_ip: str,
        now: float,
    ) -> int:
        count = history_map.get(source_ip, 0) + 1
        history_map[source_ip] = count
        self._rolling_events.append((now, event_class, source_ip))
        return count

    def _expire(self, now: float) -> None:
        while (
            self._rolling_events
            and now - self._rolling_events[0][0] > self.window_seconds
        ):
            _event_time, event_class, source_ip = self._rolling_events.popleft()
            history_map = (
                self.events if event_class == "SSH_PREAUTH" else self.failed_logins
            )
            count = history_map[source_ip] - 1
            if count:
                history_map[source_ip] = count
            else:
                del history_map[source_ip]
                if not history_map:
                    # A CPython dict retains a large hash table after mass
                    # deletion. Clear it in place to release that table while
                    # preserving references to the detector's state maps.
                    history_map.clear()

    def _is_suspicious_username(
        self,
        username: str | None,
    ) -> bool:
        if username is None:
            return False

        normalized = username.strip().casefold()

        if not normalized:
            return False

        return normalized in self.suspicious_usernames

    def _analyze_preauth(
        self,
        source_ip: str,
        now: float,
    ) -> DetectionResult:
        count = self._add_event(
            self.events,
            "SSH_PREAUTH",
            source_ip,
            now,
        )

        if count >= self.threshold:
            return DetectionResult(
                severity="ALERT",
                message="Possible SSH scan",
                count=count,
            )

        if count >= 3:
            return DetectionResult(
                severity="WARNING",
                message="Repeated SSH pre-auth activity",
                count=count,
            )

        return DetectionResult(
            severity="INFO",
            message="SSH pre-auth activity",
            count=count,
        )

    def _analyze_failed_login(
        self,
        source_ip: str,
        now: float,
        username: str | None,
    ) -> DetectionResult:
        count = self._add_event(
            self.failed_logins,
            "LOGIN_FAILED",
            source_ip,
            now,
        )

        if count >= self.threshold:
            return DetectionResult(
                severity="ALERT",
                message="Possible SSH brute-force attack",
                count=count,
            )

        if count >= 3:
            return DetectionResult(
                severity="WARNING",
                message="Repeated SSH login failures",
                count=count,
            )

        if self._is_suspicious_username(username):
            return DetectionResult(
                severity="WARNING",
                message="Suspicious SSH username attempt",
                count=count,
            )

        return DetectionResult(
            severity="INFO",
            message="SSH login failed",
            count=count,
        )

    def analyze(
        self,
        event_type: str,
        source_ip: str,
        username: str | None = None,
    ) -> DetectionResult:
        now = self._clock()
        self._expire(now)

        if event_type == "SSH_PREAUTH":
            return self._analyze_preauth(
                source_ip,
                now,
            )

        if event_type == "LOGIN_FAILED":
            return self._analyze_failed_login(
                source_ip,
                now,
                username,
            )

        return DetectionResult(
            severity="INFO",
            message=event_type,
            count=1,
        )
