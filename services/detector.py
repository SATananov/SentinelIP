from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta


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
    ):
        self.threshold = threshold
        self.window = timedelta(seconds=window_seconds)

        # Existing SSH_PREAUTH history.
        self.events = defaultdict(deque)

        # Separate failed-login history.
        self.failed_logins = defaultdict(deque)

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
        history_map,
        source_ip: str,
        timestamp: datetime,
    ) -> int:
        history = history_map[source_ip]
        history.append(timestamp)

        cutoff = timestamp - self.window

        while history and history[0] < cutoff:
            history.popleft()

        return len(history)

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
        timestamp: datetime,
    ) -> DetectionResult:
        count = self._add_event(
            self.events,
            source_ip,
            timestamp,
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
        timestamp: datetime,
        username: str | None,
    ) -> DetectionResult:
        count = self._add_event(
            self.failed_logins,
            source_ip,
            timestamp,
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
        timestamp: datetime,
        username: str | None = None,
    ) -> DetectionResult:
        if event_type == "SSH_PREAUTH":
            return self._analyze_preauth(
                source_ip,
                timestamp,
            )

        if event_type == "LOGIN_FAILED":
            return self._analyze_failed_login(
                source_ip,
                timestamp,
                username,
            )

        return DetectionResult(
            severity="INFO",
            message=event_type,
            count=1,
        )
