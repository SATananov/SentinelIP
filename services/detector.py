from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta


@dataclass
class DetectionResult:
    severity: str
    message: str
    count: int


class SSHDetector:
    def __init__(self, threshold: int = 5, window_seconds: int = 60):
        self.threshold = threshold
        self.window = timedelta(seconds=window_seconds)
        self.events = defaultdict(deque)

    def analyze(
        self,
        event_type: str,
        source_ip: str,
        timestamp: datetime,
    ) -> DetectionResult:
        if event_type != "SSH_PREAUTH":
            return DetectionResult(
                severity="INFO",
                message=event_type,
                count=1,
            )

        history = self.events[source_ip]
        history.append(timestamp)

        cutoff = timestamp - self.window

        while history and history[0] < cutoff:
            history.popleft()

        count = len(history)

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
