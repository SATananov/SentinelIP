from datetime import datetime

from collectors.live_ssh import stream_ssh_logs
from collectors.ssh_logs import parse_ssh_line
from database.db import initialize_database, save_event
from services.detector import SSHDetector


def main():
    initialize_database()

    detector = SSHDetector(
        threshold=5,
        window_seconds=60,
    )

    print("=" * 72)
    print("SentinelIP")
    print("Live SSH Security Monitor")
    print("=" * 72)
    print("Monitoring 192.168.122.25...")
    print("Detection window: 60 seconds")
    print("Alert threshold: 5 SSH_PREAUTH events")
    print("SQLite persistence: enabled")
    print("Press Ctrl+C to stop.\n")

    try:
        for line in stream_ssh_logs():
            event = parse_ssh_line(line)

            if not event:
                continue

            now = datetime.now()

            result = detector.analyze(
                event_type=event.event_type,
                source_ip=event.source_ip,
            )

            timestamp_text = now.isoformat(timespec="seconds")

            save_event(
                timestamp=timestamp_text,
                source_ip=event.source_ip,
                username=event.username,
                event_type=event.event_type,
                severity=result.severity,
                message=result.message,
                event_count=result.count,
            )

            print(
                f"{now.strftime('%H:%M:%S')} "
                f"{result.severity:<7} "
                f"IP={event.source_ip:<15} "
                f"EVENT={event.event_type:<17} "
                f"COUNT={result.count:<2} "
                f"{result.message}"
            )

    except KeyboardInterrupt:
        print("\nSentinelIP stopped.")

    except Exception as exc:
        print(f"\nERROR: {exc}")


if __name__ == "__main__":
    main()
