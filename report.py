from database.db import (
    get_alerts,
    get_event_count,
    get_event_type_counts,
    get_recent_events,
    get_severity_counts,
    get_top_source_ips,
)


def print_section(title: str):
    print()
    print("=" * 72)
    print(title)
    print("=" * 72)


def main():
    print("=" * 72)
    print("SentinelIP Security Report")
    print("=" * 72)

    total_events = get_event_count()
    print(f"Total events: {total_events}")

    print_section("Severity Summary")

    severity_counts = get_severity_counts()

    if not severity_counts:
        print("No severity data.")
    else:
        for item in severity_counts:
            print(
                f"{item['severity']:<10} "
                f"{item['total']}"
            )

    print_section("Event Types")

    event_type_counts = get_event_type_counts()

    if not event_type_counts:
        print("No event type data.")
    else:
        for item in event_type_counts:
            print(
                f"{item['event_type']:<22} "
                f"{item['total']}"
            )

    print_section("Top Source IPs")

    top_ips = get_top_source_ips(limit=10)

    if not top_ips:
        print("No source IP data.")
    else:
        for item in top_ips:
            print(
                f"{item['source_ip']:<18} "
                f"events={item['event_total']}"
            )

    print_section("Recent Alerts")

    alerts = get_alerts(limit=10)

    if not alerts:
        print("No alerts recorded.")
    else:
        for alert in alerts:
            print(
                f"{alert['timestamp']} "
                f"{alert['severity']:<7} "
                f"IP={alert['source_ip']:<15} "
                f"EVENT={alert['event_type']:<17} "
                f"COUNT={alert['event_count']:<2} "
                f"{alert['message']}"
            )

    print_section("Recent Events")

    events = get_recent_events(limit=10)

    if not events:
        print("No events recorded.")
    else:
        for event in events:
            print(
                f"{event['timestamp']} "
                f"{event['severity']:<7} "
                f"IP={event['source_ip']:<15} "
                f"EVENT={event['event_type']:<17} "
                f"COUNT={event['event_count']:<2} "
                f"{event['message']}"
            )


if __name__ == "__main__":
    main()
