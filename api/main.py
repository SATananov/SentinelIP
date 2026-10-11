from fastapi import FastAPI, Query

from database.db import (
    get_alerts,
    get_event_type_counts,
    get_recent_events,
    get_severity_counts,
    get_top_source_ips,
)


app = FastAPI(
    title="SentinelIP API",
    version="1.6.2",
)


@app.get("/health")
def health():
    return {
        "status": "ok",
        "service": "SentinelIP",
    }


@app.get("/events")
def events(limit: int = Query(default=20, ge=1, le=100)):
    event_list = get_recent_events(limit=limit)

    return {
        "count": len(event_list),
        "events": event_list,
    }


@app.get("/alerts")
def alerts(limit: int = Query(default=20, ge=1, le=100)):
    alert_list = get_alerts(limit=limit)

    return {
        "count": len(alert_list),
        "alerts": alert_list,
    }


@app.get("/stats/severity")
def severity_stats():
    return {
        "items": get_severity_counts(),
    }


@app.get("/stats/event-types")
def event_type_stats():
    return {
        "items": get_event_type_counts(),
    }


@app.get("/stats/top-ips")
def top_ip_stats(limit: int = Query(default=10, ge=1, le=100)):
    return {
        "items": get_top_source_ips(limit=limit),
    }
