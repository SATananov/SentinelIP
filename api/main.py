import csv
import io
import sqlite3
from datetime import datetime, timedelta
from typing import Literal

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response, StreamingResponse

from database.db import (
    get_alerts,
    get_event_type_counts,
    get_events_over_time,
    get_filtered_events,
    get_overview,
    get_paginated_events,
    get_severity_counts,
    get_source_ips,
    get_top_source_ips,
    initialize_database,
)
from database.networks import (
    create_network,
    delete_network,
    get_network,
    list_networks,
    update_network,
)
from api.schemas import NetworkCreate, NetworkResponse, NetworkUpdate
from services.pdf_report import build_security_report
from services.target_policy import TargetPolicyError


app = FastAPI(
    title="SentinelIP API",
    version="2.4.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "DELETE"],
    allow_headers=["*"],
)


def resolve_since(time_range: str):
    if time_range == "15m":
        return (
            datetime.now() - timedelta(minutes=15)
        ).isoformat(timespec="seconds")

    if time_range == "1h":
        return (
            datetime.now() - timedelta(hours=1)
        ).isoformat(timespec="seconds")

    if time_range == "24h":
        return (
            datetime.now() - timedelta(hours=24)
        ).isoformat(timespec="seconds")

    return None


@app.get("/health")
def health():
    return {
        "status": "ok",
        "service": "SentinelIP",
    }


@app.get("/networks", response_model=list[NetworkResponse])
def networks():
    initialize_database()
    return list_networks()


@app.post("/networks", response_model=NetworkResponse, status_code=201)
def create_authorized_network(payload: NetworkCreate):
    try:
        return create_network(
            cidr=payload.cidr,
            name=payload.name,
            description=payload.description,
            authorized=payload.authorized,
            enabled=payload.enabled,
        )
    except TargetPolicyError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except sqlite3.IntegrityError as exc:
        raise HTTPException(
            status_code=409,
            detail="A network with this CIDR already exists.",
        ) from exc


@app.get("/networks/{network_id}", response_model=NetworkResponse)
def get_authorized_network(network_id: int):
    network = get_network(network_id)

    if network is None:
        raise HTTPException(status_code=404, detail="Network not found.")

    return network


@app.patch("/networks/{network_id}", response_model=NetworkResponse)
def update_authorized_network(
    network_id: int,
    payload: NetworkUpdate,
):
    if get_network(network_id) is None:
        raise HTTPException(status_code=404, detail="Network not found.")

    updates = payload.model_dump(exclude_unset=True)

    if any(value is None for value in updates.values()):
        raise HTTPException(
            status_code=422,
            detail="Network update values cannot be null.",
        )

    return update_network(network_id, **updates)


@app.delete("/networks/{network_id}", status_code=204)
def delete_authorized_network(network_id: int):
    if not delete_network(network_id):
        raise HTTPException(status_code=404, detail="Network not found.")


@app.get("/overview")
def overview():
    return get_overview()


@app.get("/events")
def events(
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    severity: Literal["INFO", "WARNING", "ALERT"] | None = None,
    source_ip: str | None = None,
    time_range: Literal["15m", "1h", "24h", "all"] = "all",
):
    since = resolve_since(time_range)

    result = get_paginated_events(
        limit=limit,
        offset=offset,
        severity=severity,
        source_ip=source_ip,
        since=since,
    )

    return {
        "total": result["total"],
        "count": len(result["items"]),
        "limit": limit,
        "offset": offset,
        "severity": severity,
        "source_ip": source_ip,
        "time_range": time_range,
        "events": result["items"],
    }


@app.get("/source-ips")
def source_ips():
    return {
        "items": get_source_ips(),
    }


@app.get("/alerts")
def alerts(
    limit: int = Query(
        default=20,
        ge=1,
        le=100,
    )
):
    alert_list = get_alerts(
        limit=limit,
    )

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
def top_ip_stats(
    limit: int = Query(
        default=10,
        ge=1,
        le=100,
    )
):
    return {
        "items": get_top_source_ips(
            limit=limit,
        ),
    }


@app.get("/stats/timeline")
def timeline_stats(
    limit: int = Query(
        default=30,
        ge=1,
        le=120,
    )
):
    return {
        "items": get_events_over_time(
            limit=limit,
        ),
    }


@app.get("/export/events.json")
def export_events_json(
    severity: Literal["INFO", "WARNING", "ALERT"] | None = None,
    source_ip: str | None = None,
    time_range: Literal["15m", "1h", "24h", "all"] = "all",
):
    since = resolve_since(time_range)

    event_list = get_filtered_events(
        severity=severity,
        source_ip=source_ip,
        since=since,
    )

    return {
        "generated_at": datetime.now().isoformat(
            timespec="seconds"
        ),
        "count": len(event_list),
        "filters": {
            "severity": severity,
            "source_ip": source_ip,
            "time_range": time_range,
        },
        "events": event_list,
    }


@app.get("/export/events.csv")
def export_events_csv(
    severity: Literal["INFO", "WARNING", "ALERT"] | None = None,
    source_ip: str | None = None,
    time_range: Literal["15m", "1h", "24h", "all"] = "all",
):
    since = resolve_since(time_range)

    event_list = get_filtered_events(
        severity=severity,
        source_ip=source_ip,
        since=since,
    )

    output = io.StringIO()

    fieldnames = [
        "id",
        "timestamp",
        "source_ip",
        "username",
        "event_type",
        "severity",
        "message",
        "event_count",
    ]

    writer = csv.DictWriter(
        output,
        fieldnames=fieldnames,
    )

    writer.writeheader()

    for event in event_list:
        writer.writerow(event)

    output.seek(0)

    filename = (
        "sentinelip-events-"
        f"{datetime.now().strftime('%Y%m%d-%H%M%S')}.csv"
    )

    headers = {
        "Content-Disposition": (
            f'attachment; filename="{filename}"'
        )
    }

    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers=headers,
    )


@app.get("/export/report.pdf")
def export_security_report(
    severity: Literal["INFO", "WARNING", "ALERT"] | None = None,
    source_ip: str | None = None,
    time_range: Literal["15m", "1h", "24h", "all"] = "all",
):
    since = resolve_since(time_range)

    event_list = get_filtered_events(
        severity=severity,
        source_ip=source_ip,
        since=since,
    )

    pdf_bytes = build_security_report(
        events=event_list,
        severity=severity,
        source_ip=source_ip,
        time_range=time_range,
    )

    filename = (
        "sentinelip-security-report-"
        f"{datetime.now().strftime('%Y%m%d-%H%M%S')}.pdf"
    )

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": (
                f'attachment; filename="{filename}"'
            )
        },
    )
