"""Authenticated remote-sensor ingestion for normalized perimeter evidence."""
from __future__ import annotations

import sqlite3
from datetime import datetime
from typing import Literal

from fastapi import Depends, FastAPI, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field, StrictStr

from api.sensor_enrollment import MachineRoute, authenticate_sensor_request, machine_transport
from database.perimeter import persist_perimeter_events
from services.perimeter_models import PerimeterEvent, PerimeterModelError
from services.remote_sensor_models import Capability


class PerimeterInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    external_event_id: StrictStr = Field(min_length=1, max_length=200)
    source_type: Literal["FIREWALL", "ROUTER", "GATEWAY"]
    source_key: StrictStr = Field(min_length=1, max_length=128)
    observed_at: datetime
    event_type: Literal["CONNECTION_ATTEMPT", "FLOW", "POLICY_DECISION", "OTHER"]
    direction: Literal["INBOUND", "OUTBOUND", "LATERAL", "UNKNOWN"]
    action: Literal["ALLOW", "BLOCK", "REJECT", "UNKNOWN"]
    protocol: Literal["TCP", "UDP", "ICMP", "OTHER"]
    source_ip: StrictStr = Field(min_length=2, max_length=45)
    destination_ip: StrictStr = Field(min_length=2, max_length=45)
    source_port: int | None = Field(default=None, ge=1, le=65535, strict=True)
    destination_port: int | None = Field(default=None, ge=1, le=65535, strict=True)
    interface: StrictStr | None = Field(default=None, max_length=128)
    source_reference: StrictStr | None = Field(default=None, max_length=256)
    raw_event_hash: StrictStr | None = Field(default=None, min_length=64, max_length=64)
    metadata: dict | None = None


class PerimeterBatch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    events: list[PerimeterInput] = Field(min_length=1, max_length=32)


def register_perimeter_ingestion_routes(app: FastAPI, store_provider, db_path_provider):
    def route(path, method, status_code=200):
        def register(endpoint):
            app.router.add_api_route(
                path, endpoint, methods=[method], status_code=status_code,
                tags=["perimeter-ingestion"], dependencies=[Depends(machine_transport)],
                route_class_override=MachineRoute,
            )
            return endpoint
        return register

    def auth(request: Request):
        return authenticate_sensor_request(request, store_provider)

    @route("/sensor/perimeter-events", "POST", 202)
    def ingest_perimeter_batch(body: PerimeterBatch, authenticated=Depends(auth)):
        _, sensor, _ = authenticated
        if Capability.LOG_COLLECTION.value not in sensor.get("capabilities", []):
            raise HTTPException(403, "Sensor does not have LOG_COLLECTION capability.")

        events = []
        try:
            for item in body.events:
                events.append(PerimeterEvent(
                    external_event_id=item.external_event_id,
                    site_id=sensor["site_id"],
                    sensor_id=sensor["id"],
                    source_type=item.source_type,
                    source_key=item.source_key,
                    observed_at=item.observed_at,
                    event_type=item.event_type,
                    direction=item.direction,
                    action=item.action,
                    protocol=item.protocol,
                    source_ip=item.source_ip,
                    destination_ip=item.destination_ip,
                    source_port=item.source_port,
                    destination_port=item.destination_port,
                    interface=item.interface,
                    source_reference=item.source_reference,
                    raw_event_hash=item.raw_event_hash,
                    metadata=item.metadata,
                ))
            rows = persist_perimeter_events(events, db_path_provider())
        except PerimeterModelError as exc:
            raise HTTPException(400, "Perimeter evidence is invalid.") from exc
        except sqlite3.IntegrityError as exc:
            raise HTTPException(409, "Perimeter evidence conflicts with existing evidence.") from exc

        return {
            "accepted": len(rows),
            "inserted": sum(1 for row in rows if not row["idempotent"]),
            "idempotent": sum(1 for row in rows if row["idempotent"]),
            "event_ids": [row["id"] for row in rows],
        }
