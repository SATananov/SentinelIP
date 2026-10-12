from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, StrictBool


class NetworkCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    cidr: str
    name: str = ""
    description: str = ""
    authorized: bool
    enabled: bool


class NetworkUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str | None = None
    description: str | None = None
    enabled: bool | None = None


class NetworkResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: int
    cidr: str
    name: str
    description: str
    authorized: bool
    enabled: bool
    created_at: str
    updated_at: str


class AuthorizedScopeResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: int
    scope_type: str
    canonical_target: str
    name: str
    description: str
    authorized: bool
    enabled: bool
    authorization_confirmed_at: str | None
    authorization_confirmation_version: str | None
    authorization_source: str | None
    created_at: str
    updated_at: str
    network_id: int | None = None


class PublicIPv4ScopeCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target: str = Field(min_length=1, max_length=64)
    name: str = Field(default="", max_length=120)
    description: str = Field(default="", max_length=500)
    authorization_confirmed: StrictBool
    authorization_confirmation_version: str = Field(min_length=1, max_length=80)


class WebTelemetryCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    external_event_id: str
    observed_at: datetime
    event_type: str
    url: str
    referrer_domain: str | None = None
    redirect_from_domain: str | None = None
    redirect_to_domain: str | None = None
    browser_session_id: str | None = None
    tab_id: str | None = None
    has_login_form: bool = False
    has_password_form: bool = False
    download_detected: bool = False
    metadata: dict | None = None


class DnsTelemetryCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    external_event_id: str
    observed_at: datetime
    queried_domain: str
    query_type: str
    response_status: str
    resolved_addresses: list[str] = []
    resolver: str | None = None
    ttl: int | None = None
    metadata: dict | None = None
