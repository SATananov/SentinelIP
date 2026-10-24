from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, StrictBool, field_validator
from services.telemetry_models import _validate_metadata, validate_utf8_text


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
    address_count: int | None = None
    approved_addresses: list[str] = Field(default_factory=list)
    resolution_verified_at: str | None = None
    resolution_version: str | None = None
    resolution_status: str | None = None


class PublicIPv4ScopeCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target: str = Field(min_length=1, max_length=64)
    name: str = Field(default="", max_length=120)
    description: str = Field(default="", max_length=500)
    authorization_confirmed: StrictBool
    authorization_confirmation_version: str = Field(min_length=1, max_length=80)


class HostnamePreviewRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    hostname: str = Field(min_length=1, max_length=1024)


class HostnameScopeCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    canonical_hostname: str = Field(min_length=1, max_length=253)
    approved_resolved_ipv4: list[str] = Field(min_length=1, max_length=16)
    name: str = Field(default="", max_length=120)
    description: str = Field(default="", max_length=500)
    authorization_confirmed: StrictBool
    authorization_confirmation_version: str = Field(min_length=1, max_length=80)


class TelemetryPayloadBase(BaseModel):
    model_config = ConfigDict(extra="forbid")

    external_event_id: str
    observed_at: datetime
    metadata: dict | None = None

    @field_validator("external_event_id", mode="before")
    @classmethod
    def bound_event_id(cls, value):
        return validate_utf8_text(value, "External event ID", 128)

    @field_validator("observed_at", mode="before")
    @classmethod
    def bound_observed_at(cls, value):
        return validate_utf8_text(value, "Observation timestamp", 64)

    @field_validator("metadata")
    @classmethod
    def bound_metadata(cls, value):
        return _validate_metadata(value)


class WebTelemetryCreate(TelemetryPayloadBase):
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

    @field_validator("event_type", mode="before")
    @classmethod
    def bound_event_type(cls, value):
        return validate_utf8_text(value, "Event type", 32)

    @field_validator("url", mode="before")
    @classmethod
    def bound_url(cls, value):
        return validate_utf8_text(value, "URL", 32_768)

    @field_validator(
        "referrer_domain", "redirect_from_domain", "redirect_to_domain", mode="before",
    )
    @classmethod
    def bound_domains(cls, value):
        return validate_utf8_text(value, "Domain", 1_024, allow_none=True)

    @field_validator("browser_session_id", mode="before")
    @classmethod
    def bound_session_id(cls, value):
        return validate_utf8_text(value, "Browser session ID", 128, allow_none=True)

    @field_validator("tab_id", mode="before")
    @classmethod
    def bound_tab_id(cls, value):
        return validate_utf8_text(value, "Tab ID", 64, allow_none=True)


class DnsTelemetryCreate(TelemetryPayloadBase):
    queried_domain: str
    query_type: str
    response_status: str
    resolved_addresses: list[str] = Field(default_factory=list, max_length=256)
    resolver: str | None = None
    ttl: int | None = Field(default=None, ge=0, le=2_147_483_647)

    @field_validator("queried_domain", mode="before")
    @classmethod
    def bound_domain(cls, value):
        return validate_utf8_text(value, "Queried domain", 1_024)

    @field_validator("query_type", mode="before")
    @classmethod
    def bound_query_type(cls, value):
        return validate_utf8_text(value, "DNS query type", 32)

    @field_validator("response_status", mode="before")
    @classmethod
    def bound_response_status(cls, value):
        return validate_utf8_text(value, "DNS response status", 16)

    @field_validator("resolved_addresses")
    @classmethod
    def bound_addresses(cls, value):
        if len(value) > 256:
            raise ValueError("DNS answer list has too many addresses.")
        for address in value:
            validate_utf8_text(address, "DNS address", 45)
        return value

    @field_validator("resolver", mode="before")
    @classmethod
    def bound_resolver(cls, value):
        return validate_utf8_text(value, "DNS resolver", 45, allow_none=True)


class PublicCIDRPreview(BaseModel):
    model_config = ConfigDict(extra="forbid")
    target: str = Field(min_length=1, max_length=64)


class PublicCIDRScopeCreate(PublicIPv4ScopeCreate):
    """Explicit confirmation for every address of a bounded public CIDR."""
