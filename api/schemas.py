from pydantic import BaseModel, ConfigDict


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