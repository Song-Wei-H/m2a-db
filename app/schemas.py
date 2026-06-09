from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class TargetCreate(BaseModel):
    target: str = Field(..., max_length=255, examples=["192.0.2.10"])
    target_type: Literal["ip", "domain", "cidr"] = "ip"
    scope: Literal["internal", "external"] = "internal"


class TargetCreateResponse(BaseModel):
    target_id: int
    scan_run_id: int
    status: str


class DecisionRunResponse(BaseModel):
    target_id: int
    next_action: str
    next_tool: str
    mitre_phase: str
    mitre_technique: str
    risk_score: float
    confidence: float
    reason: str


class OpenPortResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    target_id: int | None
    scan_run_id: int | None
    ip: str | None
    port: int | None
    protocol: str | None
    service: str | None
    product: str | None
    version: str | None
    extra_info: str | None
    state: str | None
    created_at: datetime
