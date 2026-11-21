"""Strict request/response and audit models.

`extra="forbid"` means unknown fields are rejected outright, so attackers
can't smuggle parameters (e.g. "temperature", "system") through the gateway.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

MAX_PROMPT_CHARS = 8_000


class Action(str, Enum):
    ALLOW = "allow"
    REDACT = "redact"   # request/response passed, but content was modified
    BLOCK = "block"


class Stage(str, Enum):
    AUTH = "auth"
    RATE_LIMIT = "rate_limit"
    INPUT = "input"
    UPSTREAM = "upstream"
    OUTPUT = "output"


# ---------------------------------------------------------------- API models
class ChatRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    prompt: str = Field(min_length=1, max_length=MAX_PROMPT_CHARS)
    conversation_id: str | None = Field(
        default=None, pattern=r"^[A-Za-z0-9_-]{1,64}$"
    )


class Finding(BaseModel):
    """A single guardrail hit. Never contains the raw sensitive value."""

    rule_id: str
    category: str
    description: str
    weight: float = 0.0


class ChatResponse(BaseModel):
    request_id: str
    action: Action
    response: str | None = None
    risk_score: float = Field(ge=0.0, le=1.0)
    input_findings: list[Finding] = []
    output_findings: list[Finding] = []
    redactions: dict[str, int] = {}
    model: str | None = None
    message: str | None = None


# -------------------------------------------------------------- Audit models
class AuditEvent(BaseModel):
    event_id: str = Field(default_factory=lambda: uuid4().hex)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    request_id: str | None = None
    client_id: str = "anonymous"          # key fingerprint, never the key itself
    stage: Stage
    action: Action
    risk_score: float = 0.0
    triggered_rules: list[str] = []
    prompt_sha256: str | None = None      # lets you correlate without storing text
    latency_ms: float | None = None
    details: dict[str, Any] = {}


class AuditStats(BaseModel):
    total_events: int
    by_action: dict[str, int]
    by_stage: dict[str, int]
    top_rules: list[tuple[str, int]]
