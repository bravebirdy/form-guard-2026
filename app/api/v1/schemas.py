from __future__ import annotations

from pydantic import BaseModel, Field


class RateLimitCheckRequest(BaseModel):
    form_key: str = Field(min_length=1, max_length=200)
    request_id: str | None = Field(default=None, max_length=200)


class RateLimitCheckResponse(BaseModel):
    allowed: bool
    limit: int
    remaining: int
    retry_after_seconds: int | None = None
    matched_rule_id: int | None = None
    matched_source: str


class RateLimitRecordRequest(BaseModel):
    form_key: str = Field(min_length=1, max_length=200)
    request_id: str | None = Field(default=None, max_length=200)


class RateLimitRecordResponse(BaseModel):
    event_id: int

