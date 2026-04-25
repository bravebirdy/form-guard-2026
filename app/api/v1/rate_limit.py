from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status

from app.api.v1.schemas import (
    RateLimitCheckRequest,
    RateLimitCheckResponse,
    RateLimitRecordRequest,
    RateLimitRecordResponse,
)
from app.core.ip import get_client_ip
from app.db.session import db_session
from app.services.rate_limiter import auto_block_if_exceeded, decide, record_success

router = APIRouter(prefix="/rate-limit", tags=["rate-limit"])


@router.post("/check", response_model=RateLimitCheckResponse)
def check(payload: RateLimitCheckRequest, request: Request) -> RateLimitCheckResponse:
    ip = get_client_ip(request)
    if not ip:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Unable to determine client IP")

    with db_session() as session:
        d = decide(session, form_key=payload.form_key, ip=ip)

    if not d.allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail={
                "allowed": d.allowed,
                "limit": d.limit,
                "remaining": d.remaining,
                "retry_after_seconds": d.retry_after_seconds,
                "matched_rule_id": d.matched_rule_id,
                "matched_source": d.matched_source,
            },
            headers={"Retry-After": str(d.retry_after_seconds or 0)} if d.retry_after_seconds is not None else None,
        )

    return RateLimitCheckResponse(
        allowed=True,
        limit=d.limit,
        remaining=d.remaining,
        retry_after_seconds=None,
        matched_rule_id=d.matched_rule_id,
        matched_source=d.matched_source,
    )


@router.post("/record", response_model=RateLimitRecordResponse)
def record(payload: RateLimitRecordRequest, request: Request) -> RateLimitRecordResponse:
    ip = get_client_ip(request)
    if not ip:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Unable to determine client IP")

    ua = request.headers.get("user-agent")

    with db_session() as session:
        event_id = record_success(
            session,
            form_key=payload.form_key,
            ip=ip,
            request_id=payload.request_id,
            user_agent=ua,
        )

        auto_block_if_exceeded(session, form_key=payload.form_key, ip=ip)

    return RateLimitRecordResponse(event_id=event_id)

