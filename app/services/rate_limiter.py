from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy import Select, and_, desc, func, select, text
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.exc import IntegrityError, ProgrammingError
from sqlalchemy.orm import Session

from app.core.settings import settings
from app.db.models import FormRateLimitDefault, IpRateLimitOverride, SubmissionEvent

WINDOW = timedelta(minutes=60)
AUTO_BLOCK_EXCEED_BY = 5  # exceed number 超过了几个record
AUTO_BLOCK_NOTE = "auto_block: exceeded limit by 5"


@dataclass(frozen=True)
class RuleMatch:
    rule_id: int | None
    limit_per_hour: int
    source: str  # override_form | override_global | default_form | default_fallback


@dataclass(frozen=True)
class RateLimitDecision:
    allowed: bool
    limit: int
    remaining: int
    retry_after_seconds: int | None
    matched_rule_id: int | None
    matched_source: str


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _match_override(session: Session, form_key: str, ip: str) -> RuleMatch | None:
    """
    Choose the most specific matching CIDR (largest prefix length).
    Prefer form-specific rule over global rule when both exist.
    """
    # Postgres CIDR: ip <<= cidr  means ip is contained by cidr.
    contains_ip = text(":ip <<= ip_range")

    base_cols = (IpRateLimitOverride.id, IpRateLimitOverride.limit_per_hour)

    def q(form_key_value: str | None) -> Select:
        return (
            select(
                *base_cols, func.masklen(IpRateLimitOverride.ip_range).label("masklen")
            )
            .where(IpRateLimitOverride.enabled.is_(True))
            .where(
                IpRateLimitOverride.form_key.is_(None)
                if form_key_value is None
                else IpRateLimitOverride.form_key == form_key_value
            )
            .where(contains_ip)
            .order_by(desc("masklen"), desc(IpRateLimitOverride.id))
            .limit(1)
        )

    row = session.execute(q(form_key).params(ip=ip)).first()
    if row:
        rule_id, limit, _masklen = row
        return RuleMatch(
            rule_id=rule_id, limit_per_hour=int(limit), source="override_form"
        )

    row = session.execute(q(None).params(ip=ip)).first()
    if row:
        rule_id, limit, _masklen = row
        return RuleMatch(
            rule_id=rule_id, limit_per_hour=int(limit), source="override_global"
        )

    return None


def _match_default(session: Session, form_key: str) -> RuleMatch:
    row = session.execute(
        select(FormRateLimitDefault.id, FormRateLimitDefault.limit_per_hour)
        .where(FormRateLimitDefault.form_key == form_key)
        .where(FormRateLimitDefault.enabled.is_(True))
        .limit(1)
    ).first()
    if row:
        rule_id, limit = row
        return RuleMatch(
            rule_id=rule_id, limit_per_hour=int(limit), source="default_form"
        )

    return RuleMatch(
        rule_id=None,
        limit_per_hour=int(settings.default_limit_per_hour),
        source="default_fallback",
    )


def match_rule(session: Session, form_key: str, ip: str) -> RuleMatch:
    override = _match_override(session, form_key=form_key, ip=ip)
    if override is not None:
        return override
    return _match_default(session, form_key=form_key)


def decide(
    session: Session, form_key: str, ip: str, now: datetime | None = None
) -> RateLimitDecision:
    now = now or _now()
    window_start = now - WINDOW

    match = match_rule(session, form_key=form_key, ip=ip)
    limit = match.limit_per_hour

    if limit <= 0:
        return RateLimitDecision(
            allowed=False,
            limit=0,
            remaining=0,
            retry_after_seconds=None,
            matched_rule_id=match.rule_id,
            matched_source=match.source,
        )

    count_stmt = (
        select(func.count())
        .select_from(SubmissionEvent)
        .where(
            and_(
                SubmissionEvent.form_key == form_key,
                SubmissionEvent.ip == ip,
                SubmissionEvent.occurred_at > window_start,
            )
        )
    )
    used = int(session.execute(count_stmt).scalar_one())

    if used >= limit:
        oldest_stmt = (
            select(SubmissionEvent.occurred_at)
            .where(
                and_(
                    SubmissionEvent.form_key == form_key,
                    SubmissionEvent.ip == ip,
                    SubmissionEvent.occurred_at > window_start,
                )
            )
            .order_by(SubmissionEvent.occurred_at.asc())
            .limit(1)
        )
        oldest = session.execute(oldest_stmt).scalar_one_or_none()
        retry_after = None
        if oldest is not None:
            retry_at = oldest + WINDOW
            retry_after = max(0, int((retry_at - now).total_seconds()))

        return RateLimitDecision(
            allowed=False,
            limit=limit,
            remaining=0,
            retry_after_seconds=retry_after,
            matched_rule_id=match.rule_id,
            matched_source=match.source,
        )

    remaining = max(0, limit - used)
    return RateLimitDecision(
        allowed=True,
        limit=limit,
        remaining=remaining,
        retry_after_seconds=None,
        matched_rule_id=match.rule_id,
        matched_source=match.source,
    )


def record_success(
    session: Session,
    form_key: str,
    ip: str,
    request_id: str | None = None,
    user_agent: str | None = None,
) -> int:
    event = SubmissionEvent(
        form_key=form_key, ip=ip, request_id=request_id, user_agent=user_agent
    )
    session.add(event)
    session.flush()
    return int(event.id)
