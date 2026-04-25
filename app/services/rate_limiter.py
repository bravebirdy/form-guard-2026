from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy import Select, and_, desc, func, or_, select, text
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.exc import IntegrityError, ProgrammingError
from sqlalchemy.orm import Session

from app.core.settings import settings
from app.db.models import FormRateLimitDefault, IpRateLimitOverride, SubmissionEvent


WINDOW = timedelta(minutes=60)
AUTO_BLOCK_EXCEED_BY = 5
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
            select(*base_cols, func.masklen(IpRateLimitOverride.ip_range).label("masklen"))
            .where(IpRateLimitOverride.enabled.is_(True))
            .where(IpRateLimitOverride.form_key.is_(None) if form_key_value is None else IpRateLimitOverride.form_key == form_key_value)
            .where(contains_ip)
            .order_by(desc("masklen"), desc(IpRateLimitOverride.id))
            .limit(1)
        )

    row = session.execute(q(form_key).params(ip=ip)).first()
    if row:
        rule_id, limit, _masklen = row
        return RuleMatch(rule_id=rule_id, limit_per_hour=int(limit), source="override_form")

    row = session.execute(q(None).params(ip=ip)).first()
    if row:
        rule_id, limit, _masklen = row
        return RuleMatch(rule_id=rule_id, limit_per_hour=int(limit), source="override_global")

    return None


def _match_default(session: Session, form_key: str) -> RuleMatch:
    row = (
        session.execute(
            select(FormRateLimitDefault.id, FormRateLimitDefault.limit_per_hour)
            .where(FormRateLimitDefault.form_key == form_key)
            .where(FormRateLimitDefault.enabled.is_(True))
            .limit(1)
        )
        .first()
    )
    if row:
        rule_id, limit = row
        return RuleMatch(rule_id=rule_id, limit_per_hour=int(limit), source="default_form")

    return RuleMatch(rule_id=None, limit_per_hour=int(settings.default_limit_per_hour), source="default_fallback")


def match_rule(session: Session, form_key: str, ip: str) -> RuleMatch:
    override = _match_override(session, form_key=form_key, ip=ip)
    if override is not None:
        return override
    return _match_default(session, form_key=form_key)


def decide(session: Session, form_key: str, ip: str, now: datetime | None = None) -> RateLimitDecision:
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
    event = SubmissionEvent(form_key=form_key, ip=ip, request_id=request_id, user_agent=user_agent)
    session.add(event)
    session.flush()
    return int(event.id)


def _single_ip_cidr(ip: str) -> str:
    addr = ipaddress.ip_address(ip)
    if isinstance(addr, ipaddress.IPv4Address):
        return f"{addr}/32"
    return f"{addr}/128"


def auto_block_if_exceeded(
    session: Session,
    form_key: str,
    ip: str,
    *,
    now: datetime | None = None,
    exceed_by: int = AUTO_BLOCK_EXCEED_BY,
    note: str = AUTO_BLOCK_NOTE,
) -> bool:
    """
    After recording a successful submission, if the last-60-min window used count
    exceeds current limit by `exceed_by`, auto-insert a form-specific single-IP block.
    Returns True when a new override row is inserted.
    """
    now = now or _now()
    window_start = now - WINDOW

    match = match_rule(session, form_key=form_key, ip=ip)
    limit = int(match.limit_per_hour)
    if limit <= 0:
        return False

    used_stmt = (
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
    used = int(session.execute(used_stmt).scalar_one())
    if used < limit + int(exceed_by):
        return False

    ip_range = _single_ip_cidr(ip)

    # Fast path: do nothing if already blocked for this form+ip_range.
    exists_stmt = (
        select(IpRateLimitOverride.id)
        .where(IpRateLimitOverride.form_key == form_key)
        .where(IpRateLimitOverride.ip_range == ip_range)
        .limit(1)
    )
    if session.execute(exists_stmt).first() is not None:
        return False

    # Concurrency-safe insert: rely on unique(form_key, ip_range) and ignore conflicts.
    stmt = (
        insert(IpRateLimitOverride)
        .values(
            form_key=form_key,
            ip_range=ip_range,
            limit_per_hour=0,
            enabled=True,
            note=note,
        )
        .on_conflict_do_nothing(index_elements=[IpRateLimitOverride.form_key.name, IpRateLimitOverride.ip_range.name])
        .returning(IpRateLimitOverride.id)
    )

    try:
        try:
            with session.begin_nested():
                inserted_id = session.execute(stmt).scalar_one_or_none()
        except ProgrammingError:
            # If the unique constraint isn't present yet (migrations not applied),
            # roll back the failed SAVEPOINT and fall back to best-effort insert.
            session.rollback()
            with session.begin_nested():
                session.add(
                    IpRateLimitOverride(
                        form_key=form_key,
                        ip_range=ip_range,
                        limit_per_hour=0,
                        enabled=True,
                        note=note,
                    )
                )
                session.flush()
                inserted_id = 1
    except IntegrityError:
        return False

    return inserted_id is not None

