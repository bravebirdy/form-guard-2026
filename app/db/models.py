from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import CIDR, INET
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class FormRateLimitDefault(Base):
    """
    每个表单的“默认配额”: 作用是给每个 form_key 一个默认上限（limit_per_hour），以及开关（enabled）。

    """

    __tablename__ = "form_rate_limit_defaults"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    form_key: Mapped[str] = mapped_column(
        String, unique=True, index=True, nullable=False
    )
    limit_per_hour: Mapped[int] = mapped_column(Integer, nullable=False)
    enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default="true"
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )


class IpRateLimitOverride(Base):
    """
    按 IP/网段的“覆盖规则”（支持 0=屏蔽）

    """

    __tablename__ = "ip_rate_limit_overrides"
    __table_args__ = (
        UniqueConstraint("form_key", "ip_range", name="uq_form_key_ip_range"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    form_key: Mapped[str] = mapped_column(String, nullable=False, index=True)
    ip_range: Mapped[str] = mapped_column(CIDR, nullable=False)
    limit_per_hour: Mapped[int] = mapped_column(Integer, nullable=False)
    enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default="true"
    )
    note: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )


class SubmissionEvent(Base):
    """
    成功提交事件表（滑动窗口的“事实数据”）:只记录“成功提交后”的事件，校验时统计最近 60 分钟的数量。
    """

    __tablename__ = "submission_events"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    form_key: Mapped[str] = mapped_column(String, nullable=False, index=True)
    ip: Mapped[str] = mapped_column(INET, nullable=False, index=True)
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), index=True
    )

    request_id: Mapped[str | None] = mapped_column(String, nullable=True)
    user_agent: Mapped[str | None] = mapped_column(Text, nullable=True)
