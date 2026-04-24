"""initial tables

Revision ID: 20260424_0001
Revises: 
Create Date: 2026-04-24
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "20260424_0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "form_rate_limit_defaults",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column("form_key", sa.String(), nullable=False),
        sa.Column("limit_per_hour", sa.Integer(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.CheckConstraint("limit_per_hour >= 0", name="ck_form_defaults_limit_nonneg"),
        sa.UniqueConstraint("form_key", name="uq_form_defaults_form_key"),
    )
    op.create_index(
        "ix_form_rate_limit_defaults_form_key",
        "form_rate_limit_defaults",
        ["form_key"],
        unique=True,
    )

    op.create_table(
        "ip_rate_limit_overrides",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column("form_key", sa.String(), nullable=True),
        sa.Column("ip_range", postgresql.CIDR(), nullable=False),
        sa.Column("limit_per_hour", sa.Integer(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("note", sa.Text(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.CheckConstraint("limit_per_hour >= 0", name="ck_ip_overrides_limit_nonneg"),
    )
    op.create_index(
        "ix_ip_rate_limit_overrides_form_key_enabled",
        "ip_rate_limit_overrides",
        ["form_key", "enabled"],
        unique=False,
    )
    op.create_index(
        "ix_ip_rate_limit_overrides_ip_range_gist",
        "ip_rate_limit_overrides",
        ["ip_range"],
        unique=False,
        postgresql_using="gist",
    )

    op.create_table(
        "submission_events",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column("form_key", sa.String(), nullable=False),
        sa.Column("ip", postgresql.INET(), nullable=False),
        sa.Column(
            "occurred_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column("request_id", sa.String(), nullable=True),
        sa.Column("user_agent", sa.Text(), nullable=True),
    )
    op.create_index(
        "ix_submission_events_form_key_ip_occurred_at",
        "submission_events",
        ["form_key", "ip", sa.text("occurred_at DESC")],
        unique=False,
    )
    op.create_index(
        "ix_submission_events_occurred_at",
        "submission_events",
        ["occurred_at"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_submission_events_occurred_at", table_name="submission_events")
    op.drop_index("ix_submission_events_form_key_ip_occurred_at", table_name="submission_events")
    op.drop_table("submission_events")

    op.drop_index("ix_ip_rate_limit_overrides_ip_range_gist", table_name="ip_rate_limit_overrides")
    op.drop_index("ix_ip_rate_limit_overrides_form_key_enabled", table_name="ip_rate_limit_overrides")
    op.drop_table("ip_rate_limit_overrides")

    op.drop_index("ix_form_rate_limit_defaults_form_key", table_name="form_rate_limit_defaults")
    op.drop_table("form_rate_limit_defaults")

