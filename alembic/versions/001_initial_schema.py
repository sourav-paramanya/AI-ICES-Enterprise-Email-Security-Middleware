"""Initial database schema

Revision ID: 001
Revises:
Create Date: 2026-06-24 12:00:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Enable UUID extension
    op.execute('CREATE EXTENSION IF NOT EXISTS "uuid-ossp"')

    # ── users ──────────────────────────────────────────────────────────
    op.create_table(
        "users",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("uuid_generate_v4()"), index=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), onupdate=sa.func.now(), nullable=False),
        sa.Column("email", sa.String(320), unique=True, nullable=False, index=True),
        sa.Column("username", sa.String(128), unique=True, nullable=False, index=True),
        sa.Column("hashed_password", sa.String(256), nullable=False),
        sa.Column("full_name", sa.String(256), nullable=True),
        sa.Column("role", sa.String(32), nullable=False, server_default="soc_analyst"),
        sa.Column("permissions", postgresql.JSONB, nullable=True),
        sa.Column("is_active", sa.Boolean, nullable=False, server_default=sa.text("true")),
        sa.Column("is_locked", sa.Boolean, nullable=False, server_default=sa.text("false")),
        sa.Column("mfa_enabled", sa.Boolean, nullable=False, server_default=sa.text("false")),
        sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_login_ip", sa.String(45), nullable=True),
        sa.Column("password_changed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("failed_login_attempts", sa.Integer, nullable=False, server_default=sa.text("0")),
    )

    # ── roles ──────────────────────────────────────────────────────────
    op.create_table(
        "roles",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("uuid_generate_v4()"), index=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), onupdate=sa.func.now(), nullable=False),
        sa.Column("name", sa.String(64), unique=True, nullable=False, index=True),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("permissions", postgresql.JSONB, nullable=False, server_default=sa.text("'[]'::jsonb")),
    )

    # ── email_logs ─────────────────────────────────────────────────────
    op.create_table(
        "email_logs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("uuid_generate_v4()"), index=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), onupdate=sa.func.now(), nullable=False),
        sa.Column("session_id", sa.String(128), unique=True, nullable=False, index=True),
        sa.Column("message_id", sa.String(256), nullable=False, index=True),
        sa.Column("sender", sa.String(320), nullable=False, index=True),
        sa.Column("recipients", postgresql.JSONB, nullable=False),
        sa.Column("subject", sa.Text, nullable=True),
        sa.Column("body_text", sa.Text, nullable=True),
        sa.Column("body_html", sa.Text, nullable=True),
        sa.Column("headers", postgresql.JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("attachments_metadata", postgresql.JSONB, nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("attachment_count", sa.Integer, nullable=False, server_default=sa.text("0")),
        sa.Column("email_size", sa.Integer, nullable=True),
        sa.Column("received_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("threat_score", sa.Float, nullable=True),
        sa.Column("verdict", sa.String(32), nullable=True),
        sa.Column("threat_type", sa.String(64), nullable=True),
        sa.Column("is_analyzed", sa.Boolean, nullable=False, server_default=sa.text("false")),
        sa.Column("has_attachments", sa.Boolean, nullable=False, server_default=sa.text("false")),
        sa.Column("has_urls", sa.Boolean, nullable=False, server_default=sa.text("false")),
        sa.Column("url_count", sa.Integer, nullable=False, server_default=sa.text("0")),
        sa.Column("urls", postgresql.JSONB, nullable=True),
        sa.Column("milter_action", sa.String(32), nullable=True),
        sa.Column("milter_response_time_ms", sa.Integer, nullable=True),
    )

    # ── threat_events ──────────────────────────────────────────────────
    op.create_table(
        "threat_events",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("uuid_generate_v4()"), index=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), onupdate=sa.func.now(), nullable=False),
        sa.Column("email_log_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("email_logs.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("threat_type", sa.String(64), nullable=False, index=True),
        sa.Column("threat_score", sa.Float, nullable=False),
        sa.Column("verdict", sa.String(32), nullable=False),
        sa.Column("nlp_score", sa.Float, nullable=True),
        sa.Column("nlp_label", sa.String(64), nullable=True),
        sa.Column("nlp_confidence", sa.Float, nullable=True),
        sa.Column("vision_score", sa.Float, nullable=True),
        sa.Column("vision_label", sa.String(64), nullable=True),
        sa.Column("detected_urls", postgresql.JSONB, nullable=True),
        sa.Column("ocr_text", sa.Text, nullable=True),
        sa.Column("url_score", sa.Float, nullable=True),
        sa.Column("url_verdict", sa.String(32), nullable=True),
        sa.Column("url_reputation_data", postgresql.JSONB, nullable=True),
        sa.Column("cdr_status", sa.String(32), nullable=True),
        sa.Column("cdr_details", postgresql.JSONB, nullable=True),
        sa.Column("detected_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("analysis_duration_ms", sa.Integer, nullable=True),
    )

    # ── remediation_history ────────────────────────────────────────────
    op.create_table(
        "remediation_history",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("uuid_generate_v4()"), index=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), onupdate=sa.func.now(), nullable=False),
        sa.Column("email_log_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("email_logs.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("action", sa.String(32), nullable=False, index=True),
        sa.Column("status", sa.String(32), nullable=False, server_default="pending"),
        sa.Column("initiated_by", sa.String(128), nullable=True),
        sa.Column("initiated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("zimbra_response", postgresql.JSONB, nullable=True),
        sa.Column("error_message", sa.Text, nullable=True),
        sa.Column("retry_count", sa.Integer, nullable=False, server_default=sa.text("0")),
        sa.Column("max_retries", sa.Integer, nullable=False, server_default=sa.text("3")),
    )

    # ── url_click_logs ─────────────────────────────────────────────────
    op.create_table(
        "url_click_logs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("uuid_generate_v4()"), index=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), onupdate=sa.func.now(), nullable=False),
        sa.Column("session_id", sa.String(128), nullable=True, index=True),
        sa.Column("original_url", sa.Text, nullable=False),
        sa.Column("rewritten_url", sa.Text, nullable=False),
        sa.Column("redirect_token", sa.String(256), unique=True, nullable=False, index=True),
        sa.Column("clicked_by", sa.String(320), nullable=True),
        sa.Column("clicked_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("ip_address", sa.String(45), nullable=True),
        sa.Column("user_agent", sa.Text, nullable=True),
        sa.Column("threat_score", sa.Float, nullable=True),
        sa.Column("reputation_status", sa.String(32), nullable=True),
        sa.Column("verdict", sa.String(16), nullable=False, server_default="unknown"),
        sa.Column("block_reason", sa.Text, nullable=True),
        sa.Column("threat_intel_data", postgresql.JSONB, nullable=True),
    )

    # ── audit_trails ───────────────────────────────────────────────────
    op.create_table(
        "audit_trails",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("uuid_generate_v4()"), index=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), onupdate=sa.func.now(), nullable=False),
        sa.Column("actor_id", sa.String(128), nullable=True, index=True),
        sa.Column("actor_email", sa.String(320), nullable=True),
        sa.Column("actor_role", sa.String(32), nullable=True),
        sa.Column("action", sa.String(64), nullable=False, index=True),
        sa.Column("resource_type", sa.String(64), nullable=False),
        sa.Column("resource_id", sa.String(128), nullable=True),
        sa.Column("details", postgresql.JSONB, nullable=True),
        sa.Column("ip_address", sa.String(45), nullable=True),
        sa.Column("user_agent", sa.Text, nullable=True),
        sa.Column("status", sa.String(16), nullable=False, server_default="success"),
        sa.Column("error_message", sa.Text, nullable=True),
    )

    # ── Indexes ────────────────────────────────────────────────────────
    op.create_index("ix_email_logs_verdict", "email_logs", ["verdict"])
    op.create_index("ix_email_logs_received_at", "email_logs", ["received_at"])
    op.create_index("ix_threat_events_detected_at", "threat_events", ["detected_at"])
    op.create_index("ix_remediation_history_status", "remediation_history", ["status"])
    op.create_index("ix_url_click_logs_verdict", "url_click_logs", ["verdict"])
    op.create_index("ix_audit_trails_created_at", "audit_trails", ["created_at"])


def downgrade() -> None:
    op.drop_table("audit_trails")
    op.drop_table("url_click_logs")
    op.drop_table("remediation_history")
    op.drop_table("threat_events")
    op.drop_table("email_logs")
    op.drop_table("roles")
    op.drop_table("users")
