"""Initial schema with users, api_keys, and security models

Revision ID: 20251116_0000
Revises:
Create Date: 2025-11-16 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '20251116_0000'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Create all tables for AdversarialShield."""

    # Create users table
    op.create_table(
        'users',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('user_id', sa.String(length=100), nullable=False),
        sa.Column('email', sa.String(length=255), nullable=False),
        sa.Column('hashed_password', sa.String(length=255), nullable=False),
        sa.Column('full_name', sa.String(length=255), nullable=True),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('is_admin', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('scopes', postgresql.ARRAY(sa.String()), nullable=False, server_default='{"read","scan"}'),
        sa.Column('failed_login_attempts', sa.Integer(), nullable=True, server_default='0'),
        sa.Column('locked_until', sa.DateTime(), nullable=True),
        sa.Column('password_changed_at', sa.DateTime(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.Column('last_login_at', sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('user_id'),
        sa.UniqueConstraint('email')
    )
    op.create_index(op.f('ix_users_user_id'), 'users', ['user_id'], unique=True)
    op.create_index(op.f('ix_users_email'), 'users', ['email'], unique=True)
    op.create_index(op.f('ix_users_created_at'), 'users', ['created_at'], unique=False)

    # Create api_keys table
    op.create_table(
        'api_keys',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('key_id', sa.String(length=100), nullable=False),
        sa.Column('key_hash', sa.String(length=255), nullable=False),
        sa.Column('key_prefix', sa.String(length=16), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('user_id', sa.String(length=100), nullable=False),
        sa.Column('scopes', postgresql.ARRAY(sa.String()), nullable=False, server_default='{"read","scan"}'),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('expires_at', sa.DateTime(), nullable=True),
        sa.Column('last_used_at', sa.DateTime(), nullable=True),
        sa.Column('total_requests', sa.Integer(), nullable=True, server_default='0'),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('revoked_at', sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('key_id')
    )
    op.create_index(op.f('ix_api_keys_key_id'), 'api_keys', ['key_id'], unique=True)
    op.create_index(op.f('ix_api_keys_key_hash'), 'api_keys', ['key_hash'], unique=False)
    op.create_index(op.f('ix_api_keys_user_id'), 'api_keys', ['user_id'], unique=False)
    op.create_index(op.f('ix_api_keys_is_active'), 'api_keys', ['is_active'], unique=False)
    op.create_index(op.f('ix_api_keys_created_at'), 'api_keys', ['created_at'], unique=False)

    # Create attack_patterns table
    op.create_table(
        'attack_patterns',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('technique', sa.String(length=100), nullable=False),
        sa.Column('category', sa.String(length=100), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('template', sa.Text(), nullable=False),
        sa.Column('variables', postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column('severity', sa.String(length=20), nullable=True, server_default='medium'),
        sa.Column('owasp_category', sa.String(length=100), nullable=True),
        sa.Column('mitre_atlas_id', sa.String(length=50), nullable=True),
        sa.Column('success_rate', sa.Float(), nullable=True, server_default='0.0'),
        sa.Column('total_executions', sa.Integer(), nullable=True, server_default='0'),
        sa.Column('successful_executions', sa.Integer(), nullable=True, server_default='0'),
        sa.Column('target_models', postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column('tags', postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.Column('is_active', sa.Boolean(), nullable=True, server_default='true'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('name')
    )
    op.create_index(op.f('ix_attack_patterns_name'), 'attack_patterns', ['name'], unique=True)
    op.create_index(op.f('ix_attack_patterns_technique'), 'attack_patterns', ['technique'], unique=False)
    op.create_index(op.f('ix_attack_patterns_category'), 'attack_patterns', ['category'], unique=False)

    # Create attack_logs table
    op.create_table(
        'attack_logs',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('pattern_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('technique', sa.String(length=100), nullable=False),
        sa.Column('payload', sa.Text(), nullable=False),
        sa.Column('target_model', sa.String(length=100), nullable=True),
        sa.Column('target_endpoint', sa.String(length=255), nullable=True),
        sa.Column('response', sa.Text(), nullable=True),
        sa.Column('success', sa.Boolean(), nullable=True, server_default='false'),
        sa.Column('execution_time_ms', sa.Integer(), nullable=True),
        sa.Column('attack_type', sa.String(length=100), nullable=True),
        sa.Column('severity', sa.String(length=20), nullable=True),
        sa.Column('metadata', postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column('user_id', sa.String(length=100), nullable=True),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_attack_logs_pattern_id'), 'attack_logs', ['pattern_id'], unique=False)
    op.create_index(op.f('ix_attack_logs_technique'), 'attack_logs', ['technique'], unique=False)
    op.create_index(op.f('ix_attack_logs_target_model'), 'attack_logs', ['target_model'], unique=False)
    op.create_index(op.f('ix_attack_logs_success'), 'attack_logs', ['success'], unique=False)
    op.create_index(op.f('ix_attack_logs_created_at'), 'attack_logs', ['created_at'], unique=False)

    # Create detection_logs table
    op.create_table(
        'detection_logs',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('input_text', sa.Text(), nullable=False),
        sa.Column('detected_technique', sa.String(length=100), nullable=True),
        sa.Column('confidence', sa.Float(), nullable=False),
        sa.Column('detector_name', sa.String(length=100), nullable=False),
        sa.Column('detector_version', sa.String(length=50), nullable=True),
        sa.Column('action', sa.String(length=50), nullable=True),
        sa.Column('blocked', sa.Boolean(), nullable=True, server_default='false'),
        sa.Column('attack_log_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('metadata', postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_detection_logs_detected_technique'), 'detection_logs', ['detected_technique'], unique=False)
    op.create_index(op.f('ix_detection_logs_blocked'), 'detection_logs', ['blocked'], unique=False)
    op.create_index(op.f('ix_detection_logs_attack_log_id'), 'detection_logs', ['attack_log_id'], unique=False)
    op.create_index(op.f('ix_detection_logs_created_at'), 'detection_logs', ['created_at'], unique=False)

    # Create vulnerability_scans table
    op.create_table(
        'vulnerability_scans',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('scan_type', sa.String(length=50), nullable=False),
        sa.Column('target', sa.String(length=255), nullable=False),
        sa.Column('status', sa.String(length=50), nullable=True, server_default='pending'),
        sa.Column('total_vulnerabilities', sa.Integer(), nullable=True, server_default='0'),
        sa.Column('critical_count', sa.Integer(), nullable=True, server_default='0'),
        sa.Column('high_count', sa.Integer(), nullable=True, server_default='0'),
        sa.Column('medium_count', sa.Integer(), nullable=True, server_default='0'),
        sa.Column('low_count', sa.Integer(), nullable=True, server_default='0'),
        sa.Column('findings', postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column('risk_score', sa.Float(), nullable=True, server_default='0.0'),
        sa.Column('config', postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column('user_id', sa.String(length=100), nullable=True),
        sa.Column('started_at', sa.DateTime(), nullable=False),
        sa.Column('completed_at', sa.DateTime(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )


def downgrade() -> None:
    """Drop all tables."""
    op.drop_table('vulnerability_scans')
    op.drop_table('detection_logs')
    op.drop_table('attack_logs')
    op.drop_table('attack_patterns')
    op.drop_table('api_keys')
    op.drop_table('users')
