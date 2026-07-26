"""Add prompt insights analytics tables.

Revision ID: f8a9b0c1d2e3
Revises: f1e2d3c4b5a6
Create Date: 2026-07-27 00:00:00.000000
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from open_webui.migrations.util import get_existing_tables

revision: str = 'f8a9b0c1d2e3'
down_revision: Union[str, None] = '42e2978c7933'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    existing_tables = set(get_existing_tables())

    if 'prompt_insights_run' not in existing_tables:
        op.create_table(
            'prompt_insights_run',
            sa.Column('id', sa.Text(), nullable=False),
            sa.Column('window_start', sa.BigInteger(), nullable=False),
            sa.Column('window_end', sa.BigInteger(), nullable=False),
            sa.Column('status', sa.Text(), nullable=False),
            sa.Column('total_prompts', sa.BigInteger(), nullable=True),
            sa.Column('clusters_found', sa.BigInteger(), nullable=True),
            sa.Column('noise_count', sa.BigInteger(), nullable=True),
            sa.Column('error_message', sa.Text(), nullable=True),
            sa.Column('created_at', sa.BigInteger(), nullable=False),
            sa.Column('completed_at', sa.BigInteger(), nullable=True),
            sa.PrimaryKeyConstraint('id'),
        )
        op.create_index('idx_prompt_insights_run_window_start', 'prompt_insights_run', ['window_start'])
        op.create_index('idx_prompt_insights_run_window_end', 'prompt_insights_run', ['window_end'])
        op.create_index('idx_prompt_insights_run_created_at', 'prompt_insights_run', ['created_at'])

    if 'prompt_cluster' not in existing_tables:
        op.create_table(
            'prompt_cluster',
            sa.Column('id', sa.Text(), nullable=False),
            sa.Column('run_id', sa.Text(), nullable=False),
            sa.Column('canonical_label', sa.Text(), nullable=False),
            sa.Column('canonical_label_hash', sa.Text(), nullable=False),
            sa.Column('cluster_size', sa.BigInteger(), nullable=False),
            sa.Column('created_at', sa.BigInteger(), nullable=False),
            sa.PrimaryKeyConstraint('id'),
            sa.ForeignKeyConstraint(['run_id'], ['prompt_insights_run.id']),
            sa.UniqueConstraint('run_id', 'canonical_label_hash', name='uq_prompt_cluster_run_hash'),
        )
        op.create_index('idx_prompt_cluster_run_id', 'prompt_cluster', ['run_id'])
        op.create_index('idx_prompt_cluster_canonical_label_hash', 'prompt_cluster', ['canonical_label_hash'])

    if 'prompt_cluster_trend' not in existing_tables:
        op.create_table(
            'prompt_cluster_trend',
            sa.Column('id', sa.Text(), nullable=False),
            sa.Column('canonical_label_hash', sa.Text(), nullable=False),
            sa.Column('bucket', sa.Text(), nullable=False),
            sa.Column('count', sa.BigInteger(), nullable=False),
            sa.Column('run_id', sa.Text(), nullable=False),
            sa.Column('created_at', sa.BigInteger(), nullable=False),
            sa.PrimaryKeyConstraint('id'),
            sa.ForeignKeyConstraint(['run_id'], ['prompt_insights_run.id']),
        )
        op.create_index('idx_prompt_cluster_trend_canonical_label_hash', 'prompt_cluster_trend', ['canonical_label_hash'])
        op.execute(
            """
            CREATE UNIQUE INDEX uq_prompt_cluster_trend_label_bucket
            ON prompt_cluster_trend (COALESCE(canonical_label_hash, ''), COALESCE(bucket, ''))
            """
        )
        op.create_index('idx_prompt_cluster_trend_run_id', 'prompt_cluster_trend', ['run_id'])

    if 'prompt_cluster_model' not in existing_tables:
        op.create_table(
            'prompt_cluster_model',
            sa.Column('id', sa.Text(), nullable=False),
            sa.Column('cluster_id', sa.Text(), nullable=False),
            sa.Column('model_id', sa.Text(), nullable=False),
            sa.Column('requested_model_key', sa.Text(), nullable=False),
            sa.Column('created_at', sa.BigInteger(), nullable=False),
            sa.PrimaryKeyConstraint('id'),
            sa.ForeignKeyConstraint(['cluster_id'], ['prompt_cluster.id']),
            sa.UniqueConstraint('cluster_id', 'model_id', 'requested_model_key', name='uq_prompt_cluster_model_cluster_model_key'),
        )
        op.create_index('idx_prompt_cluster_model_cluster_id', 'prompt_cluster_model', ['cluster_id'])
        op.create_index('idx_prompt_cluster_model_model_id', 'prompt_cluster_model', ['model_id'])
        op.create_index('idx_prompt_cluster_model_requested_model_key', 'prompt_cluster_model', ['requested_model_key'])

    if 'prompt_embedding_cache' not in existing_tables:
        op.create_table(
            'prompt_embedding_cache',
            sa.Column('text_hash', sa.Text(), nullable=False),
            sa.Column('text', sa.Text(), nullable=False),
            sa.Column('embedding', sa.Text(), nullable=True),
            sa.Column('expires_at', sa.BigInteger(), nullable=False),
            sa.Column('created_at', sa.BigInteger(), nullable=False),
            sa.PrimaryKeyConstraint('text_hash'),
        )
        op.create_index('idx_prompt_embedding_cache_expires_at', 'prompt_embedding_cache', ['expires_at'])


def downgrade() -> None:
    existing_tables = set(get_existing_tables())

    for table_name in [
        'prompt_cluster_model',
        'prompt_cluster_trend',
        'prompt_cluster',
        'prompt_embedding_cache',
        'prompt_insights_run',
    ]:
        if table_name in existing_tables:
            op.drop_table(table_name)
