"""Add atomic active-run claim for prompt insights.

Revision ID: 6c7d8e9f0a1b
Revises: 28f62ff35ad1
Create Date: 2026-09-09 10:20:00.000000
"""

import time
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = '6c7d8e9f0a1b'
down_revision: Union[str, None] = '28f62ff35ad1'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    columns = {column['name'] for column in inspector.get_columns('prompt_insights_run')}

    if 'active_claim' not in columns:
        with op.batch_alter_table('prompt_insights_run') as batch_op:
            batch_op.add_column(sa.Column('active_claim', sa.String(length=16), nullable=True))

    running = bind.execute(
        sa.text("SELECT id FROM prompt_insights_run " "WHERE status = 'running' ORDER BY created_at DESC, id DESC")
    ).fetchall()
    if running:
        active_id = running[0][0]
        bind.execute(
            sa.text("UPDATE prompt_insights_run SET active_claim = 'active' WHERE id = :run_id"),
            {'run_id': active_id},
        )
        stale_ids = [row[0] for row in running[1:]]
        if stale_ids:
            bind.execute(
                sa.text(
                    "UPDATE prompt_insights_run "
                    "SET status = 'failed', completed_at = :completed_at, "
                    "error_message = COALESCE(error_message, 'Superseded while adding atomic run claims') "
                    "WHERE id IN :run_ids"
                ).bindparams(sa.bindparam('run_ids', expanding=True)),
                {'completed_at': int(time.time()), 'run_ids': stale_ids},
            )

    constraints = inspector.get_unique_constraints('prompt_insights_run')
    if not any(constraint['name'] == 'uq_prompt_insights_run_active_claim' for constraint in constraints):
        with op.batch_alter_table('prompt_insights_run') as batch_op:
            batch_op.create_unique_constraint('uq_prompt_insights_run_active_claim', ['active_claim'])


def downgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    columns = {column['name'] for column in inspector.get_columns('prompt_insights_run')}
    if 'active_claim' in columns:
        with op.batch_alter_table('prompt_insights_run') as batch_op:
            batch_op.drop_constraint('uq_prompt_insights_run_active_claim', type_='unique')
            batch_op.drop_column('active_claim')
