import importlib.util
import io
import sys
from pathlib import Path

import sqlalchemy as sa
from alembic.migration import MigrationContext
from alembic.operations import Operations

sys.path.append(str(Path(__file__).resolve().parents[3]))


def _load_migration_module():
    path = (
        Path(__file__).resolve().parents[2]
        / 'migrations'
        / 'versions'
        / '6c7d8e9f0a1b_add_prompt_insights_active_claim.py'
    )
    spec = importlib.util.spec_from_file_location('prompt_insights_active_claim_migration', path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_upgrade_repairs_partially_added_text_claim_column(monkeypatch):
    engine = sa.create_engine('sqlite://')
    metadata = sa.MetaData()
    runs = sa.Table(
        'prompt_insights_run',
        metadata,
        sa.Column('id', sa.Text(), primary_key=True),
        sa.Column('window_start', sa.BigInteger(), nullable=False),
        sa.Column('window_end', sa.BigInteger(), nullable=False),
        sa.Column('status', sa.Text(), nullable=False),
        sa.Column('total_prompts', sa.BigInteger()),
        sa.Column('clusters_found', sa.BigInteger()),
        sa.Column('noise_count', sa.BigInteger()),
        sa.Column('error_message', sa.Text()),
        sa.Column('created_at', sa.BigInteger(), nullable=False),
        sa.Column('completed_at', sa.BigInteger()),
        sa.Column('active_claim', sa.Text()),
    )
    metadata.create_all(engine)

    migration = _load_migration_module()
    with engine.begin() as connection:
        connection.execute(
            runs.insert().values(
                id='partial-run',
                window_start=1,
                window_end=2,
                status='running',
                created_at=1,
            )
        )
        context = MigrationContext.configure(connection)
        monkeypatch.setattr(migration, 'op', Operations(context))
        migration.upgrade()

        inspector = sa.inspect(connection)
        active_claim = next(
            column for column in inspector.get_columns('prompt_insights_run') if column['name'] == 'active_claim'
        )
        constraints = {constraint['name'] for constraint in inspector.get_unique_constraints('prompt_insights_run')}
        row = connection.execute(
            sa.text('SELECT status, active_claim FROM prompt_insights_run WHERE id = :run_id'),
            {'run_id': 'partial-run'},
        ).one()

    assert active_claim['type'].length == 16
    assert 'uq_prompt_insights_run_active_claim' in constraints
    assert row == ('running', 'active')


def test_mysql_repair_ddl_uses_bounded_varchar():
    output = io.StringIO()
    context = MigrationContext.configure(
        dialect_name='mysql',
        opts={'as_sql': True, 'output_buffer': output},
    )

    Operations(context).alter_column(
        'prompt_insights_run',
        'active_claim',
        existing_type=sa.Text(),
        type_=sa.String(length=16),
        existing_nullable=True,
    )

    ddl = output.getvalue()
    assert 'MODIFY active_claim VARCHAR(16) NULL' in ddl
    assert 'active_claim TEXT' not in ddl
