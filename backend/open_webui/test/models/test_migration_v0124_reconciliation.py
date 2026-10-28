"""Upgrade of disposable SQLite databases onto the v0.12.4 merged Alembic head."""

import os
import subprocess
import sys
import tempfile
from pathlib import Path

import sqlalchemy as sa
from alembic.config import Config
from alembic.script import ScriptDirectory

# Loading revision modules imports open_webui.env; keep that import off any real data or database.
os.environ.setdefault('WEBUI_SECRET_KEY', 'migration-tests-only')
DB_CONNECTION_VARS = (
    'DATABASE_TYPE',
    'DATABASE_USER',
    'DATABASE_PASSWORD',
    'DATABASE_HOST',
    'DATABASE_PORT',
    'DATABASE_NAME',
)
# env.py prefers these over DATABASE_URL, so they must never reach a real server.
for _name in DB_CONNECTION_VARS:
    os.environ.pop(_name, None)
_SCRATCH = tempfile.mkdtemp(prefix='owui-migration-')
os.environ['DATA_DIR'] = _SCRATCH
os.environ['DATABASE_URL'] = f'sqlite:///{_SCRATCH}/import-only.db'

ROOT = Path(__file__).resolve().parents[4]
APP = ROOT / 'backend' / 'open_webui'
FORK_HEAD = 'e304e2e7c45a'
UPSTREAM_HEAD = '0bd252b206fb'
PI_TABLES = (
    'prompt_insights_run',
    'prompt_cluster',
    'prompt_cluster_trend',
    'prompt_cluster_model',
    'prompt_embedding_cache',
)


def _scripts() -> ScriptDirectory:
    config = Config(str(APP / 'alembic.ini'))
    config.set_main_option('script_location', str(APP / 'migrations'))
    return ScriptDirectory.from_config(config)


def _upgrade(url: str, revision: str, data_dir: Path) -> None:
    env = {key: value for key, value in os.environ.items() if key not in DB_CONNECTION_VARS}
    env.update(
        DATABASE_URL=url,
        DATABASE_SCHEMA='',
        DATA_DIR=str(data_dir),
        WEBUI_SECRET_KEY='migration-tests-only',
        USE_SLIM_DOCKER='true',
        VECTOR_DB='pgvector',  # avoids the chromadb import in the slim runtime
        OLLAMA_BASE_URL='http://127.0.0.1:9',
        OLLAMA_BASE_URLS='http://127.0.0.1:9',
        ENABLE_DB_MIGRATIONS='false',
        ENABLE_PERSISTENT_CONFIG='false',
        PYTHON_DOTENV_DISABLED='1',
        OFFLINE_MODE='true',
        PYTHONDONTWRITEBYTECODE='1',
        PYTHONPATH=str(ROOT / 'backend'),
    )
    result = subprocess.run(
        [sys.executable, '-m', 'alembic', '-c', 'alembic.ini', 'upgrade', revision],
        cwd=APP,
        env=env,
        text=True,
        capture_output=True,
        timeout=180,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def _table(connection, name: str) -> sa.Table:
    return sa.Table(name, sa.MetaData(), autoload_with=connection)


def _versions(connection) -> list[str]:
    return connection.execute(sa.text('SELECT version_num FROM alembic_version')).scalars().all()


def _snapshot(connection, names) -> dict[str, list[dict]]:
    return {
        name: [dict(row) for row in connection.execute(sa.select(_table(connection, name))).mappings()]
        for name in names
    }


def _seed_non_analytics(connection) -> None:
    connection.execute(
        _table(connection, 'user').insert(),
        dict(
            id='sentinel-user',
            email='migration@example.invalid',
            name='Sentinel',
            role='user',
            profile_image_url='/user.png',
            last_active_at=1,
            updated_at=1,
            created_at=1,
        ),
    )
    connection.execute(
        _table(connection, 'chat').insert(),
        dict(
            id='sentinel-chat',
            user_id='sentinel-user',
            title='Sentinel chat',
            chat={'sentinel': True},
            created_at=1,
            updated_at=1,
        ),
    )


def _seed_prompt_insights(connection) -> None:
    rows = {
        'prompt_insights_run': dict(
            id='sentinel-run',
            window_start=1,
            window_end=2,
            status='completed',
            total_prompts=7,
            clusters_found=1,
            noise_count=0,
            created_at=1,
            completed_at=2,
        ),
        'prompt_cluster': dict(
            id='sentinel-cluster',
            run_id='sentinel-run',
            canonical_label='preserve me',
            canonical_label_hash='sentinel-hash',
            cluster_size=7,
            created_at=1,
        ),
        'prompt_cluster_trend': dict(
            id='sentinel-trend',
            canonical_label_hash='sentinel-hash',
            bucket='2026-10',
            count=7,
            run_id='sentinel-run',
            created_at=1,
        ),
        'prompt_cluster_model': dict(
            id='sentinel-model',
            cluster_id='sentinel-cluster',
            model_id='test-model',
            requested_model_key='test-request',
            created_at=1,
        ),
        'prompt_embedding_cache': dict(text_hash='sentinel-text', embedding='[0.1, 0.2]', expires_at=99, created_at=1),
    }
    for name, values in rows.items():
        connection.execute(_table(connection, name).insert(), values)


def test_single_merge_head_joins_upstream_and_fork_heads():
    scripts = _scripts()
    heads = scripts.get_heads()
    assert len(heads) == 1
    assert set(scripts.get_revision(heads[0]).down_revision) == {UPSTREAM_HEAD, FORK_HEAD}


def test_empty_database_upgrades_to_single_head(tmp_path):
    url = f'sqlite:///{tmp_path / "empty.db"}'
    _upgrade(url, 'head', tmp_path)
    engine = sa.create_engine(url)
    try:
        with engine.connect() as connection:
            assert _versions(connection) == _scripts().get_heads()
            assert set(PI_TABLES) <= set(sa.inspect(connection).get_table_names())
    finally:
        engine.dispose()


def test_fork_head_database_upgrade_preserves_data(tmp_path):
    url = f'sqlite:///{tmp_path / "fork.db"}'
    _upgrade(url, FORK_HEAD, tmp_path)
    engine = sa.create_engine(url)
    try:
        with engine.begin() as connection:
            assert _versions(connection) == [FORK_HEAD]
            _seed_non_analytics(connection)
            _seed_prompt_insights(connection)
            non_analytics = _snapshot(connection, ('user', 'chat'))
            legacy = _snapshot(connection, PI_TABLES)
        _upgrade(url, 'head', tmp_path)
        with engine.connect() as connection:
            assert _versions(connection) == _scripts().get_heads()
            assert _snapshot(connection, ('user', 'chat')) == non_analytics
            assert _snapshot(connection, PI_TABLES) == legacy
        _upgrade(url, 'head', tmp_path)
        with engine.connect() as connection:
            assert _snapshot(connection, PI_TABLES) == legacy
    finally:
        engine.dispose()
