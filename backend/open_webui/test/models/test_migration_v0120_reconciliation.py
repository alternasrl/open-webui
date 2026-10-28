"""Exercise the published migration histories against disposable databases.

TEST_POSTGRES_URL must identify a disposable PostgreSQL database. Each PostgreSQL
case creates and drops its own schema; SQLite cases use pytest's file-based tmp_path.
"""

import ast
import os
import subprocess
import sys
import uuid
from pathlib import Path

import pytest
import sqlalchemy as sa
from alembic.config import Config
from alembic.script import ScriptDirectory

ROOT = Path(__file__).resolve().parents[4]
APP = ROOT / 'backend' / 'open_webui'
VERSIONS = APP / 'migrations' / 'versions'
UPSTREAM = '15818d88fd7bde1b73de33590f50d15d21e8d7c1'
FORK = '6d4a5ebd5fb3f1f0c4c3de210fe5da8395c37153'
FORK_HEAD = '6c7d8e9f0a1b'
UPSTREAM_V0124 = 'v0.12.4'
UPSTREAM_V0124_HEAD = '0bd252b206fb'
# Published fork release (v0.12.0-261012) whose history already contains the e304e2e7c45a merge.
FORK_PUBLISHED = 'ccf8f5fa35a81d7e295e31346ae427a877ffb800'
FORK_PUBLISHED_HEAD = 'e304e2e7c45a'
DB_CONNECTION_VARS = (
    'DATABASE_TYPE',
    'DATABASE_USER',
    'DATABASE_PASSWORD',
    'DATABASE_HOST',
    'DATABASE_PORT',
    'DATABASE_NAME',
)
UPSTREAM_HEAD = 'b8f2c6d91a04'
PI_TABLES = {
    'prompt_insights_run',
    'prompt_cluster',
    'prompt_cluster_trend',
    'prompt_cluster_model',
    'prompt_embedding_cache',
}
HISTORY_TABLES = {
    'prompt_history',
    'skill_history',
    'model_history',
    'tool_history',
    'function_history',
}


def _revision_metadata(source: str) -> tuple[str, tuple[str, ...]]:
    assignments = {}
    for node in ast.parse(source).body:
        if isinstance(node, ast.Assign):
            targets = node.targets
        elif isinstance(node, ast.AnnAssign):
            targets = [node.target]
        else:
            continue
        for target in targets:
            if isinstance(target, ast.Name) and target.id in ('revision', 'down_revision'):
                assignments[target.id] = ast.literal_eval(node.value)
    parent = assignments['down_revision']
    parents = () if parent is None else (parent,) if isinstance(parent, str) else tuple(parent)
    return assignments['revision'], parents


def _git(*args: str) -> str:
    return subprocess.check_output(['git', *args], cwd=ROOT, text=True)


def _published_graph(sha: str) -> dict[str, tuple[str, ...]]:
    graph = {}
    paths = _git('ls-tree', '-r', '--name-only', sha, 'backend/open_webui/migrations/versions')
    for path in paths.splitlines():
        if path.endswith('.py'):
            revision, parents = _revision_metadata(_git('show', f'{sha}:{path}'))
            assert revision not in graph, f'duplicate published revision: {revision}'
            graph[revision] = parents
    return graph


def _scripts() -> ScriptDirectory:
    config = Config(str(APP / 'alembic.ini'))
    config.set_main_option('script_location', str(APP / 'migrations'))
    return ScriptDirectory.from_config(config)


def test_single_head_and_published_parents_unchanged():
    published = _published_graph(UPSTREAM)
    for revision, parents in _published_graph(FORK).items():
        if revision in published:
            assert published[revision] == parents, f'divergent published parent: {revision}'
        published[revision] = parents
    for sha in (UPSTREAM_V0124, FORK_PUBLISHED):
        for revision, parents in _published_graph(sha).items():
            assert published.setdefault(revision, parents) == parents, f'divergent published parent: {revision}'
    graph = {}
    for path in VERSIONS.glob('*.py'):
        revision, parents = _revision_metadata(path.read_text())
        assert revision not in graph, f'duplicate revision: {revision}'
        graph[revision] = parents
    for revision, parents in published.items():
        assert graph.get(revision) == parents, f'published parent changed: {revision}'
    for revision, parents in graph.items():
        assert set(parents) <= graph.keys(), f'missing parent for {revision}'

    visited = set()
    visiting = set()

    def visit(revision: str) -> None:
        assert revision not in visiting, f'cycle at {revision}'
        if revision in visited:
            return
        visiting.add(revision)
        for parent in graph[revision]:
            visit(parent)
        visiting.remove(revision)
        visited.add(revision)

    for revision in graph:
        visit(revision)
    parents = {parent for parent_list in graph.values() for parent in parent_list}
    heads = set(graph) - parents
    assert len(heads) == 1, f'expected one head, got {sorted(heads)}'
    head = heads.pop()
    # The only unpublished revision is the v0.12.4 merge (see test_migration_v0124_reconciliation).
    assert set(graph) - set(published) == {head}
    assert graph[head] == (UPSTREAM_V0124_HEAD, FORK_PUBLISHED_HEAD)
    assert graph[FORK_PUBLISHED_HEAD] == (FORK_HEAD, UPSTREAM_HEAD)
    assert _scripts().get_heads() == [head]
    merge = _scripts().get_revision(head).module
    # A future DDL operation in the merge must not silently mutate either history.
    for function in ('upgrade', 'downgrade'):
        tree = ast.parse(Path(merge.__file__).read_text())
        body = next(node.body for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == function)
        assert len(body) == 1 and isinstance(body[0], ast.Pass)


def _migration_env(url: str, schema: str = '') -> dict[str, str]:
    env = {key: value for key, value in os.environ.items() if key not in DB_CONNECTION_VARS}
    env.update(
        DATABASE_URL=url,
        DATABASE_SCHEMA=schema,
        ENABLE_DB_MIGRATIONS='false',
        ENABLE_PERSISTENT_CONFIG='false',
        PYTHON_DOTENV_DISABLED='1',
        OFFLINE_MODE='true',
        PYTHONDONTWRITEBYTECODE='1',
        PYTHONPATH=str(ROOT / 'backend'),
    )
    return env


def _upgrade(url: str, revision: str, schema: str = '') -> None:
    result = subprocess.run(
        [sys.executable, '-m', 'alembic', '-c', 'alembic.ini', 'upgrade', revision],
        cwd=APP,
        env=_migration_env(url, schema),
        text=True,
        capture_output=True,
        timeout=120,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def _table(connection, name: str) -> sa.Table:
    return sa.Table(name, sa.MetaData(), autoload_with=connection)


def _seed_prompt_insights(connection) -> dict[str, list[dict]]:
    rows = {
        'prompt_insights_run': [
            dict(
                id='sentinel-run',
                window_start=1,
                window_end=2,
                status='completed',
                total_prompts=7,
                clusters_found=1,
                noise_count=0,
                created_at=1,
                completed_at=2,
            )
        ],
        'prompt_cluster': [
            dict(
                id='sentinel-cluster',
                run_id='sentinel-run',
                canonical_label='preserve me',
                canonical_label_hash='sentinel-hash',
                cluster_size=7,
                created_at=1,
            )
        ],
        'prompt_cluster_trend': [
            dict(
                id='sentinel-trend',
                canonical_label_hash='sentinel-hash',
                bucket='2026-10',
                count=7,
                run_id='sentinel-run',
                created_at=1,
            )
        ],
        'prompt_cluster_model': [
            dict(
                id='sentinel-model',
                cluster_id='sentinel-cluster',
                model_id='test-model',
                requested_model_key='test-request',
                created_at=1,
            )
        ],
        'prompt_embedding_cache': [
            dict(text_hash='sentinel-text', embedding='[0.1, 0.2]', expires_at=99, created_at=1)
        ],
    }
    for name, values in rows.items():
        connection.execute(_table(connection, name).insert(), values)
    return _snapshot(connection, PI_TABLES)


def _snapshot(connection, names: set[str]) -> dict[str, list[dict]]:
    return {
        name: [dict(row) for row in connection.execute(sa.select(_table(connection, name))).mappings()]
        for name in names
    }


def _seed_auth_and_versioned_content(connection) -> None:
    connection.execute(
        _table(connection, 'auth')
        .insert()
        .values(id='sentinel-user', email='migration@example.invalid', password='sentinel-hash', active=True)
    )
    for kind in ('skill', 'model', 'tool', 'function'):
        values = dict(
            id=f'sentinel-{kind}',
            user_id='sentinel-user',
            name=f'Sentinel {kind}',
            created_at=1,
            updated_at=2,
            meta={} if kind == 'skill' else '{}',
        )
        if kind != 'model':
            values['content'] = '# sentinel bytes — never execute\n'
        if kind == 'skill':
            values['description'] = 'sentinel skill'
            values['is_active'] = True
        connection.execute(_table(connection, kind).insert().values(**values))


def _assert_reconciled(connection) -> None:
    inspector = sa.inspect(connection)
    assert PI_TABLES | HISTORY_TABLES <= set(inspector.get_table_names())
    assert {'mfa', 'session_stamp'} <= {column['name'] for column in inspector.get_columns('auth')}
    claim = next(column for column in inspector.get_columns('prompt_insights_run') if column['name'] == 'active_claim')
    assert claim['type'].length == 16
    assert 'uq_prompt_insights_run_active_claim' in {
        constraint['name'] for constraint in inspector.get_unique_constraints('prompt_insights_run')
    }
    assert (
        connection.execute(sa.text('SELECT version_num FROM alembic_version')).scalars().all() == _scripts().get_heads()
    )
    if connection.dialect.name == 'postgresql':
        indexes = {index['name']: index for index in inspector.get_indexes('file')}
        assert 'file_pending_knowledge_idx' in indexes
        index = indexes['file_pending_knowledge_idx']
        assert 'knowledge_id' in str(index['expressions'])
        predicate = str(index['dialect_options']['postgresql_where'])
        assert all(value in predicate for value in ('status', 'pending', 'processing'))
    else:
        assert 'file_pending_knowledge_idx' not in {index['name'] for index in inspector.get_indexes('file')}


def _exercise_upgrade(url: str, start: str | None, schema: str = '') -> None:
    engine = sa.create_engine(url)
    try:
        if schema:

            @sa.event.listens_for(engine, 'connect')
            def set_search_path(dbapi_connection, _record):
                with dbapi_connection.cursor() as cursor:
                    cursor.execute(f'SET search_path TO "{schema}"')
                dbapi_connection.commit()

        pi_before = None
        history_before = None
        if start:
            _upgrade(url, start, schema)
            with engine.begin() as connection:
                assert connection.execute(sa.text('SELECT version_num FROM alembic_version')).scalar_one() == start
                _seed_auth_and_versioned_content(connection)
                if start == FORK_HEAD:
                    pi_before = _seed_prompt_insights(connection)
                else:
                    for kind in ('skill', 'model', 'tool', 'function'):
                        connection.execute(
                            _table(connection, f'{kind}_history')
                            .insert()
                            .values(
                                **{
                                    'id': f'sentinel-{kind}-history',
                                    f'{kind}_id': f'sentinel-{kind}',
                                    'snapshot': {'sentinel': kind},
                                    'user_id': 'sentinel-user',
                                    'created_at': 2,
                                }
                            )
                        )
                    connection.execute(
                        _table(connection, 'auth')
                        .update()
                        .values(mfa={'sentinel': 'encrypted-test-value'}, session_stamp='sentinel-stamp')
                    )
                    history_before = _snapshot(connection, HISTORY_TABLES)
                auth_before = _snapshot(connection, {'auth'})['auth'][0]
        _upgrade(url, 'head', schema)
        with engine.connect() as connection:
            _assert_reconciled(connection)
            if start:
                auth_after = _snapshot(connection, {'auth'})['auth'][0]
                assert all(auth_after[key] == value for key, value in auth_before.items())
            if pi_before is not None:
                assert _snapshot(connection, PI_TABLES) == pi_before
                for kind in ('skill', 'model', 'tool', 'function'):
                    row = connection.execute(sa.select(_table(connection, f'{kind}_history'))).mappings().one()
                    assert row[f'{kind}_id'] == f'sentinel-{kind}'
                    assert row['user_id'] == 'sentinel-user'
                    assert row['snapshot']['name'] == f'Sentinel {kind}'
                    if kind != 'model':
                        assert row['snapshot']['content'] == '# sentinel bytes — never execute\n'
            if history_before is not None:
                assert _snapshot(connection, HISTORY_TABLES) == history_before
        # A second singular-head upgrade must not duplicate or rewrite preserved data.
        _upgrade(url, 'head', schema)
        with engine.connect() as connection:
            _assert_reconciled(connection)
            if pi_before is not None:
                assert _snapshot(connection, PI_TABLES) == pi_before
            if history_before is not None:
                assert _snapshot(connection, HISTORY_TABLES) == history_before
    finally:
        engine.dispose()


def test_upgrade_preserves_fork_data(tmp_path):
    _exercise_upgrade(f'sqlite:///{tmp_path / "fork.db"}', FORK_HEAD)


def test_upgrade_from_upstream_head(tmp_path):
    _exercise_upgrade(f'sqlite:///{tmp_path / "upstream.db"}', UPSTREAM_HEAD)


def test_empty_database_upgrade(tmp_path):
    _exercise_upgrade(f'sqlite:///{tmp_path / "empty.db"}', None)


def test_startup_migration_failure_is_not_swallowed(tmp_path):
    url = f'sqlite:///{tmp_path / "startup.db"}'
    _upgrade(url, 'head')
    result = subprocess.run(
        [
            sys.executable,
            '-c',
            'from open_webui import config\n'
            'from alembic import command\n'
            'def fail_upgrade(*args, **kwargs):\n'
            '    raise RuntimeError("migration-startup-sentinel")\n'
            'command.upgrade = fail_upgrade\n'
            'config.run_migrations()\n',
        ],
        cwd=ROOT,
        env=_migration_env(url),
        text=True,
        capture_output=True,
        timeout=120,
    )
    assert result.returncode != 0
    assert 'RuntimeError: migration-startup-sentinel' in result.stderr


@pytest.mark.skipif(
    not os.environ.get('TEST_POSTGRES_URL'), reason='TEST_POSTGRES_URL not set; PostgreSQL not exercised'
)
@pytest.mark.parametrize('start', [FORK_HEAD, UPSTREAM_HEAD, None], ids=['fork', 'upstream', 'empty'])
def test_postgres_upgrade_creates_pending_files_index(start):
    url = os.environ['TEST_POSTGRES_URL']
    engine = sa.create_engine(url)
    assert engine.dialect.name == 'postgresql'
    schema = f'reconciliation_{uuid.uuid4().hex}'
    try:
        with engine.begin() as connection:
            connection.execute(sa.schema.CreateSchema(schema))
        _exercise_upgrade(url, start, schema)
    finally:
        with engine.begin() as connection:
            connection.execute(sa.schema.DropSchema(schema, cascade=True))
        engine.dispose()
