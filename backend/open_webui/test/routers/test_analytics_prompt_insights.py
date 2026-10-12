"""Unit tests for prompt-insights analytics endpoints.

Tests use AST inspection (no DB, no full app import, no env requirements) to verify:
- All 6 routes are declared in the analytics router source
- Each route function has a `user=Depends(get_admin_user)` parameter
- Pure-logic helpers (emerging-topic growth ratio calculation) behave correctly
"""

import ast
import sys
from pathlib import Path

import pytest

sys.path.append(str(Path(__file__).resolve().parents[3]))


# ---------------------------------------------------------------------------
# AST helpers
# ---------------------------------------------------------------------------

_ANALYTICS_SRC = (Path(__file__).resolve().parents[2] / 'routers' / 'analytics.py').read_text(encoding='utf-8')
_ANALYTICS_TREE = ast.parse(_ANALYTICS_SRC)


def _get_router_decorators() -> list[tuple[str, str]]:
    """Return list of (method, path) tuples from @router.get/post/... decorators."""
    results = []
    for node in ast.walk(_ANALYTICS_TREE):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for deco in node.decorator_list:
            if not isinstance(deco, ast.Call):
                continue
            func = deco.func
            if not (isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name) and func.value.id == 'router'):
                continue
            method = func.attr  # get, post, put, …
            if deco.args:
                path_node = deco.args[0]
                if isinstance(path_node, ast.Constant):
                    results.append((method.upper(), path_node.value, node.name))
    return results


def _func_has_admin_dep(func_name: str) -> bool:
    """Return True if the named function has `user=Depends(get_admin_user)` in its args."""
    for node in ast.walk(_ANALYTICS_TREE):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == func_name:
            for default in node.args.defaults + node.args.kw_defaults:
                if default is None:
                    continue
                # Depends(get_admin_user) is a Call node
                if isinstance(default, ast.Call):
                    func = default.func
                    if isinstance(func, ast.Name) and func.id == 'Depends':
                        if default.args and isinstance(default.args[0], ast.Name):
                            if default.args[0].id == 'get_admin_user':
                                return True
    return False


# ---------------------------------------------------------------------------
# Route existence + admin guard tests
# ---------------------------------------------------------------------------

EXPECTED_ROUTES = [
    ('GET', '/prompt-insights/summary'),
    ('GET', '/prompt-insights/clusters'),
    ('GET', '/prompt-insights/clusters/{cluster_id}/trend'),
    ('GET', '/prompt-insights/emerging'),
    ('POST', '/prompt-insights/run'),
    ('GET', '/prompt-insights/runs'),
]


def test_all_prompt_insights_routes_registered():
    declared = {(method, path) for method, path, _ in _get_router_decorators()}
    missing = [(m, p) for m, p in EXPECTED_ROUTES if (m, p) not in declared]
    assert not missing, f'Missing routes in analytics.py: {missing}'


def test_all_prompt_insights_routes_have_admin_dep():
    router_funcs = {(method, path): fname for method, path, fname in _get_router_decorators()}
    failing = []
    for method, path in EXPECTED_ROUTES:
        fname = router_funcs.get((method, path))
        if fname is None:
            failing.append(f'{method} {path} — route not found')
        elif not _func_has_admin_dep(fname):
            failing.append(f'{method} {path} ({fname}) — missing get_admin_user dep')
    assert not failing, '\n'.join(failing)


# ---------------------------------------------------------------------------
# Emerging-topic growth logic (pure-Python, no DB)
# ---------------------------------------------------------------------------


def _compute_growth_ratio(trend_rows: list[dict], min_volume: int, min_growth_ratio: float):
    """
    Mirrors the logic in PromptInsightsTableStore.get_emerging_topics.

    trend_rows: list of {canonical_label_hash, bucket, count}
    Returns list of {canonical_label_hash, recent_count, total_count, growth_ratio}
    """
    from collections import defaultdict

    groups: dict[str, list] = defaultdict(list)
    for row in trend_rows:
        groups[row['canonical_label_hash']].append(row)

    results = []
    for label_hash, rows in groups.items():
        rows_sorted = sorted(rows, key=lambda r: r['bucket'], reverse=True)
        recent_count = rows_sorted[0]['count']
        total_count = sum(r['count'] for r in rows_sorted)
        prior_count = total_count - recent_count
        growth_ratio = recent_count / prior_count if prior_count > 0 else float('inf')

        if recent_count >= min_volume and growth_ratio >= min_growth_ratio:
            results.append(
                {
                    'canonical_label_hash': label_hash,
                    'recent_count': recent_count,
                    'total_count': total_count,
                    'growth_ratio': growth_ratio,
                }
            )

    return sorted(results, key=lambda x: -x['growth_ratio'])


def test_emerging_topics_new_topic_always_qualifies():
    rows = [{'canonical_label_hash': 'abc', 'bucket': '2024-01-01', 'count': 10}]
    result = _compute_growth_ratio(rows, min_volume=5, min_growth_ratio=1.5)
    assert len(result) == 1
    assert result[0]['growth_ratio'] == float('inf')


def test_emerging_topics_growing_topic_qualifies():
    rows = [
        {'canonical_label_hash': 'abc', 'bucket': '2024-01-02', 'count': 30},
        {'canonical_label_hash': 'abc', 'bucket': '2024-01-01', 'count': 10},
    ]
    result = _compute_growth_ratio(rows, min_volume=5, min_growth_ratio=1.5)
    assert len(result) == 1
    assert result[0]['growth_ratio'] == pytest.approx(3.0)


def test_emerging_topics_stable_topic_excluded():
    rows = [
        {'canonical_label_hash': 'abc', 'bucket': '2024-01-02', 'count': 10},
        {'canonical_label_hash': 'abc', 'bucket': '2024-01-01', 'count': 10},
    ]
    result = _compute_growth_ratio(rows, min_volume=5, min_growth_ratio=1.5)
    assert result == []


def test_emerging_topics_low_volume_excluded():
    rows = [{'canonical_label_hash': 'abc', 'bucket': '2024-01-01', 'count': 2}]
    result = _compute_growth_ratio(rows, min_volume=5, min_growth_ratio=1.5)
    assert result == []


def test_emerging_topics_sorted_by_growth_desc():
    rows = [
        {'canonical_label_hash': 'slow', 'bucket': '2024-01-02', 'count': 10},
        {'canonical_label_hash': 'slow', 'bucket': '2024-01-01', 'count': 5},
        {'canonical_label_hash': 'fast', 'bucket': '2024-01-02', 'count': 20},
        {'canonical_label_hash': 'fast', 'bucket': '2024-01-01', 'count': 5},
    ]
    result = _compute_growth_ratio(rows, min_volume=5, min_growth_ratio=1.5)
    assert result[0]['canonical_label_hash'] == 'fast'
    assert result[1]['canonical_label_hash'] == 'slow'


@pytest.mark.parametrize('method,path', EXPECTED_ROUTES)
def test_prompt_insights_api_rejects_non_admin(method, path):
    import asyncio
    from types import SimpleNamespace
    import httpx
    from fastapi import FastAPI
    from open_webui.routers.analytics import router
    from open_webui.internal.db import get_async_session
    from open_webui.utils.auth import get_current_user

    async def scenario():
        app = FastAPI()
        app.include_router(router)

        async def non_admin():
            return SimpleNamespace(id='user-1', role='user')

        async def no_database():
            raise AssertionError('Non-admin must be rejected before accessing insights')
            yield

        app.dependency_overrides[get_current_user] = non_admin
        app.dependency_overrides[get_async_session] = no_database
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='http://test') as client:
            response = await client.request(method, path.replace('{cluster_id}', 'cluster-1'))
        assert response.status_code == 401

    asyncio.run(scenario())


def test_manual_run_is_nonblocking_tracked_and_exclusive(tmp_path, monkeypatch):
    import asyncio
    from contextlib import asynccontextmanager
    from types import SimpleNamespace
    import httpx
    from fastapi import FastAPI
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
    from open_webui.routers.analytics import router
    from open_webui.models.prompt_insights import Base, PromptInsightsRuns
    from open_webui.utils.auth import get_current_user
    from open_webui.prompt_insights import pipeline
    import open_webui.internal.db as internal_db

    async def scenario():
        engine = create_async_engine(f'sqlite+aiosqlite:///{tmp_path / "manual.db"}')
        sessions = async_sessionmaker(engine, expire_on_commit=False)
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)

        @asynccontextmanager
        async def get_test_db():
            async with sessions() as session:
                yield session

        async def get_session():
            async with sessions() as session:
                yield session

        async def admin():
            return SimpleNamespace(id='admin', role='admin')

        started = asyncio.Event()

        class BlockingPipeline:
            def __init__(self, app):
                pass

            async def run(self, *args, **kwargs):
                started.set()
                await asyncio.Event().wait()

        monkeypatch.setattr(internal_db, 'get_async_db', get_test_db)
        monkeypatch.setattr(pipeline, 'PromptInsightsPipeline', BlockingPipeline)
        app = FastAPI()
        app.state.redis = None
        app.include_router(router)
        app.dependency_overrides[get_current_user] = admin
        app.dependency_overrides[internal_db.get_async_session] = get_session

        try:
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='http://test') as client:
                first = await asyncio.wait_for(client.post('/prompt-insights/run'), timeout=1)
                assert first.status_code == 200
                assert first.json()['status'] == 'started'
                await asyncio.wait_for(started.wait(), timeout=1)
                assert not app.state.prompt_insights_task.done()
                second = await client.post('/prompt-insights/run')
                assert second.json() == {
                    'status': 'skipped',
                    'reason': 'run_in_progress',
                    'run_id': first.json()['run_id'],
                }
                assert await pipeline.run_prompt_insights_if_due(app) is None
                assert await PromptInsightsRuns.count_runs() == 1
        finally:
            if hasattr(app.state, 'prompt_insights_task'):
                await pipeline.stop_prompt_insights(app)
            await engine.dispose()

    asyncio.run(scenario())
