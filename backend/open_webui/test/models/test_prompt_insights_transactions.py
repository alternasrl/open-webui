import asyncio
import sys
from contextlib import asynccontextmanager
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest
from sqlalchemy import func, select
from sqlalchemy.dialects import mysql, postgresql
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.schema import CreateTable

sys.path.append(str(Path(__file__).resolve().parents[3]))

from open_webui.models.prompt_insights import (
    Base,
    PromptCluster,
    PromptClusterTrend,
    PromptInsightsRun,
    PromptInsightsRuns,
    PromptInsightsTable,
    _canonical_label_hash,
    _trend_increment_statement,
    _trend_insert_statement,
)
from open_webui.prompt_insights.pipeline import PromptInsightsPipeline, _resolve_window_start


def _session_factory(database_url: str):
    engine = create_async_engine(database_url)
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    return engine, sessions


def test_trend_statements_compile_for_supported_server_dialects():
    statements = (
        _trend_increment_statement('label-hash', '2026-09-09', 3),
        _trend_insert_statement('label-hash', '2026-09-09', 3, 'run-id'),
    )

    for dialect in (postgresql.dialect(), mysql.dialect()):
        compiled = [str(statement.compile(dialect=dialect)) for statement in statements]
        assert all('prompt_cluster_trend' in sql for sql in compiled)
        assert all('ON CONFLICT' not in sql.upper() for sql in compiled)


def test_mysql_active_claim_ddl_uses_bounded_unique_varchar():
    ddl = str(CreateTable(PromptInsightsRun.__table__).compile(dialect=mysql.dialect()))

    assert 'active_claim VARCHAR(16)' in ddl
    assert 'CONSTRAINT uq_prompt_insights_run_active_claim UNIQUE (active_claim)' in ddl
    assert 'active_claim TEXT' not in ddl


def test_only_one_concurrent_run_claim_wins(tmp_path):
    async def scenario():
        engine, sessions = _session_factory(f'sqlite+aiosqlite:///{tmp_path / "claims.db"}')
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)

        async with sessions() as first, sessions() as second:
            claims = await asyncio.gather(
                PromptInsightsRuns.claim_run(10, 20, db=first),
                PromptInsightsRuns.claim_run(10, 20, db=second),
            )

        async with sessions() as session:
            active_count = await session.scalar(
                select(func.count()).select_from(PromptInsightsRun).where(PromptInsightsRun.active_claim == 'active')
            )

        await engine.dispose()
        assert sum(claim is not None for claim in claims) == 1
        assert active_count == 1

    asyncio.run(scenario())


@pytest.mark.parametrize('failure_type', [RuntimeError, asyncio.CancelledError])
def test_failed_pipeline_rolls_back_all_cluster_and_trend_writes(tmp_path, monkeypatch, failure_type):
    async def scenario():
        engine, sessions = _session_factory(f'sqlite+aiosqlite:///{tmp_path / "rollback.db"}')
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)

        @asynccontextmanager
        async def get_test_db():
            async with sessions() as session:
                yield session

        import open_webui.internal.db as internal_db

        monkeypatch.setattr(internal_db, 'get_async_db', get_test_db)

        old_run = None
        topic_hash = _canonical_label_hash('alpha')
        async with sessions() as session:
            old_run = await PromptInsightsRuns.claim_run(1, 2, db=session)
        assert old_run is not None
        async with sessions() as session:
            await PromptInsightsTable.upsert_trend(topic_hash, '1970-01-01', 5, old_run.id, db=session)
            await PromptInsightsRuns.complete_run(old_run.id, 5, 1, 0, db=session)
            await session.commit()

        clusterer = ModuleType('open_webui.prompt_insights.clusterer')
        clusterer.cluster_embeddings = lambda embeddings: ([0, 1], set())
        monkeypatch.setitem(sys.modules, 'open_webui.prompt_insights.clusterer', clusterer)

        embedder = ModuleType('open_webui.prompt_insights.embedder')

        class FakeEmbedder:
            async def embed_texts(self, texts, db):
                assert texts == ['Contact [EMAIL]', 'second']
                return [[0.0], [1.0]]

        embedder.PromptInsightsEmbedder = FakeEmbedder
        monkeypatch.setitem(sys.modules, 'open_webui.prompt_insights.embedder', embedder)

        labeler = ModuleType('open_webui.prompt_insights.labeler')
        labeler.build_cluster_label_prompt = lambda keywords: ' '.join(keywords)
        monkeypatch.setitem(sys.modules, 'open_webui.prompt_insights.labeler', labeler)

        tfidf = ModuleType('open_webui.prompt_insights.tfidf')
        tfidf.extract_cluster_keywords = lambda texts, labels: {0: ['alpha'], 1: ['beta']}
        monkeypatch.setitem(sys.modules, 'open_webui.prompt_insights.tfidf', tfidf)

        pipeline = PromptInsightsPipeline(SimpleNamespace(state=SimpleNamespace(MODELS={})))

        async def fetch_prompts(window_start, window_end):
            return [('user-1', 'Contact owner@example.com'), ('user-2', 'second')]

        async def generate_label(prompt, keywords):
            return keywords[0]

        monkeypatch.setattr(pipeline, '_fetch_prompts', fetch_prompts)
        monkeypatch.setattr(pipeline, '_generate_label', generate_label)

        original_upsert = PromptInsightsTable.upsert_trend
        calls = 0

        async def fail_after_second_write(*args, **kwargs):
            nonlocal calls
            await original_upsert(*args, **kwargs)
            calls += 1
            if calls == 2:
                raise failure_type('forced persistence failure')

        monkeypatch.setattr(PromptInsightsTable, 'upsert_trend', fail_after_second_write)

        with pytest.raises(failure_type, match='forced persistence failure'):
            await pipeline.run(0, 100)

        async with sessions() as session:
            trend_rows = (await session.execute(select(PromptClusterTrend))).scalars().all()
            failed_run = (
                (
                    await session.execute(
                        select(PromptInsightsRun)
                        .where(PromptInsightsRun.status == 'failed')
                        .order_by(PromptInsightsRun.created_at.desc())
                    )
                )
                .scalars()
                .first()
            )
            failed_clusters = (
                await session.scalar(
                    select(func.count()).select_from(PromptCluster).where(PromptCluster.run_id == failed_run.id)
                )
                if failed_run
                else None
            )

        await engine.dispose()
        assert [(row.canonical_label_hash, row.count) for row in trend_rows] == [(topic_hash, 5)]
        assert failed_run is not None
        assert failed_run.active_claim is None
        assert failed_clusters == 0

    asyncio.run(scenario())


@pytest.mark.parametrize('failure', ['missing_dependency', 'cancelled'])
def test_claim_released_when_pipeline_cannot_finish(tmp_path, monkeypatch, failure):
    async def scenario():
        engine, sessions = _session_factory(f'sqlite+aiosqlite:///{tmp_path / "failures.db"}')
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)

        @asynccontextmanager
        async def get_test_db():
            async with sessions() as session:
                yield session

        import open_webui.internal.db as internal_db

        monkeypatch.setattr(internal_db, 'get_async_db', get_test_db)
        async with sessions() as session:
            claimed = await PromptInsightsRuns.claim_run(0, 100, db=session)

        clusterer = ModuleType('open_webui.prompt_insights.clusterer')
        clusterer.cluster_embeddings = lambda embeddings: ([], set())
        monkeypatch.setitem(
            sys.modules,
            'open_webui.prompt_insights.clusterer',
            None if failure == 'missing_dependency' else clusterer,
        )
        tfidf = ModuleType('open_webui.prompt_insights.tfidf')
        tfidf.extract_cluster_keywords = lambda texts, labels: {}
        monkeypatch.setitem(sys.modules, 'open_webui.prompt_insights.tfidf', tfidf)
        pipeline = PromptInsightsPipeline(SimpleNamespace(state=SimpleNamespace(MODELS={})))
        started = asyncio.Event()

        async def fetch(*args):
            started.set()
            await asyncio.Event().wait()

        monkeypatch.setattr(pipeline, '_fetch_prompts', fetch)
        task = asyncio.create_task(pipeline.run(0, 100, run_id=claimed.id))
        if failure == 'cancelled':
            await asyncio.wait_for(started.wait(), timeout=1)
            task.cancel()
        with pytest.raises(ModuleNotFoundError if failure == 'missing_dependency' else asyncio.CancelledError):
            await task
        async with sessions() as session:
            row = await session.get(PromptInsightsRun, claimed.id)
            assert row.status == 'failed'
            assert row.active_claim is None
            assert await session.scalar(select(func.count()).select_from(PromptCluster)) == 0
            assert await session.scalar(select(func.count()).select_from(PromptClusterTrend)) == 0
        await engine.dispose()

    asyncio.run(scenario())


def test_failed_backfill_retries_history_and_completed_window_resumes_without_overlap(tmp_path, monkeypatch):
    async def scenario():
        engine, sessions = _session_factory(f'sqlite+aiosqlite:///{tmp_path / "backfill.db"}')
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)

        @asynccontextmanager
        async def get_test_db():
            async with sessions() as session:
                yield session

        import open_webui.internal.db as internal_db

        monkeypatch.setattr(internal_db, 'get_async_db', get_test_db)
        async with sessions() as session:
            first = await PromptInsightsRuns.claim_run(0, 100, db=session)
            await PromptInsightsRuns.fail_run(first.id, 'dependency unavailable', db=session)
            await session.commit()
        assert await _resolve_window_start(24, None) == 0
        async with sessions() as session:
            retry = await PromptInsightsRuns.claim_run(0, 200, db=session)
            await PromptInsightsRuns.complete_run(retry.id, 0, 0, 0, db=session)
            await session.commit()
        assert await _resolve_window_start(24, None) == 201
        assert await _resolve_window_start(24, 200_000_000_000) == 201
        await engine.dispose()

    asyncio.run(scenario())


@pytest.mark.parametrize('stage', ['clustering', 'keywords'])
@pytest.mark.parametrize('cancel', [True, False])
def test_clustering_does_not_block_event_loop(tmp_path, monkeypatch, stage, cancel):
    import threading

    async def scenario():
        engine, sessions = _session_factory(f'sqlite+aiosqlite:///{tmp_path / "responsive.db"}')
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)

        @asynccontextmanager
        async def get_test_db():
            async with sessions() as session:
                yield session

        import open_webui.internal.db as internal_db

        monkeypatch.setattr(internal_db, 'get_async_db', get_test_db)
        loop = asyncio.get_running_loop()
        started = asyncio.Event()
        release = threading.Event()
        finished = threading.Event()
        clusterer = ModuleType('open_webui.prompt_insights.clusterer')

        def blocking_compute(*args):
            loop.call_soon_threadsafe(started.set)
            release.wait(timeout=2)
            finished.set()
            return ([-1], {0}) if stage == 'clustering' else {}

        clusterer.cluster_embeddings = blocking_compute if stage == 'clustering' else lambda embeddings: ([-1], {0})
        monkeypatch.setitem(sys.modules, 'open_webui.prompt_insights.clusterer', clusterer)
        embedder = ModuleType('open_webui.prompt_insights.embedder')

        class FakeEmbedder:
            async def embed_texts(self, texts, db):
                return [[0.0]]

        embedder.PromptInsightsEmbedder = FakeEmbedder
        monkeypatch.setitem(sys.modules, 'open_webui.prompt_insights.embedder', embedder)
        tfidf = ModuleType('open_webui.prompt_insights.tfidf')
        tfidf.extract_cluster_keywords = blocking_compute if stage == 'keywords' else lambda texts, labels: {}
        monkeypatch.setitem(sys.modules, 'open_webui.prompt_insights.tfidf', tfidf)
        pipeline = PromptInsightsPipeline(SimpleNamespace(state=SimpleNamespace(MODELS={})))

        async def fetch(*args):
            return [('user', 'prompt')]

        monkeypatch.setattr(pipeline, '_fetch_prompts', fetch)
        task = asyncio.create_task(pipeline.run(0, 100))
        try:
            await asyncio.wait_for(started.wait(), timeout=2)
            assert not finished.is_set(), 'Event loop could not run until clustering had finished'
            if cancel:
                task.cancel()
                with pytest.raises(asyncio.TimeoutError):
                    await asyncio.wait_for(asyncio.shield(task), timeout=0.1)
        finally:
            release.set()
            if cancel:
                with pytest.raises(asyncio.CancelledError):
                    await task
            else:
                await task
            assert finished.is_set(), 'Awaited pipeline must not leave CPU work running'
            await engine.dispose()

    asyncio.run(scenario())
