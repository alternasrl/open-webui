import asyncio
import sys
from contextlib import asynccontextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.append(str(Path(__file__).resolve().parents[3]))

from open_webui.prompt_insights import pipeline as pipeline_module


@pytest.mark.parametrize('entry_point', ['scheduler', 'pipeline'])
@pytest.mark.parametrize('cancellations', [1, 2])
def test_claim_exit_error_then_cleanup_cancellation_propagates(tmp_path, monkeypatch, entry_point, cancellations):
    async def scenario():
        from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
        from open_webui.models.prompt_insights import Base, PromptInsightsRun, PromptInsightsRuns
        import open_webui.internal.db as internal_db

        engine = create_async_engine(f'sqlite+aiosqlite:///{tmp_path / "cleanup-cancellation.db"}')
        sessions = async_sessionmaker(engine, expire_on_commit=False)
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)

        claimed_ids = []
        original_claim = PromptInsightsRuns.claim_run
        original_fail = pipeline_module._fail_claimed_run
        cleanup_started, release_cleanup = asyncio.Event(), asyncio.Event()
        failed_exit = False

        async def claim_run(*args, **kwargs):
            run = await original_claim(*args, **kwargs)
            if run is not None:
                claimed_ids.append(run.id)
            return run

        @asynccontextmanager
        async def get_test_db():
            nonlocal failed_exit
            async with sessions() as session:
                yield session
                if claimed_ids and not failed_exit:
                    failed_exit = True
                    raise RuntimeError('DB context cleanup failed')

        async def fail_claimed_run(*args, **kwargs):
            cleanup_started.set()
            await release_cleanup.wait()
            await original_fail(*args, **kwargs)

        monkeypatch.setattr(internal_db, 'get_async_db', get_test_db)
        monkeypatch.setattr(PromptInsightsRuns, 'claim_run', claim_run)
        monkeypatch.setattr(pipeline_module, '_fail_claimed_run', fail_claimed_run)
        app = SimpleNamespace(state=SimpleNamespace(redis=None))
        coroutine = (
            pipeline_module.run_prompt_insights_if_due(app)
            if entry_point == 'scheduler'
            else pipeline_module.PromptInsightsPipeline(app).run(0, 99)
        )
        task = asyncio.create_task(coroutine)
        try:
            await asyncio.wait_for(cleanup_started.wait(), timeout=1)
            async with sessions() as session:
                row = await session.get(PromptInsightsRun, claimed_ids[0])
                assert row.status == 'running'
                assert row.active_claim == 'active'
            for _ in range(cancellations):
                task.cancel()
                await asyncio.sleep(0)
                assert not task.done()
            release_cleanup.set()
            await asyncio.gather(task, return_exceptions=True)
            assert await PromptInsightsRuns.get_active_run() is None
            async with sessions() as session:
                row = await session.get(PromptInsightsRun, claimed_ids[0])
                assert row.status == 'failed'
                assert row.active_claim is None
                assert await original_claim(100, 101, db=session) is not None
            assert not hasattr(app.state, 'prompt_insights_task')
            assert task.cancelled() is True
            with pytest.raises(asyncio.CancelledError):
                task.result()
        finally:
            release_cleanup.set()
            if not task.done():
                task.cancel()
            await asyncio.gather(task, return_exceptions=True)
            await engine.dispose()

    asyncio.run(scenario())


@pytest.mark.parametrize('entry_point', ['scheduler', 'pipeline'])
@pytest.mark.parametrize('failure', ['cancelled_exit', 'cancelled_claim', 'error_exit'])
def test_committed_claim_is_released_before_handoff(tmp_path, monkeypatch, entry_point, failure):
    async def scenario():
        from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
        from open_webui.models.prompt_insights import Base, PromptInsightsRun, PromptInsightsRuns
        import open_webui.internal.db as internal_db

        engine = create_async_engine(f'sqlite+aiosqlite:///{tmp_path / "handoff.db"}')
        sessions = async_sessionmaker(engine, expire_on_commit=False)
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)

        committed, release = asyncio.Event(), asyncio.Event()
        claimed_ids = []
        original_claim = PromptInsightsRuns.claim_run

        async def claim_run(*args, **kwargs):
            run = await original_claim(*args, **kwargs)
            if run is not None:
                claimed_ids.append(run.id)
                if failure == 'cancelled_claim':
                    committed.set()
                    await release.wait()
            return run

        @asynccontextmanager
        async def get_test_db():
            async with sessions() as session:
                yield session
                if claimed_ids and not committed.is_set():
                    committed.set()
                    await release.wait()
                    if failure == 'error_exit':
                        raise RuntimeError('DB context cleanup failed')

        monkeypatch.setattr(internal_db, 'get_async_db', get_test_db)
        monkeypatch.setattr(PromptInsightsRuns, 'claim_run', claim_run)
        app = SimpleNamespace(state=SimpleNamespace(redis=None))
        if entry_point == 'scheduler':
            coroutine = pipeline_module.run_prompt_insights_if_due(app)
        else:
            coroutine = pipeline_module.PromptInsightsPipeline(app).run(0, 99)
        task = asyncio.create_task(coroutine)
        try:
            await asyncio.wait_for(committed.wait(), timeout=1)
            async with sessions() as session:
                row = await session.get(PromptInsightsRun, claimed_ids[0])
                assert row.status == 'running'
                assert row.active_claim == 'active'
            if failure.startswith('cancelled'):
                task.cancel()
                await asyncio.sleep(0)
                release.set()
                with pytest.raises(asyncio.CancelledError):
                    await task
            else:
                release.set()
                if entry_point == 'scheduler':
                    assert await task is None
                else:
                    with pytest.raises(RuntimeError, match='DB context cleanup failed'):
                        await task
            assert not hasattr(app.state, 'prompt_insights_task')
            assert await PromptInsightsRuns.get_active_run() is None
            async with sessions() as session:
                row = await session.get(PromptInsightsRun, claimed_ids[0])
                assert row.status == 'failed'
                assert row.error_message
                assert await original_claim(100, 101, db=session) is not None
        finally:
            release.set()
            if not task.done():
                task.cancel()
            await asyncio.gather(task, return_exceptions=True)
            await engine.dispose()

    asyncio.run(scenario())


@pytest.mark.parametrize('entry_point', ['scheduler', 'manual'])
def test_late_prompt_in_current_second_is_fetched_next_window(tmp_path, monkeypatch, entry_point):
    async def scenario():
        from fastapi import BackgroundTasks, FastAPI
        from starlette.requests import Request
        from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
        from open_webui.models.chat_messages import ChatMessage
        from open_webui.models.prompt_insights import Base, PromptInsightsRuns
        from open_webui.routers.analytics import trigger_prompt_insights_run
        import open_webui.internal.db as internal_db

        engine = create_async_engine(f'sqlite+aiosqlite:///{tmp_path / "late-prompt.db"}')
        sessions = async_sessionmaker(engine, expire_on_commit=False)
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)

        @asynccontextmanager
        async def get_test_db():
            async with sessions() as session:
                yield session

        now = [100.25]
        fetched, windows = [], []

        class FetchOnlyPipeline(pipeline_module.PromptInsightsPipeline):
            async def run(self, window_start, window_end, run_id=None):
                windows.append((window_start, window_end))
                records = await self._fetch_prompts(window_start, window_end)
                fetched.extend(content for _, content in records)
                async with sessions() as session:
                    if len(windows) == 1:
                        # This is the old inclusive window_end: inserted after the fetch.
                        session.add(
                            ChatMessage(
                                id='late',
                                chat_id='chat',
                                user_id='user',
                                role='user',
                                content='late prompt',
                                created_at=int(now[0]),
                            )
                        )
                    await PromptInsightsRuns.complete_run(run_id, len(records), 0, 0, db=session)
                    await session.commit()

        monkeypatch.setattr(internal_db, 'get_async_db', get_test_db)
        monkeypatch.setattr(pipeline_module, 'PromptInsightsPipeline', FetchOnlyPipeline)
        monkeypatch.setattr(pipeline_module.time, 'time', lambda: now[0])
        monkeypatch.setattr(pipeline_module.time, 'time_ns', lambda: int(now[0] * 1_000_000_000))
        monkeypatch.setenv('PROMPT_INSIGHTS_INTERVAL_HOURS', '0')
        app = FastAPI()
        app.state.redis = None
        try:
            for clock in (100.25, 101.25):
                now[0] = clock
                if entry_point == 'scheduler':
                    assert await pipeline_module.run_prompt_insights_if_due(app)
                else:
                    async with sessions() as session:
                        response = await trigger_prompt_insights_run(
                            BackgroundTasks(),
                            Request({'type': 'http', 'app': app}),
                            user=SimpleNamespace(role='admin'),
                            db=session,
                        )
                    assert response.status == 'started'
                await app.state.prompt_insights_task
            assert fetched == ['late prompt']
            assert windows == [(0, 99), (100, 100)]
        finally:
            if hasattr(app.state, 'prompt_insights_task'):
                await pipeline_module.stop_prompt_insights(app)
            await engine.dispose()

    asyncio.run(scenario())


def test_scheduler_launches_tracked_pipeline_without_waiting(monkeypatch):
    async def scenario():
        started = asyncio.Event()
        release = asyncio.Event()
        tracked = []

        @asynccontextmanager
        async def get_test_db():
            yield object()

        async def latest_completed(db=None):
            return None

        async def claim_run(window_start, window_end, db=None):
            return SimpleNamespace(id='claimed-run')

        class FakePipeline:
            def __init__(self, app):
                self.app = app

            async def run(self, window_start, window_end, run_id=None):
                assert (window_start, window_end) == (0, 99)
                started.set()
                await release.wait()

        async def track_task(redis, coroutine, id=None, task_id=None):
            task = asyncio.create_task(coroutine)
            tracked.append((id, task))
            return 'tracked-task', task

        import open_webui.internal.db as internal_db
        import open_webui.models.prompt_insights as model_module
        import open_webui.tasks as tasks_module

        monkeypatch.setattr(internal_db, 'get_async_db', get_test_db)
        monkeypatch.setattr(model_module.PromptInsightsRuns, 'get_latest_completed_run', latest_completed)
        monkeypatch.setattr(model_module.PromptInsightsRuns, 'claim_run', claim_run)
        monkeypatch.setattr(pipeline_module, 'PromptInsightsPipeline', FakePipeline)
        monkeypatch.setattr(tasks_module, 'create_task', track_task)
        monkeypatch.setenv('PROMPT_INSIGHTS_INTERVAL_HOURS', '0')
        monkeypatch.setattr(pipeline_module.time, 'time', lambda: 100)
        monkeypatch.setattr(pipeline_module.time, 'time_ns', lambda: 200_000_000_000)

        app = SimpleNamespace(state=SimpleNamespace(redis=None))
        task_id = await asyncio.wait_for(pipeline_module.run_prompt_insights_if_due(app), timeout=0.1)

        assert task_id == 'tracked-task'
        assert tracked[0][0] == 'prompt-insights'
        await asyncio.wait_for(started.wait(), timeout=0.1)
        assert tracked[0][1].done() is False
        assert app.state.prompt_insights_task is tracked[0][1]

        release.set()
        await tracked[0][1]
        assert app.state._prompt_insights_last_run_ns == 99_000_000_000

    asyncio.run(scenario())


@pytest.mark.parametrize('wait_until_started', [True, False])
def test_shutdown_cancels_and_awaits_claimed_pipeline(tmp_path, monkeypatch, wait_until_started):
    async def scenario():
        from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
        from open_webui.models.prompt_insights import Base, PromptInsightsRun, PromptInsightsRuns
        import open_webui.internal.db as internal_db

        engine = create_async_engine(f'sqlite+aiosqlite:///{tmp_path / "shutdown.db"}')
        sessions = async_sessionmaker(engine, expire_on_commit=False)
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)

        @asynccontextmanager
        async def get_test_db():
            async with sessions() as session:
                yield session

        monkeypatch.setattr(internal_db, 'get_async_db', get_test_db)
        started, stopped = asyncio.Event(), asyncio.Event()

        class BlockingPipeline:
            def __init__(self, app):
                pass

            async def run(self, *args, **kwargs):
                started.set()
                try:
                    await asyncio.Event().wait()
                finally:
                    await asyncio.sleep(0)
                    stopped.set()

        monkeypatch.setattr(pipeline_module, 'PromptInsightsPipeline', BlockingPipeline)
        app = SimpleNamespace(state=SimpleNamespace(redis=None))
        await pipeline_module.run_prompt_insights_if_due(app)
        if wait_until_started:
            await asyncio.wait_for(started.wait(), timeout=1)
        run_id = app.state.prompt_insights_run_id
        await pipeline_module.stop_prompt_insights(app)
        assert stopped.is_set() is wait_until_started
        assert app.state.prompt_insights_task.done()
        assert not hasattr(app.state, '_prompt_insights_last_run_ns')
        async with sessions() as session:
            row = await session.get(PromptInsightsRun, run_id)
            assert row.status == 'failed'
            assert row.active_claim is None
        await engine.dispose()

    asyncio.run(scenario())


@pytest.mark.parametrize('local_task_started', [True, False])
def test_failed_task_registration_releases_claim(tmp_path, monkeypatch, local_task_started):
    async def scenario():
        from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
        from open_webui.models.prompt_insights import Base, PromptInsightsRuns
        import open_webui.internal.db as internal_db
        import open_webui.tasks as tasks_module

        engine = create_async_engine(f'sqlite+aiosqlite:///{tmp_path / "registration.db"}')
        sessions = async_sessionmaker(engine, expire_on_commit=False)
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)

        @asynccontextmanager
        async def get_test_db():
            async with sessions() as session:
                yield session

        async def fail_registration(redis, coroutine, **kwargs):
            coroutine.close()
            raise RuntimeError('registration failed')

        async def fail_redis_registration(*args, **kwargs):
            await asyncio.sleep(0)
            raise RuntimeError('Redis registration failed')

        async def blocking_run(*args, **kwargs):
            await asyncio.Event().wait()

        monkeypatch.setattr(internal_db, 'get_async_db', get_test_db)
        if local_task_started:
            monkeypatch.setattr(tasks_module, 'redis_save_task', fail_redis_registration)
            monkeypatch.setattr(pipeline_module.PromptInsightsPipeline, 'run', blocking_run)
        else:
            monkeypatch.setattr(tasks_module, 'create_task', fail_registration)
        app = SimpleNamespace(state=SimpleNamespace(redis=object() if local_task_started else None))

        # The fake Redis supports registration failure, but no network cleanup.
        async def cleanup(*args, **kwargs):
            pass

        monkeypatch.setattr(tasks_module, 'redis_cleanup_task', cleanup)
        previous_tasks = set(tasks_module.tasks)
        assert await pipeline_module.run_prompt_insights_if_due(app) is None
        assert await PromptInsightsRuns.get_active_run() is None
        runs = await PromptInsightsRuns.list_runs()
        assert len(runs) == 1
        assert runs[0].status == 'failed'
        await asyncio.sleep(0)
        assert set(tasks_module.tasks) == previous_tasks
        await engine.dispose()

    asyncio.run(scenario())


def test_lifespan_stops_scheduler_and_pi_before_closing_sessions(monkeypatch):
    async def scenario():
        from fastapi import FastAPI
        import open_webui.main as main
        import open_webui.utils.automations as automations
        import open_webui.utils.mfa as mfa
        import open_webui.utils.session_pool as session_pool
        from open_webui.models.prompt_insights import PromptInsightsRuns

        stopped = []

        async def noop(*args, **kwargs):
            pass

        async def config_get(key, default=None):
            return default

        async def background():
            await asyncio.Event().wait()

        async def scheduler(app):
            try:
                await background()
            finally:
                stopped.append('scheduler')

        async def insights():
            try:
                await background()
            finally:
                await asyncio.sleep(0)
                stopped.append('insights')

        async def no_active_run(db=None):
            return None

        async def close_session():
            assert stopped == ['scheduler', 'insights']
            stopped.append('sessions')

        for name in (
            'import_legacy_config_json',
            'seed_registered_defaults',
            'initialize_runtime_config',
            'migrate_legacy_webhook_config',
            'install_tool_and_function_dependencies',
            'publish_event',
        ):
            monkeypatch.setattr(main, name, noop)
        for name in ('periodic_socket_authentication', 'periodic_usage_pool_cleanup', 'periodic_session_pool_cleanup'):
            monkeypatch.setattr(main, name, background)
        for name, value in (
            ('THREAD_POOL_SIZE', 0),
            ('RESET_CONFIG_ON_START', False),
            ('LICENSE_KEY', ''),
            ('WEBUI_ADMIN_EMAIL', ''),
            ('SAFE_MODE', False),
            ('WEBSOCKET_MANAGER', ''),
            ('ENABLE_TOOL_SERVERS', False),
        ):
            monkeypatch.setattr(main, name, value)
        monkeypatch.setattr(main, 'start_logger', lambda: None)
        monkeypatch.setattr(main, 'get_redis_client', lambda **kwargs: None)
        monkeypatch.setattr(main.Config, 'get', config_get)
        monkeypatch.setattr(mfa, 'validate_mfa_configuration', noop)
        monkeypatch.setattr(automations, 'scheduler_worker_loop', scheduler)
        monkeypatch.setattr(session_pool, 'close_session', close_session)
        monkeypatch.setattr(PromptInsightsRuns, 'get_active_run', no_active_run)
        app = FastAPI()
        async with main.lifespan(app):
            app.state.prompt_insights_task = asyncio.create_task(insights())
            app.state.prompt_insights_run_id = 'run-id'
            await asyncio.sleep(0)
        assert stopped == ['scheduler', 'insights', 'sessions']
        assert app.state.scheduler_worker_loop.done()
        assert app.state.prompt_insights_task.done()

    asyncio.run(scenario())
