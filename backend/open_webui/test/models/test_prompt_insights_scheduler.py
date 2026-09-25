import asyncio
import sys
from contextlib import asynccontextmanager
from pathlib import Path
from types import SimpleNamespace

sys.path.append(str(Path(__file__).resolve().parents[3]))

from open_webui.prompt_insights import pipeline as pipeline_module


def test_scheduler_launches_tracked_pipeline_without_waiting(monkeypatch):
    async def scenario():
        started = asyncio.Event()
        release = asyncio.Event()
        tracked = []

        @asynccontextmanager
        async def get_test_db():
            yield object()

        async def count_runs(db=None):
            return 0

        async def claim_run(window_start, window_end, db=None):
            return SimpleNamespace(id='claimed-run')

        class FakePipeline:
            def __init__(self, app):
                self.app = app

            async def run(self, window_start, window_end, run_id=None):
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
        monkeypatch.setattr(model_module.PromptInsightsRuns, 'count_runs', count_runs)
        monkeypatch.setattr(model_module.PromptInsightsRuns, 'claim_run', claim_run)
        monkeypatch.setattr(pipeline_module, 'PromptInsightsPipeline', FakePipeline)
        monkeypatch.setattr(tasks_module, 'create_task', track_task)
        monkeypatch.setenv('PROMPT_INSIGHTS_INTERVAL_HOURS', '0')

        app = SimpleNamespace(state=SimpleNamespace(redis=None))
        task_id = await asyncio.wait_for(pipeline_module.run_prompt_insights_if_due(app), timeout=0.1)

        assert task_id == 'tracked-task'
        assert tracked[0][0] == 'prompt-insights'
        await asyncio.wait_for(started.wait(), timeout=0.1)
        assert tracked[0][1].done() is False

        release.set()
        await tracked[0][1]
        assert app.state._prompt_insights_last_run_ns > 0

    asyncio.run(scenario())
