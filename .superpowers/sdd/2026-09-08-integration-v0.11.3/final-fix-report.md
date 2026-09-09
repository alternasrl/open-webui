# Integration v0.11.3 Final Fix Report

## Scope

Implemented the complete final-review fix wave for Prompt Insights and restored the
static assets removed by the prior synthetic merge. The confirmed
`CHAT_STREAM_RESPONSE_CHUNK_MAX_BUFFER_SIZE` correction required no code change.

## Root Causes and Fixes

### Portable trend accumulation

`PromptInsightsTableStore.upsert_trend()` used the SQLite-only
`sqlalchemy.dialects.sqlite.insert().on_conflict_do_update()` API and committed
the session internally. This failed to compile on PostgreSQL/MySQL and broke the
pipeline transaction into per-cluster commits.

The implementation now uses generic SQLAlchemy `UPDATE` and `INSERT`
statements. It first atomically increments an existing row, then attempts an
insert inside a savepoint when no row exists; a concurrent unique-key winner is
handled by retrying the increment after the savepoint rollback. The helper only
commits when it owns the session, preserving caller transaction boundaries.

### Atomic cross-instance run claim

The prior lock performed a read for a running row and later inserted a new run
in a separate transaction. Concurrent workers could both pass the read and
create active runs.

Migration `6c7d8e9f0a1b` adds nullable `prompt_insights_run.active_claim` with the
named unique constraint `uq_prompt_insights_run_active_claim`. Active runs use
the sentinel value `active`; completed and failed runs clear it to `NULL`.
Because all supported databases permit multiple `NULL` values in a unique
constraint, the invariant allows run history while guaranteeing only one active
claim. The claim is a single insert/commit operation, and uniqueness conflicts
are treated as a lost claim only when an active row is present.

The migration is based on the prior integration head `28f62ff35ad1`. If legacy
data contains multiple running rows, it keeps the newest as active and marks
older rows failed before creating the unique constraint.

### Non-blocking tracked scheduler execution

`scheduler_worker_loop()` awaited `run_prompt_insights_if_due()`, which previously
ran the complete pipeline before returning. The due-check now atomically claims
the run and registers the pipeline coroutine through the existing
`open_webui.tasks.create_task()` task registry. It returns immediately after
registration, keeping timer, automation, and calendar polling responsive.

The manual analytics trigger also claims atomically before registering its
FastAPI background task and passes the claimed run ID into the pipeline.

### Atomic successful/failed pipeline writes

Cluster rows, trend increments, and the completed-run status now share one
explicit transaction. `upsert_trend()` no longer commits a caller-provided
session. Any persistence error rolls back every cluster and trend contribution,
then the failed run status is committed in a separate transaction. Embedding
cache writes remain independent of analytics result writes.

### Static asset restoration

Restored the following tracked files exactly from `main`, without restoring any
unrelated files:

- `backend/open_webui/static/apple-touch-icon.png`
- `backend/open_webui/static/custom.css`
- `backend/open_webui/static/favicon-96x96.png`
- `backend/open_webui/static/favicon.ico`
- `backend/open_webui/static/favicon.png`
- `backend/open_webui/static/favicon.svg`
- `backend/open_webui/static/loader.js`
- `backend/open_webui/static/logo.png`
- `backend/open_webui/static/site.webmanifest`
- `backend/open_webui/static/splash-dark.png`
- `backend/open_webui/static/splash.png`
- `backend/open_webui/static/user-import.csv`
- `backend/open_webui/static/user.png`
- `backend/open_webui/static/web-app-manifest-192x192.png`
- `backend/open_webui/static/web-app-manifest-512x512.png`

Existing tracked static subdirectories and any package `__init__.py` files were
left unchanged.

## Files Changed

- `backend/open_webui/models/prompt_insights.py`
- `backend/open_webui/prompt_insights/pipeline.py`
- `backend/open_webui/routers/analytics.py`
- `backend/open_webui/migrations/versions/6c7d8e9f0a1b_add_prompt_insights_active_claim.py`
- `backend/open_webui/test/models/test_prompt_insights_schema.py`
- `backend/open_webui/test/models/test_prompt_insights_transactions.py`
- `backend/open_webui/test/models/test_prompt_insights_scheduler.py`
- Restored static files listed above

## Validation

### Focused Prompt Insights model, pipeline, privacy, ML, scheduler, and router tests

Command:

```text
WEBUI_SECRET_KEY=test-secret-key .venv/bin/python -m pytest -q \
  backend/open_webui/test/models/test_prompt_insights_ml.py \
  backend/open_webui/test/models/test_prompt_insights_pipeline.py \
  backend/open_webui/test/models/test_prompt_insights_privacy.py \
  backend/open_webui/test/models/test_prompt_insights_schema.py \
  backend/open_webui/test/models/test_prompt_insights_transactions.py \
  backend/open_webui/test/models/test_prompt_insights_scheduler.py \
  backend/open_webui/test/routers/test_analytics_prompt_insights.py
```

Output:

```text
27 passed, 5 skipped, 2 warnings in 1.35s
```

The warnings are pre-existing SQLAlchemy `declarative_base()` and
`datetime.utcfromtimestamp()` deprecations.

### New concurrency, rollback, portability, and scheduler tests

Command:

```text
WEBUI_SECRET_KEY=test-secret-key .venv/bin/python -m pytest -q \
  backend/open_webui/test/models/test_prompt_insights_transactions.py \
  backend/open_webui/test/models/test_prompt_insights_scheduler.py
```

Output:

```text
4 passed, 2 warnings in 1.47s
```

These tests prove:

- Two concurrent database sessions produce exactly one active run claim.
- A failure after multiple cluster/trend writes rolls back all new clusters and
  restores the previous trend count before the run is marked failed.
- Trend statements compile for PostgreSQL and MySQL without SQLite-specific
  conflict syntax.
- The scheduler path registers a tracked task and returns while the pipeline
  coroutine remains blocked/running.

### Formatting and syntax

Commands and output:

```text
.venv/bin/python -m black --check <changed Python files>
All done! 7 files would be left unchanged.

.venv/bin/python -m compileall -q <changed Python files>
(no output; exit 0)

git diff --check
(no output; exit 0)
```

### Alembic

Command and output:

```text
cd backend/open_webui
WEBUI_SECRET_KEY=test-secret-key ../../.venv/bin/alembic -c alembic.ini heads
6c7d8e9f0a1b (head)
```

A fresh SQLite database upgraded from base through `6c7d8e9f0a1b` successfully.
A second migration test upgraded to `28f62ff35ad1`, inserted two legacy running
rows, then upgraded to head. Result:

```text
[('old', 'failed', None), ('new', 'running', 'active')]
```

### Static assets

After staging the restored files:

```text
git diff --cached main -- backend/open_webui/static
(no output; exit 0)

git status --short --untracked-files=all backend/open_webui/static
```

The status contains only the expected staged additions relative to the
integration branch; no static asset remains untracked.
