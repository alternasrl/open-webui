# Upstream v0.11.3 Integration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rebase the alternasrl/open-webui fork customizations onto the real upstream `v0.11.3` tag, preserve proprietary features and NIS2 compliance behavior, and cut the release/taggable integration branch `integration-v0.11.3`.

**Architecture:** Treat the integration as a cumulative patch transfer from the true upstream ancestor `f9590b8017199e56d5e953657e6498e3cef1d246` onto `v0.11.3`, then resolve overlapping files in risk-ordered batches. Keep the fork-only feature directories intact, re-check Alembic head alignment after the code merge, and add an automated route-vs-NIS2 coverage harness so new upstream endpoints cannot silently fall back to generic audit actions again.

**Tech Stack:** Git patch/apply workflow, Python 3.11/3.12, FastAPI, Alembic, pytest, SvelteKit, TypeScript, npm, ESLint, Ruff/pylint.

**Spec:** `patches/README.md`

## Global Constraints

- Source tags must use `v{MAJOR}.{MINOR}.{PATCH}-{YYMMDD}[{lettera}]`.
- Integration branches must use `integration-v{MAJOR}.{MINOR}.{PATCH}`.
- Dates use `YYMMDD` and never `DDMMYY`.
- Do not use the local `v0.11.0` tag as the merge base; the true upstream ancestor already present in `main` is `f9590b8017199e56d5e953657e6498e3cef1d246`.
- Preserve the fork customizations introduced on `f9590b801..main` (115 commits; Prompt Insights, Analytics/Routing/Cross-filter, NIS2 audit/access-log/OIDC, MCP import compatibility, Alembic multi-head fix, `nltk` bump, scrollbar UI fixes).
- Keep the integration as one cohesive plan; do not split it into multiple plan documents.

---

## Confirmed Source Context

- `patches/README.md` already documents the `integration-v0.10.2` precedent and explicitly describes the repo convention of replaying a cumulative fork diff onto a newer upstream tag.
- `git merge-base --is-ancestor f9590b801 main` succeeds, so `f9590b801` is the real upstream anchor for this integration.
- `git diff --stat f9590b801..main` reports the expected 146 touched files and preserves the exact command needed to capture the cumulative fork patch.
- `backend/open_webui/middleware/access_log.py` currently builds `_NIS2_ACTION_RULES` in `217-527`, assigns them at `528`, and classifies requests in `_classify_action()` at `666-674`.
- `backend/open_webui/test/middleware/test_access_log.py` already contains focused action-classification coverage, including `CONFIG_OAUTH_ADMIN`, routing analytics, object-reference extraction, and NIS2 security-set assertions.
- `backend/open_webui/alembic.ini` lives at `backend/open_webui/alembic.ini`, and the fork already changed `backend/open_webui/config.py` from `command.upgrade(..., 'head')` to `command.upgrade(..., 'heads')`.
- `docs/superpowers/plans/` already exists and is the correct destination for this plan file.

## File Structure

| File | Responsibility |
| --- | --- |
| `patches/integration-v0.11.3-customizations-from-main.patch` | Raw cumulative transport patch generated from `git diff --binary f9590b801..main` before touching the new integration branch. |
| `patches/integration-v0.11.3-customizations-files.txt` | Flat inventory of every fork-touched path used to track patch coverage while resolving conflicts. |
| `backend/open_webui/utils/middleware.py` | Highest-risk merge surface: chat pipeline, MCP tool injection, routing usage merge, response streaming helpers. |
| `backend/open_webui/main.py` | Highest-risk merge surface: app wiring, audit middleware ordering, access-log setup, OIDC routes, provider compatibility endpoints. |
| `backend/open_webui/utils/tools.py` | Highest-risk merge surface: built-in tool gating, subagent enablement, mutating tool restrictions. |
| `backend/open_webui/utils/oauth.py` | Medium-risk merge surface: OAuth/OIDC behavior, MCP auth compatibility, access-log cache invalidation. |
| `backend/open_webui/config.py` | Medium-risk merge surface: runtime config defaults and the local Alembic `heads` upgrade fix. |
| `backend/open_webui/env.py` | Medium-risk merge surface: audit/access-log environment variables and related defaults. |
| `backend/open_webui/routers/retrieval.py` | Medium-risk merge surface: `/api/v1/retrieval/process/url` and admin retrieval config endpoints. |
| `backend/open_webui/routers/knowledge.py` | Medium-risk merge surface: reindex and external-knowledge routes touched by upstream. |
| `backend/open_webui/routers/users.py`, `backend/open_webui/routers/auths.py`, `backend/open_webui/routers/openai.py` | Medium-risk merge surfaces for user settings, OAuth admin config, and provider-model management routes. |
| `backend/open_webui/routers/chats.py`, `backend/open_webui/routers/ollama.py`, `backend/open_webui/routers/channels.py`, `backend/open_webui/routers/models.py`, `backend/open_webui/routers/audio.py`, `backend/open_webui/routers/files.py`, `backend/open_webui/routers/folders.py`, `backend/open_webui/routers/functions.py`, `backend/open_webui/routers/images.py`, `backend/open_webui/routers/notifications.py`, `backend/open_webui/routers/scim.py`, `backend/open_webui/routers/terminals.py`, `backend/open_webui/models/chat_messages.py`, `backend/open_webui/models/folders.py`, `backend/open_webui/models/users.py`, `src/lib/apis/openai/index.ts`, `src/lib/components/admin/Settings/Connections.svelte` | Low-risk overlapping files that still need explicit merge confirmation. |
| `backend/open_webui/prompt_insights/**`, `backend/open_webui/routers/analytics.py`, `src/lib/components/admin/Analytics/**`, `docs/superpowers/**`, `patches/**`, `docker-compose.yaml`, `backend/open_webui/middleware/__init__.py`, `backend/open_webui/utils/mcp/client.py`, `src/lib/components/admin/Settings/Connections/OllamaConnection.svelte`, `src/lib/components/admin/Settings/Connections/OpenAIConnection.svelte` | Fork-only paths that should replay cleanly and must survive intact. |
| `backend/open_webui/middleware/access_log.py` | NIS2 action map that must gain the new v0.11.3 routes under a dedicated comment block. |
| `backend/open_webui/test/middleware/access_log_route_coverage.py` | New automated route-inventory script that compares `app.routes` to `_NIS2_ACTION_RULES` and flags dead rules. |
| `backend/open_webui/test/middleware/test_access_log.py` | Concrete regression tests for new v0.11.3 action types and security-set decisions. |
| `backend/open_webui/migrations/versions/*.py` | Existing migration chain plus an Alembic merge revision if the integration produces multiple heads. |
| `package.json`, `package-lock.json`, `patches/README.md` | Release metadata: version bump to `0.11.3-260908` and the documented patch series for this integration. |

## Task Map

1. Create the integration branch from `v0.11.3` and capture the raw cumulative fork patch plus file inventory.
2. Apply the raw patch and hand-resolve the three critical conflict files: `utils/middleware.py`, `main.py`, `utils/tools.py`.
3. Resolve the medium-risk backend overlaps, keeping upstream `v0.11.3` APIs while reintroducing fork behavior.
4. Replay low-risk overlaps and restore every fork-only path that should survive unchanged.
5. Verify Alembic lineage and create a merge migration only if the integrated tree now has multiple heads.
6. Re-apply the recent fork fixes that are easy to lose during conflict resolution (`nltk`, MCP import compatibility, Alembic `heads`, scrollbar UI).
7. Add automated NIS2 route coverage, extend `access_log.py` for the missing v0.11.3 endpoints, and update access-log tests.
8. Run the full backend/frontend validation gate and fix only integration-caused regressions.
9. Bump the version to `0.11.3-260908`, document the patch series in `patches/README.md`, and create the final source tag.

### Task 1: Create the integration branch and preserve the cumulative fork artifact

**Files:**
- Create: `patches/integration-v0.11.3-customizations-from-main.patch`
- Create: `patches/integration-v0.11.3-customizations-files.txt`

**Interfaces:**
- Consumes: Git refs `f9590b8017199e56d5e953657e6498e3cef1d246`, `main`, `v0.11.3`.
- Produces: `patches/integration-v0.11.3-customizations-from-main.patch` (unified diff) and `patches/integration-v0.11.3-customizations-files.txt` (one path per line) for Tasks 2-4.

- [ ] **Step 1: Create the integration branch from the real upstream tag**

```bash
git switch v0.11.3
git switch -c integration-v0.11.3
git status --short
```

Expected: `integration-v0.11.3` points at `v0.11.3`, with no merge work started yet.

- [ ] **Step 2: Capture the exact cumulative fork diff from the true upstream ancestor**

```bash
mkdir -p patches
git diff --binary f9590b8017199e56d5e953657e6498e3cef1d246..main > patches/integration-v0.11.3-customizations-from-main.patch
git diff --name-only f9590b8017199e56d5e953657e6498e3cef1d246..main > patches/integration-v0.11.3-customizations-files.txt
```

The `--binary` flag preserves non-text payloads and keeps the artifact usable with `git apply --3way`.

- [ ] **Step 3: Validate that the captured artifact matches the expected scope**

```bash
test -s patches/integration-v0.11.3-customizations-from-main.patch
test -s patches/integration-v0.11.3-customizations-files.txt
grep -F "backend/open_webui/utils/middleware.py" patches/integration-v0.11.3-customizations-files.txt
grep -F "backend/open_webui/middleware/access_log.py" patches/integration-v0.11.3-customizations-files.txt
grep -F "backend/open_webui/routers/analytics.py" patches/integration-v0.11.3-customizations-files.txt
grep -F "src/lib/components/admin/Analytics/Dashboard.svelte" patches/integration-v0.11.3-customizations-files.txt
wc -l patches/integration-v0.11.3-customizations-files.txt
```

Expected: the inventory contains the high-risk backend files, NIS2 middleware, analytics UI, and roughly the known 146-file fork surface.

- [ ] **Step 4: Commit the raw artifact before applying it**

```bash
git add patches/integration-v0.11.3-customizations-from-main.patch patches/integration-v0.11.3-customizations-files.txt
git commit -m "chore: capture v0.11.3 integration patch seed"
```

### Task 2: Apply the raw patch and resolve the critical conflict trio

**Files:**
- Modify: `backend/open_webui/utils/middleware.py`
- Modify: `backend/open_webui/main.py`
- Modify: `backend/open_webui/utils/tools.py`
- Test: `backend/open_webui/test/middleware/test_routing_usage_merge.py`

**Interfaces:**
- Consumes: `patches/integration-v0.11.3-customizations-from-main.patch` from Task 1.
- Produces: merged `utils/middleware.py`, `main.py`, and `utils/tools.py` that still expose `merge_routing_usage(usage: dict | None, metadata: dict | None) -> dict`, `setup_access_logging(app: FastAPI) -> None`, and the `subagents.enable` / `subagents.background_enabled` gating paths used by later tasks.

- [ ] **Step 1: Apply the raw patch with 3-way fallback and stop at the first unresolved state**

```bash
git apply --3way --reject patches/integration-v0.11.3-customizations-from-main.patch || true
git status --short
git diff --name-only --diff-filter=U
find . -name '*.rej'
```

Expected: unresolved conflicts include the three critical files listed above.

- [ ] **Step 2: Merge `backend/open_webui/utils/middleware.py` around the routing, MCP, and streaming seams**

After editing the file, all of these checks must pass:

```bash
grep -n "def merge_routing_usage" backend/open_webui/utils/middleware.py
grep -n "metadata\\['mcp_clients'\\] = mcp_clients" backend/open_webui/utils/middleware.py
grep -n "async def connect_mcp_server" backend/open_webui/utils/middleware.py
grep -n "usage = merge_routing_usage(usage, metadata)" backend/open_webui/utils/middleware.py
python -m py_compile backend/open_webui/utils/middleware.py
```

The resolved file must keep upstream `v0.11.3` control flow and reintroduce the fork helpers instead of choosing one side wholesale.

- [ ] **Step 3: Merge `backend/open_webui/main.py` without losing audit/access-log or OIDC wiring**

After editing the file, all of these checks must pass:

```bash
grep -n "setup_access_logging(app)" backend/open_webui/main.py
grep -n "AuditLoggingMiddleware" backend/open_webui/main.py
grep -n "oauth/backchannel-logout" backend/open_webui/main.py
grep -n "mcp_clients" backend/open_webui/main.py
python -m py_compile backend/open_webui/main.py
```

Keep the upstream router registrations and compatibility endpoints, but preserve the fork middleware ordering and the access-log/OIDC paths already shipped in `main`.

- [ ] **Step 4: Merge `backend/open_webui/utils/tools.py` so subagent gating survives the upstream changes**

After editing the file, all of these checks must pass:

```bash
grep -n "subagents.enable" backend/open_webui/utils/tools.py
grep -n "subagents.background_enabled" backend/open_webui/utils/tools.py
grep -n "MUTATING_MEMORY_TOOLS" backend/open_webui/utils/tools.py
python -m py_compile backend/open_webui/utils/tools.py
```

Do not drop the fork restrictions around `delegate_task` or the upstream built-in tool catalog changes.

- [ ] **Step 5: Run a route-registry smoke test before moving on**

```bash
PYTHONPATH=backend python - <<'PY'
from fastapi.routing import APIRoute
from open_webui.main import app

routes = {
    (method, route.path)
    for route in app.routes
    if isinstance(route, APIRoute)
    for method in (route.methods or set())
    if method not in {'HEAD', 'OPTIONS'}
}

required = {
    ('GET', '/api/models'),
    ('GET', '/api/v1/models'),
    ('POST', '/oauth/backchannel-logout'),
}

missing = sorted(required - routes)
assert not missing, missing
print('critical-route-smoke-ok')
PY
PYTHONPATH=backend pytest -q backend/open_webui/test/middleware/test_routing_usage_merge.py
```

Expected: the app imports successfully and the routing-usage helper test still passes.

- [ ] **Step 6: Commit the critical conflict resolution**

```bash
git add backend/open_webui/utils/middleware.py backend/open_webui/main.py backend/open_webui/utils/tools.py
git commit -m "merge: resolve critical v0.11.3 integration conflicts"
```

### Task 3: Resolve the medium-risk backend overlaps

**Files:**
- Modify: `backend/open_webui/utils/oauth.py`
- Modify: `backend/open_webui/config.py`
- Modify: `backend/open_webui/env.py`
- Modify: `backend/open_webui/routers/retrieval.py`
- Modify: `backend/open_webui/routers/knowledge.py`
- Modify: `backend/open_webui/routers/users.py`
- Modify: `backend/open_webui/routers/auths.py`
- Modify: `backend/open_webui/routers/openai.py`

**Interfaces:**
- Consumes: the integrated app entrypoint from Task 2.
- Produces: merged OAuth/config/router surfaces that expose `OAuthConfigResponse`, `/api/v1/retrieval/process/url`, `/api/v1/knowledge/reindex`, and `/openai/models/{url_idx}/{catalog|download|load|unload|sse}` for Tasks 5-7.

- [ ] **Step 1: Merge `utils/oauth.py` and keep both the MCP compatibility and access-log cache invalidation hooks**

After editing the file, all of these checks must pass:

```bash
grep -n "from mcp.shared.auth import" backend/open_webui/utils/oauth.py
grep -n "invalidate_user_cache" backend/open_webui/utils/oauth.py
grep -n "Back-Channel Logout" backend/open_webui/utils/oauth.py
python -m py_compile backend/open_webui/utils/oauth.py
```

Keep the upstream OIDC/MCP logic, but preserve the fork cache-eviction calls that make NIS2 login audit data visible immediately after OAuth session changes.

- [ ] **Step 2: Merge `config.py` and `env.py` without regressing fork runtime defaults**

After editing the two files, all of these checks must pass:

```bash
grep -n "command.upgrade(alembic_cfg, 'heads')" backend/open_webui/config.py
grep -n "AUDIT_LOGS_FILE_PATH" backend/open_webui/env.py
grep -n "ENABLE_AUDIT_GET_REQUESTS" backend/open_webui/env.py
grep -n "subagents.system_prompt" backend/open_webui/config.py
python -m py_compile backend/open_webui/config.py backend/open_webui/env.py
```

Keep upstream config additions, but do not regress the fork's audit env vars or the Alembic multi-head safety change.

- [ ] **Step 3: Merge the medium-risk router group with route-level smoke checks**

After editing `retrieval.py`, `knowledge.py`, `users.py`, `auths.py`, and `openai.py`, run:

```bash
PYTHONPATH=backend python - <<'PY'
from fastapi.routing import APIRoute
from open_webui.main import app

routes = {
    (method, route.path)
    for route in app.routes
    if isinstance(route, APIRoute)
    for method in (route.methods or set())
    if method not in {'HEAD', 'OPTIONS'}
}

required = {
    ('POST', '/api/v1/retrieval/process/url'),
    ('POST', '/api/v1/knowledge/reindex'),
    ('GET', '/api/v1/auths/admin/config/oauth'),
    ('POST', '/api/v1/auths/admin/config/oauth'),
    ('POST', '/openai/models/{url_idx}/download'),
    ('POST', '/openai/models/{url_idx}/load'),
    ('POST', '/openai/models/{url_idx}/unload'),
    ('GET', '/openai/models/{url_idx}/catalog'),
    ('GET', '/openai/models/{url_idx}/sse'),
}

missing = sorted(required - routes)
assert not missing, missing
print('medium-risk-route-smoke-ok')
PY
python -m py_compile \
  backend/open_webui/routers/retrieval.py \
  backend/open_webui/routers/knowledge.py \
  backend/open_webui/routers/users.py \
  backend/open_webui/routers/auths.py \
  backend/open_webui/routers/openai.py
```

Resolve conflicts in favor of the upstream route signatures and response models, then reintroduce only the fork behavior actually shipped on `main`.

- [ ] **Step 4: Commit the medium-risk backend merges**

```bash
git add \
  backend/open_webui/utils/oauth.py \
  backend/open_webui/config.py \
  backend/open_webui/env.py \
  backend/open_webui/routers/retrieval.py \
  backend/open_webui/routers/knowledge.py \
  backend/open_webui/routers/users.py \
  backend/open_webui/routers/auths.py \
  backend/open_webui/routers/openai.py
git commit -m "merge: resolve medium-risk v0.11.3 overlaps"
```

### Task 4: Replay the low-risk overlaps and restore all fork-only paths

**Files:**
- Modify: `backend/open_webui/routers/chats.py`
- Modify: `backend/open_webui/routers/ollama.py`
- Modify: `backend/open_webui/routers/channels.py`
- Modify: `backend/open_webui/routers/models.py`
- Modify: `backend/open_webui/routers/audio.py`
- Modify: `backend/open_webui/routers/files.py`
- Modify: `backend/open_webui/routers/folders.py`
- Modify: `backend/open_webui/routers/functions.py`
- Modify: `backend/open_webui/routers/images.py`
- Modify: `backend/open_webui/routers/notifications.py`
- Modify: `backend/open_webui/routers/scim.py`
- Modify: `backend/open_webui/routers/terminals.py`
- Modify: `backend/open_webui/models/chat_messages.py`
- Modify: `backend/open_webui/models/folders.py`
- Modify: `backend/open_webui/models/users.py`
- Modify: `src/lib/apis/openai/index.ts`
- Modify: `src/lib/components/admin/Settings/Connections.svelte`
- Modify: `backend/open_webui/prompt_insights/**`
- Modify: `backend/open_webui/routers/analytics.py`
- Modify: `src/lib/components/admin/Analytics/**`
- Modify: `docs/superpowers/**`
- Modify: `patches/**`
- Modify: `docker-compose.yaml`
- Modify: `backend/open_webui/middleware/__init__.py`
- Modify: `backend/open_webui/utils/mcp/client.py`
- Modify: `src/lib/components/admin/Settings/Connections/OllamaConnection.svelte`
- Modify: `src/lib/components/admin/Settings/Connections/OpenAIConnection.svelte`
- Test: `backend/open_webui/test/models/test_prompt_insights_schema.py`
- Test: `backend/open_webui/test/models/test_prompt_insights_pipeline.py`
- Test: `backend/open_webui/test/routers/test_analytics_prompt_insights.py`
- Test: `backend/open_webui/test/routers/test_analytics_routing_unit.py`
- Test: `src/lib/components/admin/Analytics/Dashboard.test.ts`
- Test: `src/lib/components/admin/Analytics/cross-filter-state.test.ts`
- Test: `src/lib/components/admin/Analytics/prompt-insights.test.ts`

**Interfaces:**
- Consumes: the merged integration branch from Task 3.
- Produces: a tree where the fork-only Prompt Insights, Analytics, docs, patches, and connection components are present exactly once and low-risk route overlaps no longer contain conflict markers.

- [ ] **Step 1: Resolve the remaining low-risk overlaps instead of blanket-checking out one side**

Use the tracked inventory to finish the remaining overlapping files:

```bash
git diff --name-only --diff-filter=U
python - <<'PY'
from pathlib import Path

inventory = Path('patches/integration-v0.11.3-customizations-files.txt').read_text(encoding='utf-8').splitlines()
for path in inventory:
    if Path(path).exists():
        continue
    print(path)
PY
```

Resolve every unresolved path in the listed low-risk group, then remove any `.rej` files left by `git apply`.

- [ ] **Step 2: Restore the fork-only directories and files directly from `main` if the raw patch did not recreate them cleanly**

```bash
git restore --source=main --worktree --staged -- \
  backend/open_webui/prompt_insights \
  backend/open_webui/routers/analytics.py \
  docs/superpowers \
  docker-compose.yaml \
  backend/open_webui/middleware/__init__.py \
  backend/open_webui/utils/mcp/client.py \
  src/lib/components/admin/Analytics \
  src/lib/components/admin/Settings/Connections/OllamaConnection.svelte \
  src/lib/components/admin/Settings/Connections/OpenAIConnection.svelte
git restore --source=main --worktree --staged -- \
  ':(top)patches' \
  ':(exclude)patches/integration-v0.11.3-customizations-from-main.patch' \
  ':(exclude)patches/integration-v0.11.3-customizations-files.txt'
```

This is safe because these paths had `0` upstream commits in the analyzed range.

- [ ] **Step 3: Validate that the fork-only surfaces exist and the analytics tests still describe the shipped feature set**

```bash
test -d backend/open_webui/prompt_insights
test -f backend/open_webui/routers/analytics.py
test -f backend/open_webui/utils/mcp/client.py
test -f src/lib/components/admin/Analytics/Dashboard.svelte
test -f src/lib/components/admin/Settings/Connections/OllamaConnection.svelte
test -z "$(git diff --name-only --diff-filter=U -- src/lib/i18n)"
PYTHONPATH=backend pytest -q \
  backend/open_webui/test/models/test_prompt_insights_schema.py \
  backend/open_webui/test/models/test_prompt_insights_pipeline.py \
  backend/open_webui/test/routers/test_analytics_prompt_insights.py \
  backend/open_webui/test/routers/test_analytics_routing_unit.py
npm run test:frontend -- \
  src/lib/components/admin/Analytics/Dashboard.test.ts \
  src/lib/components/admin/Analytics/cross-filter-state.test.ts \
  src/lib/components/admin/Analytics/prompt-insights.test.ts
```

Expected: the fork-only backend modules and analytics UI still exist, and their focused regression tests pass before the broader validation gate.

- [ ] **Step 4: Commit the low-risk and fork-only replay**

```bash
git add \
  backend/open_webui \
  src/lib/apis/openai/index.ts \
  src/lib/components/admin \
  docs/superpowers \
  patches \
  docker-compose.yaml
git commit -m "merge: restore low-risk and fork-only customizations"
```

### Task 5: Verify Alembic lineage and merge heads only if the integrated tree requires it

**Files:**
- Modify: `backend/open_webui/migrations/versions/*.py`
- Validate: `backend/open_webui/alembic.ini`
- Validate: `backend/open_webui/migrations/env.py`

**Interfaces:**
- Consumes: the integrated migration tree produced by Tasks 2-4.
- Produces: a single reachable Alembic head, plus an optional merge migration file if upstream and fork histories now diverge.

- [ ] **Step 1: Inspect the post-merge Alembic head set**

```bash
PYTHONPATH=backend alembic -c backend/open_webui/alembic.ini heads
PYTHONPATH=backend alembic -c backend/open_webui/alembic.ini branches
```

Record the exact head revision IDs in the commit message or reviewer notes; this is the decision point for whether a merge migration is required.

- [ ] **Step 2: Create a merge migration only when multiple heads are present**

```bash
HEADS=$(PYTHONPATH=backend alembic -c backend/open_webui/alembic.ini heads | awk '{print $1}')
HEAD_COUNT=$(printf '%s\n' "$HEADS" | sed '/^$/d' | wc -l | tr -d ' ')
if [ "$HEAD_COUNT" -gt 1 ]; then
  PYTHONPATH=backend alembic -c backend/open_webui/alembic.ini merge -m "merge v0.11.3 integration heads" $HEADS
fi
git status --short backend/open_webui/migrations/versions
```

This command keeps the task concrete without hard-coding head IDs that are only known after the merge.

- [ ] **Step 3: Prove that `upgrade heads` works on a disposable database**

```bash
TMP_DB="$(mktemp /tmp/open-webui-v0.11.3-XXXXXX.db)"
DATABASE_URL="sqlite:///$TMP_DB" PYTHONPATH=backend alembic -c backend/open_webui/alembic.ini upgrade heads
rm -f "$TMP_DB"
PYTHONPATH=backend alembic -c backend/open_webui/alembic.ini heads
```

Expected: the disposable upgrade succeeds and the final `heads` output shows one effective head.

- [ ] **Step 4: Commit the Alembic realignment if this task created a migration**

```bash
git add backend/open_webui/migrations/versions
git diff --cached --quiet || git commit -m "fix: realign alembic heads for v0.11.3"
```

### Task 6: Re-apply the recent local fixes that are easy to lose in conflict resolution

**Files:**
- Modify: `backend/requirements.txt`
- Modify: `backend/open_webui/utils/mcp/client.py`
- Modify: `backend/open_webui/config.py`
- Modify: `src/lib/components/admin/Analytics.svelte`
- Modify: `src/lib/components/admin/Analytics/EmergingTopics.svelte`
- Modify: `src/lib/components/admin/Analytics/RoutingUsage.svelte`

**Interfaces:**
- Consumes: the merged files from Tasks 3-4.
- Produces: preserved local fixes for `nltk==3.10.0`, MCP client import compatibility, Alembic `upgrade(..., 'heads')`, and the scrollbar class changes used by the analytics UI.

- [ ] **Step 1: Re-apply the dependency and MCP compatibility fixes exactly as shipped on `main`**

After editing the files, all of these checks must pass:

```bash
grep -n "nltk==3.10.0" backend/requirements.txt
grep -n "langchain-classic==1.0.7 # CVE-2026-45134/GHSA-3644-q5cj-c5c7: fixed in 1.0.7" backend/requirements.txt
grep -n "streamable_http_client as streamablehttp_client" backend/open_webui/utils/mcp/client.py
grep -n "command.upgrade(alembic_cfg, 'heads')" backend/open_webui/config.py
python -m py_compile backend/open_webui/utils/mcp/client.py backend/open_webui/config.py
```

- [ ] **Step 2: Re-apply the shipped analytics scrollbar fixes**

After editing the Svelte files, all of these checks must pass:

```bash
grep -n "scrollbar-hover" src/lib/components/admin/Analytics.svelte
grep -n "scrollbar-hidden" src/lib/components/admin/Analytics/EmergingTopics.svelte
grep -n "scrollbar-hidden" src/lib/components/admin/Analytics/RoutingUsage.svelte
```

Keep the upstream layout changes, but preserve these fork UI classes so the analytics screens do not regress to clipped or unusable scroll regions.

- [ ] **Step 3: Run the narrow regression checks for these fixes**

```bash
PYTHONPATH=backend pytest -q backend/open_webui/test/routers/test_analytics_routing_unit.py
npm run test:frontend -- src/lib/components/admin/Analytics/Dashboard.test.ts
```

Expected: the routing analytics backend test and the main analytics frontend test both remain green after the fix re-application.

- [ ] **Step 4: Commit the restored local fixes**

```bash
git add \
  backend/requirements.txt \
  backend/open_webui/utils/mcp/client.py \
  backend/open_webui/config.py \
  src/lib/components/admin/Analytics.svelte \
  src/lib/components/admin/Analytics/EmergingTopics.svelte \
  src/lib/components/admin/Analytics/RoutingUsage.svelte
git commit -m "fix: restore fork-specific integration regressions"
```

### Task 7: Add automated NIS2 route coverage and extend `access_log.py` for v0.11.3

**Files:**
- Create: `backend/open_webui/test/middleware/access_log_route_coverage.py`
- Modify: `backend/open_webui/middleware/access_log.py:217-710`
- Modify: `backend/open_webui/test/middleware/test_access_log.py`

**Interfaces:**
- Consumes: `open_webui.main.app`, `_NIS2_ACTION_RULES`, `_NIS2_SECURITY_ACTIONS`, and the upstream `v0.11.3` runtime routes.
- Produces: `backend/open_webui/test/middleware/access_log_route_coverage.py` with `iter_runtime_routes() -> list[dict[str, object]]` and `classify_route(method: str, path: str) -> str`, plus new action types in `access_log.py` and concrete route tests in `test_access_log.py`.

- [ ] **Step 1: Create the failing route-coverage harness before editing the rule table**

Create `backend/open_webui/test/middleware/access_log_route_coverage.py` with this exact source:

```python
from __future__ import annotations

import json
from fastapi.routing import APIRoute
from open_webui.main import app
from open_webui.middleware.access_log import _NIS2_ACTION_RULES

REQUIRED_ACTIONS = {
    ('GET', '/openai/models/{url_idx}/catalog'): 'MODEL_PROVIDER_CATALOG',
    ('POST', '/openai/models/{url_idx}/download'): 'MODEL_PROVIDER_DOWNLOAD',
    ('GET', '/openai/models/{url_idx}/download/status/{job_id}'): 'MODEL_PROVIDER_DOWNLOAD_STATUS',
    ('POST', '/openai/models/{url_idx}/load'): 'MODEL_PROVIDER_LOAD',
    ('POST', '/openai/models/{url_idx}/unload'): 'MODEL_PROVIDER_UNLOAD',
    ('GET', '/openai/models/{url_idx}/sse'): 'MODEL_PROVIDER_SSE',
    ('POST', '/api/v1/retrieval/process/url'): 'RETRIEVAL_PROCESS_URL',
    ('POST', '/api/v1/memories/reindex'): 'MEMORY_REINDEX',
    ('GET', '/ollama/v1/models/{url_idx}'): 'OLLAMA_COMPAT_MODELS_READ',
    ('GET', '/ollama/api/tags/{url_idx}'): 'OLLAMA_COMPAT_TAGS_READ',
    ('GET', '/ollama/api/version/{url_idx}'): 'OLLAMA_COMPAT_VERSION_READ',
}


def classify_route(method: str, path: str) -> str:
    for pattern, rule_method, action in _NIS2_ACTION_RULES:
        if rule_method is not None and method != rule_method:
            continue
        if pattern.search(path):
            return action
    return '-'


def dependency_names(route: APIRoute) -> set[str]:
    names = set()
    for dependency in route.dependant.dependencies:
        call = getattr(dependency, 'call', None)
        name = getattr(call, '__name__', None)
        if name:
            names.add(name)
    return names


def iter_runtime_routes() -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for route in app.routes:
        if not isinstance(route, APIRoute):
            continue
        for method in sorted((route.methods or set()) - {'HEAD', 'OPTIONS'}):
            rows.append(
                {
                    'method': method,
                    'path': route.path,
                    'action': classify_route(method, route.path),
                    'dependencies': sorted(dependency_names(route)),
                }
            )
    return sorted(rows, key=lambda row: (row['path'], row['method']))


def main() -> None:
    rows = iter_runtime_routes()
    row_map = {(row['method'], row['path']): row for row in rows}

    mismatches = []
    for key, expected_action in REQUIRED_ACTIONS.items():
        row = row_map.get(key)
        if row is None:
            mismatches.append({'route': key, 'problem': 'missing runtime route'})
            continue
        if row['action'] != expected_action:
            mismatches.append({'route': key, 'expected': expected_action, 'actual': row['action']})

    admin_only_routes = {
        ('GET', '/ollama/v1/models/{url_idx}'),
        ('GET', '/ollama/api/tags/{url_idx}'),
        ('GET', '/ollama/api/version/{url_idx}'),
    }
    admin_dependency_issues = []
    for key in admin_only_routes:
        row = row_map[key]
        if 'get_admin_user' not in row['dependencies']:
            admin_dependency_issues.append({'route': key, 'dependencies': row['dependencies']})

    dead_rules = []
    for pattern, method, action in _NIS2_ACTION_RULES:
        if action in {'READ', 'WRITE_OTHER', 'DELETE_OTHER', '-'}:
            continue
        if not any((method is None or row['method'] == method) and pattern.search(row['path']) for row in rows):
            dead_rules.append({'method': method, 'pattern': pattern.pattern, 'action': action})

    report = {
        'mismatches': mismatches,
        'admin_dependency_issues': admin_dependency_issues,
        'dead_rules': dead_rules,
    }
    print(json.dumps(report, indent=2))
    if mismatches or admin_dependency_issues or dead_rules:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
```

- [ ] **Step 2: Run the new harness and confirm that the current rule table fails on the missing v0.11.3 routes**

Run:

```bash
PYTHONPATH=backend python backend/open_webui/test/middleware/access_log_route_coverage.py
```

Expected: **FAIL** with `mismatches` for the provider-model management routes, `/api/v1/retrieval/process/url`, `/api/v1/memories/reindex`, and the admin-only Ollama compatibility reads that currently collapse to generic actions.

- [ ] **Step 3: Add the v0.11.3 rules to `_compile_action_rules()` under a dedicated comment block**

Insert this block in `backend/open_webui/middleware/access_log.py` immediately before the catch-all rules:

```python
        # ── v0.11.3 new endpoints ──────────────────────────────────────────
        (rf'^/openai/models/{_ID}/catalog$', 'GET', 'MODEL_PROVIDER_CATALOG'),
        (rf'^/openai/models/{_ID}/download$', 'POST', 'MODEL_PROVIDER_DOWNLOAD'),
        (rf'^/openai/models/{_ID}/download/status/{_ID}$', 'GET', 'MODEL_PROVIDER_DOWNLOAD_STATUS'),
        (rf'^/openai/models/{_ID}/load$', 'POST', 'MODEL_PROVIDER_LOAD'),
        (rf'^/openai/models/{_ID}/unload$', 'POST', 'MODEL_PROVIDER_UNLOAD'),
        (rf'^/openai/models/{_ID}/sse$', 'GET', 'MODEL_PROVIDER_SSE'),
        (rf'^/api/v1/retrieval/process/url$', 'POST', 'RETRIEVAL_PROCESS_URL'),
        (rf'^/api/v1/memories/reindex$', 'POST', 'MEMORY_REINDEX'),
        (rf'^/ollama/v1/models/{_ID}$', 'GET', 'OLLAMA_COMPAT_MODELS_READ'),
        (rf'^/ollama/api/tags/{_ID}$', 'GET', 'OLLAMA_COMPAT_TAGS_READ'),
        (rf'^/ollama/api/version/{_ID}$', 'GET', 'OLLAMA_COMPAT_VERSION_READ'),
```

Add the mutating actions to `_NIS2_SECURITY_ACTIONS` and leave the pure reads out:

```python
        'MODEL_PROVIDER_DOWNLOAD',
        'MODEL_PROVIDER_LOAD',
        'MODEL_PROVIDER_UNLOAD',
        'MEMORY_REINDEX',
```

Keep `RETRIEVAL_PROCESS_URL`, `MODEL_PROVIDER_CATALOG`, `MODEL_PROVIDER_DOWNLOAD_STATUS`, `MODEL_PROVIDER_SSE`, and the three `OLLAMA_COMPAT_*_READ` actions outside the security set unless the route-coverage review proves they carry sensitive state changes.

- [ ] **Step 4: Extend `test_access_log.py` with concrete v0.11.3 action tests**

Append this class to `backend/open_webui/test/middleware/test_access_log.py`:

```python
class TestClassifyV0113Actions:
    def test_openai_provider_model_catalog(self):
        assert action_of('GET', '/openai/models/0/catalog') == 'MODEL_PROVIDER_CATALOG'
        assert not is_nis2('GET', '/openai/models/0/catalog')

    def test_openai_provider_model_download(self):
        assert action_of('POST', '/openai/models/0/download') == 'MODEL_PROVIDER_DOWNLOAD'
        assert is_nis2('POST', '/openai/models/0/download')

    def test_openai_provider_model_download_status(self):
        assert (
            action_of('GET', '/openai/models/0/download/status/job-42')
            == 'MODEL_PROVIDER_DOWNLOAD_STATUS'
        )
        assert not is_nis2('GET', '/openai/models/0/download/status/job-42')

    def test_openai_provider_model_load(self):
        assert action_of('POST', '/openai/models/0/load') == 'MODEL_PROVIDER_LOAD'
        assert is_nis2('POST', '/openai/models/0/load')

    def test_openai_provider_model_unload(self):
        assert action_of('POST', '/openai/models/0/unload') == 'MODEL_PROVIDER_UNLOAD'
        assert is_nis2('POST', '/openai/models/0/unload')

    def test_openai_provider_model_sse(self):
        assert action_of('GET', '/openai/models/0/sse') == 'MODEL_PROVIDER_SSE'
        assert not is_nis2('GET', '/openai/models/0/sse')

    def test_retrieval_process_url(self):
        assert action_of('POST', '/api/v1/retrieval/process/url') == 'RETRIEVAL_PROCESS_URL'

    def test_memory_reindex(self):
        assert action_of('POST', '/api/v1/memories/reindex') == 'MEMORY_REINDEX'
        assert is_nis2('POST', '/api/v1/memories/reindex')

    def test_ollama_admin_tags_read(self):
        assert action_of('GET', '/ollama/api/tags/0') == 'OLLAMA_COMPAT_TAGS_READ'
        assert not is_nis2('GET', '/ollama/api/tags/0')

    def test_ollama_admin_version_read(self):
        assert action_of('GET', '/ollama/api/version/0') == 'OLLAMA_COMPAT_VERSION_READ'
        assert not is_nis2('GET', '/ollama/api/version/0')

    def test_ollama_admin_models_read(self):
        assert action_of('GET', '/ollama/v1/models/0') == 'OLLAMA_COMPAT_MODELS_READ'
        assert not is_nis2('GET', '/ollama/v1/models/0')
```

Do not replace the existing `CONFIG_OAUTH_ADMIN` tests; keep them and use the new harness to verify that the runtime route still resolves to the same action after the `OAuthConfigResponse` response-model change.

- [ ] **Step 5: Re-run the harness and the access-log tests until both are green**

```bash
PYTHONPATH=backend python backend/open_webui/test/middleware/access_log_route_coverage.py
PYTHONPATH=backend pytest -q backend/open_webui/test/middleware/test_access_log.py
```

Expected: the coverage script exits `0`, the new v0.11.3 routes have semantic actions instead of generic fallbacks, the three Ollama compatibility routes still depend on `get_admin_user`, and `dead_rules` is empty after removing or correcting any stale patterns.

- [ ] **Step 6: Commit the NIS2 coverage and rule-table update**

```bash
git add \
  backend/open_webui/middleware/access_log.py \
  backend/open_webui/test/middleware/access_log_route_coverage.py \
  backend/open_webui/test/middleware/test_access_log.py
git commit -m "feat: cover v0.11.3 NIS2 audit routes"
```

### Task 8: Run the final validation gate

**Files:**
- Validate: `backend/`
- Validate: `src/`
- Validate: `package.json`
- Validate: `package-lock.json`

**Interfaces:**
- Consumes: the fully merged integration branch from Tasks 1-7.
- Produces: a validated tree ready for release metadata and tagging.

- [ ] **Step 1: Run the backend test suite**

```bash
PYTHONPATH=backend pytest backend/
```

Expected: all backend tests pass, including middleware, analytics, Prompt Insights, and migration-adjacent coverage.

- [ ] **Step 2: Run the frontend unit tests**

```bash
npm run test:frontend
```

Expected: Vitest passes for the analytics and settings surfaces touched by the integration.

- [ ] **Step 3: Run the type-check gate**

```bash
npm run check
```

Expected: Svelte and TypeScript checks pass with no new integration regressions.

- [ ] **Step 4: Run the repository lint gate**

```bash
npm run lint
```

Expected: frontend lint, type checks, and backend lint all pass in the repository's standard sequence.

- [ ] **Step 5: Commit only if the validation gate forced a follow-up fix**

```bash
git add backend src package.json package-lock.json
git diff --cached --quiet || git commit -m "fix: address v0.11.3 validation regressions"
```

### Task 9: Bump the release version, document the patch series, and create the source tag

**Files:**
- Modify: `package.json`
- Modify: `package-lock.json`
- Modify: `patches/README.md`

**Interfaces:**
- Consumes: the green branch from Task 8.
- Produces: version `0.11.3-260908`, documented patch metadata for the v0.11.3 integration, and source tag `v0.11.3-260908`.

- [ ] **Step 1: Bump the package version to the exact dated release string**

```bash
npm version --no-git-tag-version 0.11.3-260908
grep -n '"version": "0.11.3-260908"' package.json
grep -n '"version": "0.11.3-260908"' package-lock.json
```

This keeps the source tree aligned with the required `YYMMDD` release naming convention.

- [ ] **Step 2: Regenerate the final documented patch series artifacts for the integrated branch**

```bash
git diff --binary v0.11.3..HEAD -- . \
  ':(exclude)patches/integration-v0.11.3-customizations-from-main.patch' \
  ':(exclude)patches/integration-v0.11.3-customizations-files.txt' \
  > patches/0001-chore-reconcile-fork-customizations-onto-v0.11.3-base.patch
git diff --binary -- package.json package-lock.json > patches/0002-chore-bump-version-to-0.11.3-260908.patch
test -s patches/0001-chore-reconcile-fork-customizations-onto-v0.11.3-base.patch
test -s patches/0002-chore-bump-version-to-0.11.3-260908.patch
```

Run this step after the version bump so the README can point to the actual patch files that ship with the integration branch.

- [ ] **Step 3: Update `patches/README.md` in the same style as the existing `integration-v0.10.2` entry**

Replace the top section with this exact structure, updating only the hand-resolved conflict bullets if the final merge uncovered one more overlapping file:

```markdown
# Patches — integration-v0.11.3

**Base upstream tag:** `v0.11.3` (SHA `2a960a59fe1dbbd35282f0556b3666d81102e781`)
**Regenerated:** 2026-09-08

## Patch series

| #    | File | Description |
| ---- | ---- | ----------- |
| 0001 | `chore-reconcile-fork-customizations-onto-v0.11.3-base.patch` | Full cumulative diff of all fork customizations reapplied onto `v0.11.3`: Prompt Insights, analytics/routing/cross-filter, NIS2 access-log/audit/OIDC compliance, MCP import compatibility, Alembic multi-head safety, dependency/security pin refreshes, and shipped UI fixes |
| 0002 | `chore-bump-version-to-0.11.3-260908.patch` | Version bump to `0.11.3-260908` |

> **Note:** this series was generated by diffing `f9590b8017199e56d5e953657e6498e3cef1d246..main`, applying that cumulative fork diff onto `v0.11.3`, and then resolving the overlapping upstream files by hand on `integration-v0.11.3`.
> Manual conflict resolutions to document here:
> - `backend/open_webui/utils/middleware.py`: kept upstream `v0.11.3` request/stream pipeline and reintroduced fork `merge_routing_usage`, MCP client wiring, and the routing metadata merge call sites.
> - `backend/open_webui/main.py`: kept upstream router registrations and compatibility endpoints while preserving fork audit/access-log ordering and OIDC back-channel logout wiring.
> - `backend/open_webui/utils/tools.py`: kept upstream built-in tool handling while preserving `subagents.enable`, `subagents.background_enabled`, and mutating-memory guardrails.
> - `backend/open_webui/middleware/access_log.py`: added explicit `v0.11.3` route rules for provider-model management, retrieval URL ingestion, memories reindex, and the admin-only Ollama compatibility endpoints, then removed any dead regex rules reported by `backend/open_webui/test/middleware/access_log_route_coverage.py`.
```

- [ ] **Step 4: Commit the release metadata and create the source tag**

```bash
git add package.json package-lock.json patches/README.md patches/0001-chore-reconcile-fork-customizations-onto-v0.11.3-base.patch patches/0002-chore-bump-version-to-0.11.3-260908.patch
git commit -m "chore: prepare v0.11.3-260908 release metadata"
git tag -a v0.11.3-260908 -m "v0.11.3-260908"
git tag --list 'v0.11.3-*'
```

Expected: the new annotated source tag follows `YYMMDD`, not `DDMMYY`, and `patches/README.md` documents the manual conflict decisions that mattered during the integration.
