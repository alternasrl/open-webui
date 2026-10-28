# Patches — integration-v0.12.0

**Base upstream tag:** `v0.12.0` (SHA `15818d88fd7bde1b73de33590f50d15d21e8d7c1`)
**Candidate:** branch `integration-v0.12.0` (code state `7c5aac115`), not released: no tag, PR or image has been created.

## Current artifact

| File                                                                  | Purpose                                                                                                                                  |
| --------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------- |
| `0001-chore-reconcile-fork-customizations-onto-v0.12.0-base.patch`   | Replayable runtime delta: the fork customizations reconciled onto upstream `v0.12.0` (174 files, 14500 insertions, 256 deletions).       |
| `integration-v0.12.0-customizations-files.txt`                        | Inventory of the original fork delta (`v0.11.4`..fork head, 217 paths) used as the input of the decision matrix.                         |
| `integration-v0.12.0-decisions.md`                                    | Decision matrix (217 rows, planned decision plus final outcome and proving test), quality gate, verification log and known limitations. |

Regenerate exactly with raw (unfiltered) output:

```bash
git diff --binary 15818d88fd7bde1b73de33590f50d15d21e8d7c1 HEAD -- . ':(exclude)patches/**' ':(exclude)docs/**' ':(exclude).superpowers/**' \
  > patches/0001-chore-reconcile-fork-customizations-onto-v0.12.0-base.patch
```

The patch is a **runtime patch, not a full history backup**. It excludes `patches/**` (non-recursive and no archive churn), `docs/**` and `.superpowers/**` (planning and workflow artifacts). Merge history, previous patch archives and reports remain in git history only. It includes tests, migrations and the 64 locale catalogs.

Check: extract `git archive 15818d88f` into a scratch directory outside any git repository and run `git apply --check <patch>` there; the result is clean (exit 0), and applying it reproduces the candidate tree (except the excluded paths). Do not apply it to the already integrated candidate.

Candidate migration graph: single head `e304e2e7c45a` (no-DDL merge of `6c7d8e9f0a1b` and the upstream head `b8f2c6d91a04`).

## Older archives are provenance only

Every other file in this directory (`0001`..`0019` patches, the dated routing-analytics patch, and the `integration-v0.11.3`/`v0.11.4` seeds and inventories) is retained as historical provenance. They target older upstream bases, must not be re-applied, and are not part of the v0.12.0 delta.

# Previous integration — v0.11.4 (provenance only)

**Base upstream tag:** `v0.11.4` (SHA `8bd8b4fac5e059578ac0c74b3c18d11139f88b7d`)
**Regenerated:** 2026-09-25

## Seed artifacts

| File                                                 | Purpose                                                                                                                                  |
| ---------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------- |
| `integration-v0.11.4-customizations-from-main.patch` | Raw cumulative fork customization seed replayed onto upstream `v0.11.4`; kept unchanged as the provenance baseline for this integration. |
| `integration-v0.11.4-customizations-files.txt`       | File inventory for the raw seed; kept unchanged so the integration surface stays auditable.                                              |

## Integration patch / commit sequence

These are the actual `integration-v0.11.4` branch commits, not standalone replayable patches. The raw seed artifacts above stay unchanged and serve as the baseline that the branch replays and then hardens.

| Order | Commit                                                          | Role                                                                         |
| ----- | --------------------------------------------------------------- | ---------------------------------------------------------------------------- |
| 1     | `96e4bf3b0` `chore: add v0.11.4 customization seed`             | Added the raw seed artifacts that start the replay baseline.                 |
| 2     | `118cf084b` `fix: repair v0.11.4 seed artifacts`                | Repaired the seed artifacts so the replay baseline could be applied cleanly. |
| 3     | `e90473657` `feat: reapply fork customizations`                 | Replayed the preserved fork customizations onto upstream `v0.11.4`.          |
| 4     | `270c4c8fe` `fix: sanitize integration audit logs`              | Removed unsafe audit payload details from the integration logs.              |
| 5     | `66464230f` `fix: complete NIS2 v0.11.4 route audit coverage`   | Completed the route/action coverage for the NIS2 inventory.                  |
| 6     | `2fc64fb47` `fix: sanitize exported model audit ids`            | Limited `GET /api/v1/models/export` references to sanitized ids.             |
| 7     | `208d66fca` `test: strengthen semantic NIS2 coverage`           | Added semantic coverage for the route inventory.                             |
| 8     | `89cc085fe` `test: tighten scheduled automation audit coverage` | Covered scheduled automation audit events, including failures.               |
| 9     | `335060e0f` `fix: clear integration frontend type errors`       | Cleared the integration-only frontend diagnostics.                           |
| 10    | `04c5a8575` `docs: finalize v0.11.4 integration gate`           | Recorded the final documentation gate for the integration.                   |

## What the fork preserved

- Prompt Insights, analytics/routing/cross-filter UI, and the shipped admin analytics behavior.
- NIS2 access-log classification, audit logging, and OIDC/OAuth compliance paths.
- MCP import compatibility, built-in tool handling, and the existing request/stream pipeline decisions.
- Alembic safety for the fork migration history and the single-head merge already verified for the integration branch.
- The existing dependency/security pin refreshes and the fork UI fixes that were already in the branch.

## NIS2 route action changes

### v0.12.4 reconciliation (Task 4)

- `backend/open_webui/middleware/audit_routes.py` is the reviewed method/template
  catalog, including actor admission contracts and security severity. Every
  mounted business HTTP route must have an explicit semantic action. Legacy
  `READ`/`WRITE_OTHER`/`DELETE_OTHER` rules are unmatched-request diagnostics,
  **not** coverage. New routes (including reads and routes matching a legacy
  regex) fail the runtime inventory guard until reviewed.
- Technical exceptions are exact health/PWA/development-doc routes. The guard
  separately checks the exact Socket.IO transport and typed static-asset mounts;
  no business prefix or arbitrary new ASGI mount is exempt.
- `setup_access_logging(app)` remains active. The custom middleware is pure ASGI,
  inside upstream `AppHTTPMiddleware` and the separate optional
  `AuditLoggingMiddleware`, without introducing a streaming cancellation scope.
- Access events contain sanitized identifiers, actor, correlation, outcome and
  timing, never bodies or query strings. Logged route templates also keep
  webhook credentials and arbitrary proxy paths out of audit URIs. Successful
  app creation records the returned ID; channel-app events retain both IDs
  once available from route parameters or validated handler state.
- The separate upstream audit retains metadata events but never captures either
  payload for Apps/channels, workspace search, calendar access updates or
  interface visibility updates (including failures and slash redirects).
  Existing auth, file, skill and workspace payload protections remain active.
  Model-usage events retain upstream request-state linkage without query strings.
- Channel ACL, update, delete and membership operations keep encrypted-session
  invalidation and metadata-only audit events. Governance mutations are
  security-relevant. Retired routing-analytics rules and Prompt Insights fallback
  bookkeeping are removed; standard upstream Analytics routes remain audited.
- Focused regression suites: `test_access_log.py`,
  `test_access_log_route_coverage.py`, `test_access_log_runtime.py` and
  `test_v0120_mfa_oauth.py`. Run mounted tests without lifespan/startup and with
  isolated/mocked data access; the coverage suite uses the real registered app.

### Earlier v0.11.4 integration

- **New or made explicit:** `CONFIG_IMAGES_VERIFY`, `MODEL_LIST_ALL`, `FOLDER_ACCESS_READ`, `MODEL_PROVIDER_CATALOG`, `MODEL_PROVIDER_LIST`, `MODEL_PROVIDER_DOWNLOAD`, `MODEL_PROVIDER_DOWNLOAD_STATUS`, `MODEL_PROVIDER_LOAD`, `MODEL_PROVIDER_UNLOAD`, `MODEL_PROVIDER_SSE`, `RETRIEVAL_PROCESS_URL`, and `MEMORY_REINDEX`.
- **Changed object-audit behavior:** `GET /api/v1/models/export` now records only sanitized `ids` in the object reference, never raw query payloads, tokens, or export contents.
- **Removed/retired legacy surfaces:** `GET /api/v1/images/config/url/verify` and `POST /api/v1/utils/pdf` no longer appear in the route inventory, and their legacy NIS2 rules are absent.
- **Maintained split semantics:** `GET /api/v1/folders/shared` stays distinct from `GET /api/v1/folders/{id}` so the folder inventory remains precise.

## Verified outcomes

- Route inventory is clean: the runtime inventory check has no mismatches, removed routes, mutating generic fallthroughs, legacy rule regressions, admin-guard mismatches, or dead semantic rules.
- Backend suite passes, including the middleware coverage and access-log tests.
- Migration verification remains on a single Alembic head; no new migration was required for the v0.11.4 reconciliation.
- Frontend tests pass, but the clean upstream baseline still reports Svelte-check errors; after the integration fixes there are zero integration-only diagnostics.
- Local production builds still need a heap override, while the Docker CI build config already supplies one, so the containerized build path remains the preferred verified path.
- Release version metadata is `0.11.4-260925`, matching the fork's dated source release tag.

## Release

The fork integration was released as [`v0.11.4-260925`](https://github.com/alternasrl/open-webui/releases/tag/v0.11.4-260925), based on upstream [`v0.11.4`](https://github.com/open-webui/open-webui/blob/v0.11.4/CHANGELOG.md).
