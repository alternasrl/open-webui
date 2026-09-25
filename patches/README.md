# Patches — integration-v0.11.4

**Base upstream tag:** `v0.11.4` (SHA `8bd8b4fac5e059578ac0c74b3c18d11139f88b7d`)
**Regenerated:** 2026-09-25

## Seed artifacts

| File | Purpose |
| ---- | ------- |
| `integration-v0.11.4-customizations-from-main.patch` | Raw cumulative fork customization seed replayed onto upstream `v0.11.4`; kept unchanged as the provenance baseline for this integration. |
| `integration-v0.11.4-customizations-files.txt` | File inventory for the raw seed; kept unchanged so the integration surface stays auditable. |

## What the fork preserved

- Prompt Insights, analytics/routing/cross-filter UI, and the shipped admin analytics behavior.
- NIS2 access-log classification, audit logging, and OIDC/OAuth compliance paths.
- MCP import compatibility, built-in tool handling, and the existing request/stream pipeline decisions.
- Alembic safety for the fork migration history and the single-head merge already verified for the integration branch.
- The existing dependency/security pin refreshes and the fork UI fixes that were already in the branch.

## NIS2 route action changes

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
- Version metadata remains `0.11.4`; the fork date suffix and release tags stay pending a separate explicit release cut.

## Final gate

This document records the integration evidence only. It is **not** approval to merge, release, tag, or publish.
