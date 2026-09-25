# Patches — integration-v0.11.4

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
