# Analytics Model Usage UX Alignment

## Problem

GIADA analytics UI on v0.11.x shows duplicated Model Usage table structure after upstream merge. The custom per-model analytics from GIADA still exist in backend, but the frontend presentation is inconsistent with v0.11 UX and hard to read.

## Goal

Restore a single, coherent Model Usage table in `src/lib/components/admin/Analytics/Dashboard.svelte`, aligned with upstream v0.11 layout while preserving GIADA-specific model metrics:

- message count
- unique users
- unique chats
- tokens
- TTFT
- Tok/s
- error rate / errors
- percentage share

## Non-goals

- No backend/API changes
- No routing analytics changes
- No prompt insights changes
- No new charts or summary cards

## Proposed UX

Keep one Model Usage table and one User Activity table in the admin analytics dashboard.

Model Usage should use a single header/body schema with stable ordering:

1. Model
2. Messages
3. Users
4. Chats
5. Tokens
6. TTFT
7. Tok/s
8. Err%
9. %

The row details should keep existing drill-down behavior:

- clicking a row filters the opposite table
- arrow button opens model modal
- active filter badge remains visible

## Implementation shape

Update only `Dashboard.svelte`:

- remove duplicate table fragments left by merge
- keep one set of header cells and matching body cells
- preserve existing data loading, filtering, and sort state
- keep `RoutingUsage.svelte` separate and untouched

## Error handling

No new runtime paths. If analytics data is missing, the table continues to render `—` / `No data` as today.

## Testing

Minimum checks:

- analytics modal opens
- Model Usage table renders once
- headers match body columns
- row click still filters User Activity
- arrow button still opens model modal
- Routing analytics still renders independently

## Rollout

Safe to ship as a frontend-only merge cleanup. No migration or feature flag required.
