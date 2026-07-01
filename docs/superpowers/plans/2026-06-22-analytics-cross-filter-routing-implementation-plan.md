# Analytics Cross-Filter Routing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement bidirectional user/model cross-filter behavior in Admin Analytics with always-visible routing summary and events, without backend changes.

**Architecture:** Keep backend contracts unchanged and implement orchestration in frontend state. Extract cross-filter decision logic into a small pure helper module to enable deterministic tests and reduce risk of regressions in the dashboard component.

**Tech Stack:** Svelte 5 + TypeScript, Vitest, existing analytics API client functions.

---

## File structure map

- Modify: `src/lib/components/admin/Analytics/Dashboard.svelte`
  - Responsibility: wire UI events, trigger table/routing reloads, keep filter badges and toggle behavior.
- Create: `src/lib/components/admin/Analytics/cross-filter-state.ts`
  - Responsibility: pure helper functions for routing filter derivation and async request freshness checks.
- Create: `src/lib/components/admin/Analytics/cross-filter-state.test.ts`
  - Responsibility: unit tests for helper semantics (mode=or default, pair precedence, toggle expectations).
- Modify: `src/lib/components/admin/Analytics/RoutingUsage.svelte`
  - Responsibility: keep summary+events visible and improve active-filter clarity text.
- Modify: `src/lib/components/admin/Analytics/routing-logic.test.ts`
  - Responsibility: preserve and extend routing mode compatibility assertions.

---

### Task 1: Add pure cross-filter helpers (TDD first)

**Files:**
- Create: `src/lib/components/admin/Analytics/cross-filter-state.test.ts`
- Create: `src/lib/components/admin/Analytics/cross-filter-state.ts`
- Test: `src/lib/components/admin/Analytics/cross-filter-state.test.ts`

- [ ] **Step 1: Write failing tests for routing filter derivation and request freshness**

```ts
import { describe, expect, it } from 'vitest';
import {
  deriveRoutingFilters,
  createRequestTracker,
  toggleSelection
} from './cross-filter-state';

describe('deriveRoutingFilters', () => {
  it('uses pair precedence over model filter', () => {
    const filters = deriveRoutingFilters({
      routingSelectedPair: { requested_model_id: 'REQ', selected_model_id: 'SEL' },
      filterByModelId: 'MODEL',
      routingModelMode: 'or'
    });

    expect(filters).toEqual({ modelSelected: 'SEL', modelRequested: 'REQ' });
  });

  it('defaults to or behavior when model filter exists', () => {
    const filters = deriveRoutingFilters({
      routingSelectedPair: null,
      filterByModelId: 'MODEL',
      routingModelMode: 'or'
    });

    expect(filters).toEqual({ modelSelected: 'MODEL', modelRequested: 'MODEL' });
  });
});

describe('createRequestTracker', () => {
  it('accepts only latest request id', () => {
    const tracker = createRequestTracker();
    const first = tracker.next();
    const second = tracker.next();

    expect(tracker.isLatest(first)).toBe(false);
    expect(tracker.isLatest(second)).toBe(true);
  });
});

describe('toggleSelection', () => {
  it('toggles off when selecting same id', () => {
    expect(toggleSelection('u1', 'u1')).toBeNull();
    expect(toggleSelection('u1', 'u2')).toBe('u2');
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run:
```bash
npm run test:frontend -- src/lib/components/admin/Analytics/cross-filter-state.test.ts
```

Expected: FAIL with module import error for `./cross-filter-state`.

- [ ] **Step 3: Implement minimal helper module**

```ts
export type RoutingMode = 'or' | 'and' | 'selected' | 'requested';

export type RoutingPair = {
  requested_model_id: string;
  selected_model_id: string;
};

export function deriveRoutingFilters(input: {
  routingSelectedPair: RoutingPair | null;
  filterByModelId: string | null;
  routingModelMode: RoutingMode;
}): { modelSelected: string | null; modelRequested: string | null } {
  const { routingSelectedPair, filterByModelId, routingModelMode } = input;

  if (routingSelectedPair) {
    return {
      modelSelected: routingSelectedPair.selected_model_id,
      modelRequested: routingSelectedPair.requested_model_id
    };
  }

  if (!filterByModelId) {
    return { modelSelected: null, modelRequested: null };
  }

  if (routingModelMode === 'selected') {
    return { modelSelected: filterByModelId, modelRequested: null };
  }

  if (routingModelMode === 'requested') {
    return { modelSelected: null, modelRequested: filterByModelId };
  }

  return { modelSelected: filterByModelId, modelRequested: filterByModelId };
}

export function createRequestTracker() {
  let current = 0;
  return {
    next() {
      current += 1;
      return current;
    },
    isLatest(id: number) {
      return id === current;
    }
  };
}

export function toggleSelection(current: string | null, next: string): string | null {
  return current === next ? null : next;
}
```

- [ ] **Step 4: Run tests to verify pass**

Run:
```bash
npm run test:frontend -- src/lib/components/admin/Analytics/cross-filter-state.test.ts
```

Expected: PASS all tests in the new file.

- [ ] **Step 5: Commit**

```bash
git add src/lib/components/admin/Analytics/cross-filter-state.ts src/lib/components/admin/Analytics/cross-filter-state.test.ts
git commit -m "test(analytics): add cross-filter helper coverage"
```

---

### Task 2: Integrate helpers into dashboard filtering flow

**Files:**
- Modify: `src/lib/components/admin/Analytics/Dashboard.svelte`
- Test: `src/lib/components/admin/Analytics/routing-logic.test.ts`

- [ ] **Step 1: Add failing assertions for or-default and pair precedence behavior**

```ts
import { describe, expect, it } from 'vitest';
import { deriveRoutingFilters } from './cross-filter-state';

describe('dashboard cross-filter defaults', () => {
  it('keeps default mode as or for model selection', () => {
    expect(
      deriveRoutingFilters({
        routingSelectedPair: null,
        filterByModelId: 'M1',
        routingModelMode: 'or'
      })
    ).toEqual({ modelSelected: 'M1', modelRequested: 'M1' });
  });
});
```

- [ ] **Step 2: Run targeted tests and verify initial failure if imports unresolved**

Run:
```bash
npm run test:frontend -- src/lib/components/admin/Analytics/routing-logic.test.ts
```

Expected: FAIL until test file imports are aligned.

- [ ] **Step 3: Update dashboard wiring to use helper functions and request trackers**

```ts
import {
  createRequestTracker,
  deriveRoutingFilters,
  toggleSelection
} from './cross-filter-state';

const routingTracker = createRequestTracker();
const modelTracker = createRequestTracker();
const userTracker = createRequestTracker();

const loadRoutingAnalytics = async () => {
  loadingRouting = true;
  const requestId = routingTracker.next();
  try {
    const { modelSelected, modelRequested } = deriveRoutingFilters({
      routingSelectedPair,
      filterByModelId,
      routingModelMode
    });

    const [summaryRes, eventsRes] = await Promise.all([
      getRoutingSummary(localStorage.token, {
        startDate: start,
        endDate: end,
        groupId: selectedGroupId,
        userId: filterByUserId,
        modelSelected,
        modelRequested,
        modelMode: routingModelMode
      }),
      getRoutingEvents(localStorage.token, {
        startDate: start,
        endDate: end,
        groupId: selectedGroupId,
        userId: filterByUserId,
        modelSelected,
        modelRequested,
        modelMode: routingModelMode,
        skip: 0,
        limit: 20
      })
    ]);

    if (!routingTracker.isLatest(requestId)) return;
    routingPairs = summaryRes ?? [];
    routingEvents = eventsRes ?? [];
  } finally {
    if (routingTracker.isLatest(requestId)) loadingRouting = false;
  }
};
```

- [ ] **Step 4: Keep click handlers deterministic for toggles**

```ts
on:click={() => {
  const next = toggleSelection(filterByUserId, user.user_id);
  filterByUserId = next;
  filterByUserName = next ? (user.name || user.email || user.user_id.substring(0, 8)) : null;
  reloadModelTable();
}}
```

```ts
on:click={() => {
  const next = toggleSelection(filterByModelId, model.model_id);
  filterByModelId = next;
  filterByModelName = next ? (model.name ?? model.model_id) : null;
  reloadUserTable();
}}
```

- [ ] **Step 5: Run tests and commit**

Run:
```bash
npm run test:frontend -- src/lib/components/admin/Analytics/cross-filter-state.test.ts src/lib/components/admin/Analytics/routing-logic.test.ts
```

Expected: PASS both files.

```bash
git add src/lib/components/admin/Analytics/Dashboard.svelte src/lib/components/admin/Analytics/routing-logic.test.ts
git commit -m "feat(analytics): stabilize cross-filter orchestration"
```

---

### Task 3: Keep routing summary + events always visible and clarify active filters

**Files:**
- Modify: `src/lib/components/admin/Analytics/RoutingUsage.svelte`
- Modify: `src/lib/components/admin/Analytics/Dashboard.svelte`

- [ ] **Step 1: Add explicit active-filter copy near routing header**

```svelte
{#if modelFilterLabel}
  <span class="text-blue-500 font-normal">
    Filtered model: <span class="font-medium">{modelFilterLabel}</span>
  </span>
{/if}
{#if activeUserLabel}
  <span class="text-blue-500 font-normal">
    Filtered user: <span class="font-medium">{activeUserLabel}</span>
  </span>
{/if}
```

- [ ] **Step 2: Ensure events block remains rendered regardless of pair selection**

```svelte
<div>
  <div class="flex items-center justify-between text-xs text-gray-600 dark:text-gray-400 mb-1">
    <span>Routing Events</span>
    {#if selectedPair}
      <button class="text-blue-500 hover:text-blue-600" on:click={onClearPair}>Clear pair</button>
    {/if}
  </div>
  <!-- table remains visible even when selectedPair is null -->
</div>
```

- [ ] **Step 3: Run frontend checks for Svelte/TS validity**

Run:
```bash
npm run check
```

Expected: PASS (or unchanged pre-existing warnings only outside touched files).

- [ ] **Step 4: Commit**

```bash
git add src/lib/components/admin/Analytics/RoutingUsage.svelte src/lib/components/admin/Analytics/Dashboard.svelte
git commit -m "ux(analytics): clarify active routing filters"
```

---

### Task 4: Verification sweep and regression gate

**Files:**
- Test: `src/lib/components/admin/Analytics/cross-filter-state.test.ts`
- Test: `src/lib/components/admin/Analytics/routing-logic.test.ts`

- [ ] **Step 1: Run focused frontend tests**

Run:
```bash
npm run test:frontend -- src/lib/components/admin/Analytics/cross-filter-state.test.ts src/lib/components/admin/Analytics/routing-logic.test.ts
```

Expected: PASS all targeted tests.

- [ ] **Step 2: Run lint and type checks**

Run:
```bash
npm run lint:frontend
npm run check
```

Expected: PASS or no new issues in touched files.

- [ ] **Step 3: Manual QA checklist**

```text
1. Click user row -> model table + routing refresh, toggle off works.
2. Click model row -> user table + routing refresh, default mode remains or.
3. User+model both active -> routing summary/events stay coherent.
4. Click routing pair -> events narrow to pair, clear pair restores baseline.
5. Rapid click switching does not show stale routing data.
```

- [ ] **Step 4: Final commit (if any polish changes from QA)**

```bash
git add src/lib/components/admin/Analytics/*.svelte src/lib/components/admin/Analytics/*.ts
git commit -m "test(analytics): validate cross-filter routing behavior"
```

---

## Spec coverage checklist

- User selection shows models used + routing: covered by Task 2 + Task 4 QA #1.
- Model selection shows users + routing: covered by Task 2 + Task 4 QA #2.
- Routing summary + events always visible: covered by Task 3.
- Default routing mode = or: covered by Task 2 tests and integration.
- Backend untouched: enforced by file scope in all tasks.

## Notes

- Keep YAGNI: no backend endpoint additions.
- Keep commits small and task-scoped for easy rollback.
- If a pre-existing unrelated lint/check issue appears, document it in commit notes and do not broaden scope.
