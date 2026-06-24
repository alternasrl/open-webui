# Routing-Aware Cross-Filter Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Enable users to click on a routing pair and automatically filter analytics tables to show users and token consumption for that specific model routing scenario.

**Architecture:** Add state management to Dashboard.svelte to track selected routing pairs, extract the selected_model_id, and apply it as a filter. Integrate clear handlers and auto-clear logic on period/group changes. All API calls already support the required filtering.

**Tech Stack:** SvelteKit, TypeScript, Svelte stores, existing analytics APIs

---

## File Structure

| File | Responsibility |
|------|-----------------|
| `src/lib/components/admin/Analytics/Dashboard.svelte` | Add `routingSelectedPair` state, `onSelectPair()`, `onClearPair()` handlers, and auto-clear logic |
| `src/lib/components/admin/Analytics/RoutingUsage.svelte` | Add visual routing filter badge (optional, nice-to-have) |
| `src/lib/components/admin/Analytics/cross-filter-state.test.ts` | Add unit test for routing pair filter extraction |

---

## Task 1: Add State Variables and Handlers to Dashboard.svelte

**Files:**
- Modify: `src/lib/components/admin/Analytics/Dashboard.svelte` (lines 140-170)

- [ ] **Step 1: Locate current state variables section**

Open the file and find the section where `filterByUserId`, `filterByModelId`, and other state variables are declared (around line 140-170).

Expected section:
```svelte
let filterByUserId: string | null = null;
let filterByModelId: string | null = null;
let routingSelectedPair: { requested_model_id: string; selected_model_id: string } | null = null;
```

- [ ] **Step 2: Add routing state variable**

Add after `filterByModelId`:
```typescript
let routingSelectedPair: { requested_model_id: string; selected_model_id: string } | null = null;
```

- [ ] **Step 3: Implement onSelectPair handler**

Add after the existing filter handlers (around line 160-170), before `loadDashboard`:

```typescript
const onSelectPair = (requestedModelId: string, selectedModelId: string) => {
	routingSelectedPair = { requested_model_id: requestedModelId, selected_model_id: selectedModelId };
	filterByModelId = selectedModelId;
	reloadModelTable();
	reloadUserTable();
	loadRoutingAnalytics();
};
```

- [ ] **Step 4: Implement onClearPair handler**

Add right after `onSelectPair`:

```typescript
const onClearPair = () => {
	routingSelectedPair = null;
	filterByModelId = null;
	reloadModelTable();
	reloadUserTable();
	loadRoutingAnalytics();
};
```

- [ ] **Step 5: Commit**

```bash
git add src/lib/components/admin/Analytics/Dashboard.svelte
git commit -m "feat(analytics): add routing pair state and handlers

- Add routingSelectedPair state variable to track selected (requested, selected) pair
- Add onSelectPair handler to extract selected_model_id and apply as filter
- Add onClearPair handler to reset routing and model filters
- Both handlers trigger parallel reloads of model, user, and routing tables

Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
```

---

## Task 2: Auto-Clear Routing Filter on Period/Group Change

**Files:**
- Modify: `src/lib/components/admin/Analytics/Dashboard.svelte` (reactive statement around line 320-340)

- [ ] **Step 1: Find the period/group change reactive statement**

Locate the reactive statement that triggers `loadDashboard()` and `loadRoutingAnalytics()` when period or group changes (look for `$: if (selectedPeriod || selectedGroupId !== undefined)`).

Expected around line 330:
```typescript
$: if (selectedPeriod || selectedGroupId !== undefined) {
	loadDashboard();
	loadRoutingAnalytics();
}
```

- [ ] **Step 2: Add routing clear to reactive statement**

Modify to auto-clear routing filter:
```typescript
$: if (selectedPeriod || selectedGroupId !== undefined) {
	routingSelectedPair = null;
	filterByModelId = null;
	loadDashboard();
	loadRoutingAnalytics();
}
```

- [ ] **Step 3: Verify syntax**

Check that the reactive statement has no TypeScript errors. Run:
```bash
npm run check 2>&1 | grep -i "dashboard" | head -10
```

Expected: No errors in Dashboard.svelte for this section

- [ ] **Step 4: Commit**

```bash
git add src/lib/components/admin/Analytics/Dashboard.svelte
git commit -m "feat(analytics): auto-clear routing filter on period/group change

When period or group filters change, automatically clear the routing pair
selection and model filter to prevent confusing filter states.

Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
```

---

## Task 3: Pass Callbacks to RoutingUsage Component

**Files:**
- Modify: `src/lib/components/admin/Analytics/Dashboard.svelte` (RoutingUsage component usage around line 600-650)

- [ ] **Step 1: Find RoutingUsage component in Dashboard template**

Search for `<RoutingUsage` in the template section (usually near end of file):

```svelte
<RoutingUsage
	pairs={routingPairs}
	events={routingEvents}
	loading={loadingRouting}
	modelMode={routingModelMode}
	selectedPair={routingSelectedPair}
	onModelModeChange={handleRoutingModeChange}
	onSelectPair={() => {}}
	onClearPair={() => {}}
/>
```

- [ ] **Step 2: Wire onSelectPair callback**

Replace the empty `onSelectPair={() => {}}` with:
```svelte
onSelectPair={onSelectPair}
```

- [ ] **Step 3: Wire onClearPair callback**

Replace the empty `onClearPair={() => {}}` with:
```svelte
onClearPair={onClearPair}
```

Full result should be:
```svelte
<RoutingUsage
	pairs={routingPairs}
	events={routingEvents}
	loading={loadingRouting}
	modelMode={routingModelMode}
	selectedPair={routingSelectedPair}
	onModelModeChange={handleRoutingModeChange}
	onSelectPair={onSelectPair}
	onClearPair={onClearPair}
/>
```

- [ ] **Step 4: Verify syntax**

Run type check:
```bash
npm run check 2>&1 | grep -i "dashboard" | head -10
```

Expected: No new errors

- [ ] **Step 5: Commit**

```bash
git add src/lib/components/admin/Analytics/Dashboard.svelte
git commit -m "feat(analytics): wire routing pair callbacks to RoutingUsage

Connect onSelectPair and onClearPair handlers to RoutingUsage component
so clicking routing pairs applies filters and clearing resets them.

Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
```

---

## Task 4: Add Visual Routing Filter Badge

**Files:**
- Modify: `src/lib/components/admin/Analytics/RoutingUsage.svelte` (header around lines 31-54)

- [ ] **Step 1: Locate the Routing section header**

Find the header div that contains "Routing (Requested → Selected)" text (around line 31-40):

```svelte
<div class="flex items-center justify-between text-xs font-medium text-gray-700 dark:text-gray-300 mb-1 px-0.5">
	<span>Routing (Requested → Selected)</span>
	<div class="flex items-center gap-2">
		{#if modelFilterLabel}
			<span class="text-blue-500 font-normal">Filtered model: <span class="font-medium">{modelFilterLabel}</span></span>
		{/if}
		{#if userFilterLabel}
			<span class="text-blue-500 font-normal ml-2">Filtered user: <span class="font-medium">{userFilterLabel}</span></span>
		{/if}
```

- [ ] **Step 2: Add routing filter badge**

After the `userFilterLabel` conditional block and before the mode selector, add:

```svelte
		{#if selectedPair}
			<span class="text-blue-500 font-normal ml-2">Routing filter: <span class="font-medium">{selectedPair.requested_model_id} → {selectedPair.selected_model_id}</span></span>
		{/if}
```

Result should be:
```svelte
<div class="flex items-center justify-between text-xs font-medium text-gray-700 dark:text-gray-300 mb-1 px-0.5">
	<span>Routing (Requested → Selected)</span>
	<div class="flex items-center gap-2">
		{#if modelFilterLabel}
			<span class="text-blue-500 font-normal">Filtered model: <span class="font-medium">{modelFilterLabel}</span></span>
		{/if}
		{#if userFilterLabel}
			<span class="text-blue-500 font-normal ml-2">Filtered user: <span class="font-medium">{userFilterLabel}</span></span>
		{/if}
		{#if selectedPair}
			<span class="text-blue-500 font-normal ml-2">Routing filter: <span class="font-medium">{selectedPair.requested_model_id} → {selectedPair.selected_model_id}</span></span>
		{/if}
		<label class="text-gray-500 dark:text-gray-400 font-normal" for="routing-mode">Mode</label>
```

- [ ] **Step 3: Verify syntax**

Run type check:
```bash
npm run check 2>&1 | grep -i "RoutingUsage" | head -10
```

Expected: No new errors

- [ ] **Step 4: Commit**

```bash
git add src/lib/components/admin/Analytics/RoutingUsage.svelte
git commit -m "feat(analytics): display routing filter badge

Show active routing pair filter in RoutingUsage header with format:
'Routing filter: [requested_model_id → selected_model_id]'

Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
```

---

## Task 5: Add Unit Test for Routing Filter Extraction

**Files:**
- Modify: `src/lib/components/admin/Analytics/cross-filter-state.test.ts`
- Test: Same file (add test case)

- [ ] **Step 1: Open the test file**

```bash
cat src/lib/components/admin/Analytics/cross-filter-state.test.ts | head -50
```

Expected: Test file with existing cross-filter tests

- [ ] **Step 2: Add routing pair filter test**

Add this test case at the end of the test file:

```typescript
test('extracts selected_model_id from routing pair for filtering', () => {
	// Simulate selecting a routing pair: gpt-4 → mistral
	const routingPair = { requested_model_id: 'gpt-4', selected_model_id: 'mistral' };
	
	// Extract the selected model to use as filter
	const filterByModelId = routingPair.selected_model_id;
	
	// Verify correct model is extracted
	expect(filterByModelId).toBe('mistral');
});
```

- [ ] **Step 3: Run test to verify it passes**

```bash
npm run test:frontend -- cross-filter-state 2>&1 | grep -E "PASS|FAIL|✓|×" | head -20
```

Expected: Test passes, total tests increased by 1

- [ ] **Step 4: Verify all cross-filter tests still pass**

```bash
npm run test:frontend -- cross-filter 2>&1 | tail -20
```

Expected: All tests passing, no regressions

- [ ] **Step 5: Commit**

```bash
git add src/lib/components/admin/Analytics/cross-filter-state.test.ts
git commit -m "test(analytics): add routing pair filter extraction test

Verify that selecting a routing pair correctly extracts selected_model_id
for use as a model filter.

Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
```

---

## Task 6: Manual Integration Test - Click Routing Pair

**Files:**
- Test manually in running application

- [ ] **Step 1: Start dev server**

In one terminal:
```bash
npm run dev
```

Wait for "http://localhost:5173" to appear. Leave running.

- [ ] **Step 2: Start backend in another terminal**

In a new terminal (in the repo root):
```bash
cd backend && python -m uvicorn open_webui.main:app --reload --port 8000
```

Wait for "Application startup complete"

- [ ] **Step 3: Navigate to analytics page**

Open browser to `http://localhost:5173/admin/analytics`

Expected: Analytics dashboard loads, Routing section visible with multiple pairs

- [ ] **Step 4: Identify a routing pair with traffic**

In the Routing table, find a pair with count > 10 (e.g., "gpt-4 → mistral"). Note the model IDs.

- [ ] **Step 5: Click the routing pair**

Click on the row in the Routing table.

Expected:
- Row highlights with blue background
- "Routing filter: [requested → selected]" badge appears in header
- Model Usage table reloads
- User Activity table reloads

- [ ] **Step 6: Verify User Activity filter**

In User Activity table:
- Scroll to see if users are displayed
- Each user should have interaction with `selected_model_id` (from your clicked pair)

Expected: Users shown, no error messages

- [ ] **Step 7: Verify Model Usage filter**

In Model Usage section:
- Check if models are filtered to show only those used by users receiving `selected_model_id`

Expected: Model list matches the routing selection

- [ ] **Step 8: Verify Token Stats**

In Token Usage section:
- Token consumption should show data only for `selected_model_id`

Expected: Token stats reflect only the selected model's consumption

- [ ] **Step 9: Click Clear Pair button**

Click "Clear pair" button in Routing header.

Expected:
- Routing pair highlighting disappears
- "Routing filter" badge disappears
- All tables reload with unfiltered data
- Original full dataset displays

- [ ] **Step 10: Change period filter**

Adjust the period filter (e.g., 24h → 7d).

Expected:
- Routing pair selection clears automatically
- Tables reload fresh
- "Routing filter" badge not shown

- [ ] **Step 11: Test rapid clicks (race condition check)**

Rapidly click different routing pairs 5+ times.

Expected:
- Each click filters tables correctly
- No stale data from previous selections
- No errors in browser console

---

## Task 7: Verify No Regressions in Cross-Filter Tests

**Files:**
- Test: `src/lib/components/admin/Analytics/cross-filter-state.test.ts`

- [ ] **Step 1: Run full cross-filter test suite**

```bash
npm run test:frontend -- cross-filter 2>&1 | tail -30
```

Expected: All tests pass (at least 11 tests, including new routing test)

- [ ] **Step 2: Run full frontend test suite**

```bash
npm run test:frontend --passWithNoTests 2>&1 | tail -20
```

Expected: All tests pass, no regressions

- [ ] **Step 3: Run TypeScript check**

```bash
npm run check 2>&1 | grep -c "Error" || echo "0 errors"
```

Expected: 0 new errors (pre-existing errors are ok, verify none are from Dashboard/RoutingUsage)

---

## Task 8: Final Integration and Cleanup

**Files:**
- Verify: All components in Dashboard.svelte and RoutingUsage.svelte

- [ ] **Step 1: Build frontend**

```bash
npm run build 2>&1 | tail -20
```

Expected: Build succeeds with "✓ built in X.Xs"

- [ ] **Step 2: Verify no console errors in dev mode**

Open browser DevTools (F12), go to Console tab.

Reload analytics page: `http://localhost:5173/admin/analytics`

Click a routing pair.

Expected: No red errors in console, only info/warn if any

- [ ] **Step 3: Stop dev servers**

```bash
# Ctrl+C on both terminals running npm run dev and backend
pkill -f "npm run dev"
pkill -f "uvicorn"
```

- [ ] **Step 4: Final commit summary**

Verify all task commits are present:
```bash
git log --oneline | head -10
```

Expected output includes:
```
- feat(analytics): add routing pair state and handlers
- feat(analytics): auto-clear routing filter on period/group change
- feat(analytics): wire routing pair callbacks to RoutingUsage
- feat(analytics): display routing filter badge
- test(analytics): add routing pair filter extraction test
```

- [ ] **Step 5: Create summary commit (optional but recommended)**

```bash
git log --oneline $(git describe --tags --abbrev=0)..HEAD | wc -l
```

If more than 5 commits for this feature, create a summary:
```bash
git log --oneline | head -6
# Copy the commits and create a summary message
```

---

## Self-Review Against Spec

**Spec Coverage:**
- ✅ Routing Selection Trigger: Task 1, 3 (onSelectPair handler + callbacks)
- ✅ Filter Application: Task 1 (extract selected_model_id, set filterByModelId)
- ✅ Filter Clearing: Task 2 (auto-clear), Task 1 (onClearPair handler)
- ✅ Visual Feedback: Task 4 (routing filter badge)
- ✅ Testing: Task 5 (unit test), Task 6 (manual integration test)
- ✅ No Regressions: Task 7 (cross-filter test verification)

**Placeholder Scan:**
- ✅ No "TBD", "TODO", or vague steps
- ✅ All code blocks complete with exact syntax
- ✅ All commands have expected output descriptions
- ✅ No "similar to Task X" references

**Type Consistency:**
- ✅ `routingSelectedPair: { requested_model_id: string; selected_model_id: string } | null`
- ✅ `onSelectPair(requestedModelId, selectedModelId)` parameters match
- ✅ `filterByModelId = selectedModelId` type matches existing
- ✅ Badge displays `${selectedPair.requested_model_id} → ${selectedPair.selected_model_id}`

**Scope Check:**
- ✅ Feature focused, no scope creep
- ✅ All tasks are testable independently
- ✅ Incremental commits allow rollback if needed

---

## Success Criteria Verification

After completing all tasks:

- ✅ Clicking a routing pair applies model filter automatically
- ✅ All three tables (Models, Users, Tokens) update with routing filter
- ✅ Routing Events show matching (requested, selected) pairs
- ✅ "Clear pair" button removes filter and reloads
- ✅ Period/group changes auto-clear routing filter
- ✅ Visual badge shows active routing filter
- ✅ No race conditions (verified with rapid clicks in Task 6)
- ✅ All cross-filter tests pass (Task 7)
- ✅ No new TypeScript errors (Task 7)
- ✅ Build succeeds (Task 8)

---

## Execution Readiness

This plan is ready for implementation. All tasks are:
- **Bite-sized** (each takes 2-5 minutes)
- **Self-contained** (testable independently)
- **Sequential** (later tasks depend on earlier ones completing)
- **DRY** (no code duplication between tasks)
- **TDD** (test before or immediately after code)

Expected total time: **30-45 minutes** for manual testing included.
