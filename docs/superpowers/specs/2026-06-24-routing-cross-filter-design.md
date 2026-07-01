# Routing-Aware Cross-Filter Design

**Date:** 2026-06-24  
**Feature:** Enable cross-filtering in Analytics Dashboard when selecting routing pairs  
**Status:** Design approved, ready for implementation

---

## Overview

Enable users to click on a routing pair (e.g., "gpt-4 → mistral") in the Routing section and automatically filter all analytics tables to show users and token consumption for that specific model routing scenario.

**User Goal:** "When gpt-4 is rerouted to mistral, I want to see which users received mistral and how many tokens they consumed."

---

## Requirements

### Functional Requirements

1. **Routing Selection Trigger**
   - Clicking a row in the Routing table (e.g., "gpt-4 → mistral") triggers cross-filter
   - Selected pair is visually highlighted (already implemented)
   - Filter applies automatically (no confirmation needed)

2. **Filter Application**
   - When a routing pair is selected: extract `selected_model_id` and apply as `filterByModelId`
   - All three tables reload with this filter:
     - Model Usage: shows models used by users receiving `selected_model_id`
     - User Activity: shows users receiving `selected_model_id`
     - Token stats: shows token consumption for `selected_model_id` only
   - Routing Events section filters to show only matching `(requested_model_id, selected_model_id)` pairs

3. **Filter Clearing**
   - "Clear pair" button in Routing header clears `routingSelectedPair` and `filterByModelId`
   - Auto-clear when user selects a different routing pair
   - Auto-clear when period/group filters change
   - Auto-clear when user clicks on a user/model in other sections (to avoid conflicts)

4. **Visual Feedback**
   - Badge near Routing section header showing active routing filter:
     - Format: "Routing filter: [requested_model_id → selected_model_id]"
     - Color: blue (matches other active filters)
   - If no routing pair selected: badge not shown

### Non-Functional Requirements

- No new API endpoints required (backend already supports model filtering)
- Race-guard tracking maintains consistency across parallel requests
- Performance: all table reloads complete within existing timeouts
- No pre-existing type errors introduced

---

## Architecture

### Component Changes

#### **Dashboard.svelte**

**New state:**
```typescript
let routingSelectedPair: { requested_model_id: string; selected_model_id: string } | null = null;
```

**Modified handlers:**

1. **onSelectPair()** (called from RoutingUsage.svelte):
   ```typescript
   const onSelectPair = (requestedModelId: string, selectedModelId: string) => {
     routingSelectedPair = { requested_model_id: requestedModelId, selected_model_id: selectedModelId };
     filterByModelId = selectedModelId; // Extract selected model and apply as filter
     // Race guards ensure reloads use latest request IDs
     reloadModelTable();
     reloadUserTable();
     loadRoutingAnalytics();
   };
   ```

2. **onClearPair()** (called from RoutingUsage.svelte):
   ```typescript
   const onClearPair = () => {
     routingSelectedPair = null;
     filterByModelId = null;
     reloadModelTable();
     reloadUserTable();
     loadRoutingAnalytics();
   };
   ```

3. **Period/Group filter changes** (already in $: reactive statements):
   - Auto-clear: `routingSelectedPair = null` when `selectedPeriod` or `selectedGroupId` changes

**Prop updates:**
- Pass `onSelectPair` and `onClearPair` callbacks to RoutingUsage component
- Pass `routingSelectedPair` for visual highlighting (already done)

#### **RoutingUsage.svelte**

**No structural changes required:**
- Component already has `onSelectPair` and `onClearPair` callbacks exported
- Component already highlights selected pair
- Just ensure Dashboard passes the callbacks

### Data Flow

```
Click routing pair (gpt-4 → mistral)
  ↓
RoutingUsage → Dashboard.onSelectPair('gpt-4', 'mistral')
  ↓
Dashboard.routingSelectedPair = {requested: 'gpt-4', selected: 'mistral'}
Dashboard.filterByModelId = 'mistral'
  ↓
Parallel requests (race-guarded):
  • getModelAnalytics(..., filterByUserId, 'mistral')
  • getUserAnalytics(..., 'mistral')
  • getTokenUsage(..., filterByUserId, 'mistral')
  • getRoutingEvents(..., modelSelected='mistral', modelRequested='gpt-4')
  ↓
State updates (only if latest request):
  • modelStats ← [models filtered by mistral usage]
  • userStats ← [users filtered by mistral receipt]
  • tokenStats ← [tokens for mistral only]
  • routingEvents ← [events matching (gpt-4 → mistral)]
  ↓
UI renders with filter badge and highlighted pair
```

### API Requirements

**Existing API already supports routing filter:**
- `getRoutingEvents()` accepts `modelSelected` parameter (filters events by selected model)
- `getModelAnalytics()` accepts `user_id` parameter (filters models by user)
- `getUserAnalytics()` accepts `model_id` parameter (filters users by model)
- `getTokenUsage()` accepts `model_id` parameter (filters tokens by model, recently added)

**No backend changes needed** — all endpoints already support the required filtering.

---

## Implementation Tasks

1. **Dashboard.svelte updates:**
   - Add `routingSelectedPair` state variable
   - Implement `onSelectPair()` handler (extract `selected_model_id`, set `filterByModelId`, reload tables)
   - Implement `onClearPair()` handler (clear both filters, reload tables)
   - Add auto-clear logic to `$: if (selectedPeriod || selectedGroupId)` reactive statement
   - Pass callbacks to RoutingUsage component

2. **RoutingUsage.svelte:**
   - No changes (already has callbacks wired in parent)

3. **UI/Visual Feedback:**
   - Add routing filter badge to Routing section header
   - Display: "Routing filter: [requested → selected]" when `routingSelectedPair` is set

4. **Testing:**
   - Verify routing pair click applies filter and reloads tables
   - Verify clear button resets filter
   - Verify period/group change clears routing filter
   - Test rapid clicks (race-guard protection)
   - Verify token stats reflect filtered model

5. **Integration verification:**
   - Manual test: click model in routing → see filtered users + token stats
   - Manual test: rapid switches between routing pairs → no race conditions
   - No regressions in existing cross-filter behavior

---

## Testing Strategy

### Unit Tests
- `cross-filter-state.test.ts`: Add test case for routing pair filter extraction
- Verify `deriveRoutingFilters()` correctly extracts `selected_model_id` when routing pair is selected

### Integration Tests
- Click routing pair → verify state updates (filterByModelId set correctly)
- Clear pair → verify state resets
- Period change → verify routing pair clears
- Rapid clicks → verify race guards prevent stale updates

### Manual Testing Scenarios
1. **Scenario A: Basic routing filter**
   - Select a high-traffic routing pair (e.g., "gpt-4 → mistral")
   - Verify User Activity shows only users who received mistral
   - Verify Model Usage shows models used by those users
   - Verify Token Usage shows only mistral tokens

2. **Scenario B: Rare routing**
   - Select a low-traffic pair
   - Verify "No users" / "No models" if no data matches
   - Verify error handling works

3. **Scenario C: Filter conflict resolution**
   - Select a routing pair, then click a user directly
   - Verify routing pair clears (user filter takes precedence)
   - Verify tables update correctly

4. **Scenario D: Race condition resistance**
   - Rapidly click different routing pairs
   - Verify only latest pair's data displays
   - Verify no stale data leaks through

---

## Success Criteria

- ✅ Clicking a routing pair applies model filter automatically
- ✅ All three tables (Models, Users, Tokens) update with routing filter
- ✅ Routing Events show only matching `(requested, selected)` pairs
- ✅ "Clear pair" button removes filter and reloads
- ✅ Period/group changes auto-clear routing filter
- ✅ Visual badge shows active routing filter
- ✅ No race conditions (verified with rapid clicks)
- ✅ All existing cross-filter tests pass
- ✅ No new TypeScript errors introduced

---

## Files to Modify

1. **src/lib/components/admin/Analytics/Dashboard.svelte**
   - Add `routingSelectedPair` state
   - Add `onSelectPair()` and `onClearPair()` handlers
   - Add auto-clear logic for period/group changes
   - Pass callbacks to RoutingUsage

2. **src/lib/components/admin/Analytics/RoutingUsage.svelte**
   - Add routing filter badge to header
   - Ensure `onSelectPair` and `onClearPair` are called correctly (already wired, verify)

3. **src/lib/components/admin/Analytics/cross-filter-state.test.ts**
   - Add test case for routing pair filter extraction

---

## Assumptions

- Backend filtering already works (verified in previous cross-filter fix)
- Race-guard tracking in Dashboard.svelte is sufficient for consistency
- User expects routing pair clear when other filters change (standard cross-filter behavior)
- "selected_model_id" is always the model the user actually got (not null)

---

## Risks and Mitigation

| Risk | Mitigation |
|------|-----------|
| Race condition between routing selection and other filter changes | Race guards + request ID tracking already in place |
| User confusion about filter scope | Clear visual badge + "Clear pair" button |
| Performance impact of frequent filter changes | Existing debouncing + request tracking prevents duplicate calls |
| Stale data from previous routing pair | Latest request ID check before state update (already implemented) |

---

## Future Enhancements (Out of Scope)

- Export routing analysis as CSV
- Drill-down into individual routing events
- Alerts for unusual routing patterns
- Routing trends over time

---

## Related PRs and Issues

- Previous fix: "add model_id filter to tokens endpoint" (2026-06-24)
- Related: Cross-filter race condition fix (systematic debugging session)
