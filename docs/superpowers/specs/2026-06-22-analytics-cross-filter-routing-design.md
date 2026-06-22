# Analytics Cross-Filter Routing Design

Date: 2026-06-22  
Repository: open-webui  
Scope: Admin Analytics UI (frontend only)

## 1. Goal

When selecting an entity in Analytics:
- Selecting a user must show:
  - all models used by that user
  - routing summary and routing events for that user
- Selecting a model must show:
  - users that used that model
  - routing summary and routing events aligned to the model filter

Routing panel must always display both:
- aggregated requested -> selected summary
- detailed events list

## 2. Constraints and decisions

### Hard constraints
- Minimize backend impact.
- Do not change backend API contracts.
- Do not add backend endpoints.

### Chosen approach
- Approach 1: UI-only orchestration using existing endpoints.

### Explicit decisions from brainstorming
- Routing detail visibility: always visible (summary + events).
- Default routing model mode for model selection: or.

## 3. Existing implementation baseline

Current dashboard already includes:
- cross-filter state for model and user selection
- routing summary/events fetching
- routing pair selection drill-down

Files involved:
- src/lib/components/admin/Analytics/Dashboard.svelte
- src/lib/components/admin/Analytics/RoutingUsage.svelte
- src/lib/apis/analytics/index.ts

Backend remains unchanged:
- backend/open_webui/routers/analytics.py
- backend/open_webui/models/chat_messages.py

## 4. Functional design

### 4.1 State model

Primary state in dashboard:
- filterByUserId, filterByUserName
- filterByModelId, filterByModelName
- routingModelMode (default: or)
- routingSelectedPair (requested_model_id, selected_model_id)

Loading state:
- loading (global first load)
- loadingModels
- loadingUsers
- loadingRouting

Race guard state:
- request tokens or incremental request ids for async reloads

### 4.2 Interactions

#### User row click
- Toggle selected user.
- Reload model table and routing data.
- Keep user row highlight and user filter badge visible.

#### Model row click
- Toggle selected model.
- Keep routingModelMode default on or unless user explicitly changes it.
- Reload user table and routing data.
- Keep model row highlight and model filter badge visible.

#### Routing pair click
- Set routingSelectedPair.
- Reload routing and constrain events to selected pair.
- Clear pair returns to current user/model filtered routing view.

### 4.3 Routing filter semantics

Routing requests use existing parameters:
- userId from filterByUserId
- modelSelected and modelRequested derived by current mode
- modelMode set to routingModelMode (default or)

If routingSelectedPair exists, it has precedence for routing fetch:
- modelSelected = pair.selected_model_id
- modelRequested = pair.requested_model_id

### 4.4 UX transparency

Because backend is unchanged, some aggregated table metrics may remain only partially cross-filtered.
UI must clearly show active filters to reduce interpretation ambiguity:
- visible badges for active user/model filters
- short explanatory note near routing panel

## 5. Data flow

### 5.1 Initial load
- On mount and period/group changes:
  - loadDashboard()
  - loadRoutingAnalytics()

### 5.2 Partial reloads
- User selection:
  - reloadModelTable()
  - loadRoutingAnalytics()
- Model selection:
  - reloadUserTable()
  - loadRoutingAnalytics()
- Pair selection:
  - loadRoutingAnalytics()

### 5.3 Race condition mitigation

Introduce per-panel request id guards:
- increment request id before each async call
- apply response only if request id matches latest id

This ensures stale responses from slower requests do not overwrite newer state.

## 6. Error handling

- If routing fetch fails:
  - set routing pairs/events to empty
  - keep UI responsive and show empty state
- If model or user partial reload fails:
  - keep other panel unchanged
  - preserve active filter state
  - log error to console

## 7. Acceptance criteria

1. Routing panel is always visible with both summary and events.
2. User -> model/routing cross-filter works with toggle behavior.
3. Model -> user/routing cross-filter works with toggle behavior.
4. Default model mode remains or unless manually changed.
5. Routing pair drill-down constrains event list correctly.
6. Clear actions restore expected filtered baseline state.
7. No backend files or API contracts are modified.
8. No regressions on period/group filters and sorting behavior.

## 8. Test plan

### Manual scenarios
- Select/deselect a user and verify model + routing updates.
- Select/deselect a model and verify user + routing updates.
- Combine user + model filters and verify routing coherence.
- Select a routing pair and verify event narrowing.
- Clear pair and clear filters in different orders.
- Rapid click changes to validate race guard behavior.

### Automated frontend tests (recommended)
- state transitions for user/model toggles
- routing pair precedence
- request id race guard behavior
- unchanged behavior for period/group filter triggers

## 9. Out of scope

- backend query refactors
- new analytics backend endpoints
- exact backend-level cross-filter parity for all aggregate metrics

## 10. Rollout strategy

1. Implement UI/state changes behind existing analytics flow.
2. Validate with manual scenarios.
3. Add focused frontend tests.
4. Ship without backend migration.

## 11. Risks and mitigations

Risk: partial data coherence due to backend unchanged.  
Mitigation: explicit filter badges and routing-first interpretation.

Risk: stale async responses during rapid interactions.  
Mitigation: request id race guards.

Risk: misunderstanding of or mode semantics.  
Mitigation: keep mode selector visible and default to or as requested.
