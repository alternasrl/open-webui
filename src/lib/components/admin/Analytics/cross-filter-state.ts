export type RoutingMode = 'or' | 'and' | 'selected' | 'requested';

export type RoutingPair = {
  requested_model_id: string;
  selected_model_id: string;
};

/**
 * Derives routing filter parameters based on active selections.
 *
 * Precedence:
 * 1. If a routing pair is selected, use pair values directly.
 * 2. Otherwise, use `filterByModelId` according to `routingModelMode`.
 * 3. If no model filter is active, return nulls.
 *
 * Routing mode semantics:
 * - `selected`: filter only selected model id.
 * - `requested`: filter only requested model id.
 * - `or` and `and`: currently both map to filtering both selected and requested
 *   with the same model id. This is intentional for server-side compatibility and
 *   leaves room for divergent semantics in future query builders.
 */
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

/**
 * Creates a monotonically increasing request id tracker.
 *
 * Use this to ignore stale async responses and only apply the latest request.
 */
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

/**
 * Toggles a selected id.
 *
 * If `current` equals `next`, it returns null (deselect). Otherwise it returns
 * `next` (select or switch selection).
 */
export function toggleSelection(current: string | null, next: string): string | null {
  return current === next ? null : next;
}
