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
