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
