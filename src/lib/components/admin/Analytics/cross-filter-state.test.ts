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

  it('filters by selected model in selected mode', () => {
    const filters = deriveRoutingFilters({
      routingSelectedPair: null,
      filterByModelId: 'MODEL',
      routingModelMode: 'selected'
    });

    expect(filters).toEqual({ modelSelected: 'MODEL', modelRequested: null });
  });

  it('filters by requested model in requested mode', () => {
    const filters = deriveRoutingFilters({
      routingSelectedPair: null,
      filterByModelId: 'MODEL',
      routingModelMode: 'requested'
    });

    expect(filters).toEqual({ modelSelected: null, modelRequested: 'MODEL' });
  });

  it('returns nulls when no filter is active', () => {
    const filters = deriveRoutingFilters({
      routingSelectedPair: null,
      filterByModelId: null,
      routingModelMode: 'or'
    });

    expect(filters).toEqual({ modelSelected: null, modelRequested: null });
  });

  it('and mode behaves like or when model filter exists', () => {
    const filters = deriveRoutingFilters({
      routingSelectedPair: null,
      filterByModelId: 'MODEL',
      routingModelMode: 'and'
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
  });

  it('switches to new id when different', () => {
    expect(toggleSelection('u1', 'u2')).toBe('u2');
  });

  it('selects id when current is null', () => {
    expect(toggleSelection(null, 'u1')).toBe('u1');
  });
});
