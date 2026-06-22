import { describe, expect, it } from 'vitest';
import { deriveRoutingFilters } from './cross-filter-state';

function filterPair(
	selected: string,
	requested: string,
	modelFilter: string,
	mode: 'selected' | 'requested' | 'or' | 'and'
) {
	if (!modelFilter) return true;
	if (mode === 'selected') return selected === modelFilter;
	if (mode === 'requested') return requested === modelFilter;
	if (mode === 'and') return selected === modelFilter && requested === modelFilter;
	return selected === modelFilter || requested === modelFilter;
}

describe('routing filter mode', () => {
	it('supports selected/requested/or/and', () => {
		expect(filterPair('A', 'B', 'A', 'selected')).toBe(true);
		expect(filterPair('A', 'B', 'B', 'requested')).toBe(true);
		expect(filterPair('A', 'B', 'B', 'or')).toBe(true);
		expect(filterPair('A', 'B', 'A', 'and')).toBe(false);
	});
});

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