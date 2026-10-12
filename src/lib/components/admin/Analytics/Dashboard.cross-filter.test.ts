import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { createRequestTracker, deriveRoutingFilters, toggleSelection } from './cross-filter-state';

const __dir = dirname(fileURLToPath(import.meta.url));
const source = readFileSync(resolve(__dir, './Dashboard.svelte'), 'utf-8');

describe('Dashboard cross-filter transitions', () => {
	it('clears the routing pair and model filter, but keeps the user, when period or group changes', () => {
		const block = source.match(/\$: if \(selectedPeriod === 'custom'[\s\S]*?\n\t\}\n/)?.[0];
		expect(block).toBeDefined();
		expect(block).toContain('selectedGroupId;');
		expect(block).toContain('routingSelectedPair = null;');
		expect(block).toContain('filterByModelId = null;');
		expect(block).not.toContain('filterByUserId = null');
		expect(block).not.toContain('filterByUserName');
	});

	it('does not extend user/model filters to the summary and daily endpoints', () => {
		expect(source).toContain('getSummary(localStorage.token, start, end, selectedGroupId)');
		expect(source).toContain(
			'getDailyStats(localStorage.token, start, end, granularity, selectedGroupId)'
		);
	});

	it('guards every async loader with a request tracker', () => {
		for (const tracker of ['dashboardTracker', 'routingTracker', 'modelTracker', 'userTracker']) {
			expect(source).toContain(`const ${tracker} = createRequestTracker();`);
			expect(source).toContain(`${tracker}.isLatest(requestId)`);
		}
	});

	it('ignores stale responses through the tracker', () => {
		const tracker = createRequestTracker();
		const first = tracker.next();
		const second = tracker.next();
		expect(tracker.isLatest(first)).toBe(false);
		expect(tracker.isLatest(second)).toBe(true);
	});

	it('derives selected/requested routing filters, pair taking precedence', () => {
		const pair = { requested_model_id: 'auto', selected_model_id: 'gpt-4o' };
		expect(
			deriveRoutingFilters({
				routingSelectedPair: pair,
				filterByModelId: 'other',
				routingModelMode: 'or'
			})
		).toEqual({ modelSelected: 'gpt-4o', modelRequested: 'auto' });
		const base = { routingSelectedPair: null, filterByModelId: 'm1' };
		expect(deriveRoutingFilters({ ...base, routingModelMode: 'selected' })).toEqual({
			modelSelected: 'm1',
			modelRequested: null
		});
		expect(deriveRoutingFilters({ ...base, routingModelMode: 'requested' })).toEqual({
			modelSelected: null,
			modelRequested: 'm1'
		});
		expect(
			deriveRoutingFilters({
				routingSelectedPair: null,
				filterByModelId: null,
				routingModelMode: 'and'
			})
		).toEqual({ modelSelected: null, modelRequested: null });
	});

	it('toggles a selection off when selected again', () => {
		expect(toggleSelection('a', 'a')).toBeNull();
		expect(toggleSelection('a', 'b')).toBe('b');
	});
});
