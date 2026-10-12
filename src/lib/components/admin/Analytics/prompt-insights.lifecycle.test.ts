import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

const __dir = dirname(fileURLToPath(import.meta.url));
const source = readFileSync(resolve(__dir, './PromptInsights.svelte'), 'utf-8');

describe('Prompt Insights polling lifecycle', () => {
	it('polls every 5 seconds only while a run is active', () => {
		expect(source).toContain('$: isRunning = summary?.active_run != null;');
		expect(source).toMatch(
			/if \(isRunning\) \{\s*if \(!pollInterval\) \{\s*pollInterval = setInterval\(onLoadData, 5000\);/
		);
		expect(source.match(/setInterval\(/g)).toHaveLength(1);
	});

	it('stops polling when the run ends and on unmount', () => {
		expect(source).toMatch(
			/\} else \{\s*if \(pollInterval\) \{\s*clearInterval\(pollInterval\);\s*pollInterval = null;/
		);
		expect(source).toMatch(
			/onDestroy\(\(\) => \{\s*if \(pollInterval\) clearInterval\(pollInterval\);/
		);
	});

	it('Dashboard reloads Prompt Insights through the callback instead of its own timer', () => {
		const dashboard = readFileSync(resolve(__dir, './Dashboard.svelte'), 'utf-8');
		expect(dashboard).not.toContain('setInterval');
		expect(dashboard).toContain('onLoadData={loadPromptInsights}');
	});
});
