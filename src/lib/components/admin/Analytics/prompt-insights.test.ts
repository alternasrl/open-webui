import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dir = dirname(__filename);

describe('PromptInsights component', () => {
	it('exports a Svelte component', async () => {
		const mod = await import('./PromptInsights.svelte');
		expect(mod.default).toBeDefined();
	});

	it('contains empty state message', () => {
		const src = readFileSync(resolve(__dir, './PromptInsights.svelte'), 'utf-8');
		expect(src).toContain('Nessuna analisi disponibile. Avvia la prima analisi.');
	});
});
