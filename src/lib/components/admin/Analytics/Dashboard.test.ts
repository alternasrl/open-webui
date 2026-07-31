import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

const __filename = fileURLToPath(import.meta.url);
const __dir = dirname(__filename);

function getModelUsageBlock() {
	const source = readFileSync(resolve(__dir, './Dashboard.svelte'), 'utf-8');
	return source.split('<!-- Model Usage Table -->')[1].split('<!-- User Activity Table -->')[0];
}

describe('Analytics dashboard Model Usage layout', () => {
	it('keeps one Model Usage table block with one header and one body', () => {
		const block = getModelUsageBlock();

		expect((block.match(/<thead/g) ?? []).length).toBe(1);
		expect((block.match(/<tbody/g) ?? []).length).toBe(1);
	});

	it('keeps one copy of each GIADA metric column in the Model Usage header', () => {
		const block = getModelUsageBlock();

		expect((block.match(/toggleModelSort\('ttft'\)/g) ?? []).length).toBe(1);
		expect((block.match(/toggleModelSort\('tps'\)/g) ?? []).length).toBe(1);
		expect((block.match(/toggleModelSort\('error_rate'\)/g) ?? []).length).toBe(1);
		expect((block.match(/\$i18n\.t\('TTFT'\)/g) ?? []).length).toBe(1);
		expect((block.match(/\$i18n\.t\('Tok\/s'\)/g) ?? []).length).toBe(1);
		expect((block.match(/\$i18n\.t\('Err%'\)/g) ?? []).length).toBe(1);
	});

	it('keeps the existing drill-down affordance on model rows', () => {
		const block = getModelUsageBlock();

		expect(block).toContain("selectedModel = { id: model.model_id, name: model.name ?? model.model_id }");
		expect(block).toContain('reloadUserTable();');
	});
});
