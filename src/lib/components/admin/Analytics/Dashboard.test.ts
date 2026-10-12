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

function getModelUsageHeader() {
	return getModelUsageBlock().split('<thead')[1].split('</thead>')[0];
}

function getModelUsageBody() {
	return getModelUsageBlock().split('<tbody>')[1].split('</tbody>')[0];
}

// The Input/Output headers come from one `{#each}` that renders two <th> elements.
function countHeaderColumns(header: string) {
	const literal = (header.match(/<th\b/g) ?? []).length;
	const eachColumns = (header.match(/\{#each \[((?:\{[^}]*\},?\s*)+)\] as column\}/) ?? [])[1];
	const generated = eachColumns ? (eachColumns.match(/\{/g) ?? []).length : 0;
	return generated ? literal - 1 + generated : literal;
}

describe('Analytics dashboard Model Usage layout', () => {
	it('renders one 12-column table with input/output token columns and a matching empty state', () => {
		const block = getModelUsageBlock();
		expect(countHeaderColumns(getModelUsageHeader())).toBe(12);
		expect(block).toContain("{ key: 'input_tokens', label: 'Input' }");
		expect(block).toContain("{ key: 'output_tokens', label: 'Output' }");
		expect(block).toContain('toggleModelSort(column.key)');
		expect(block).toContain('colspan="12"');
	});

	it('keeps header and body column counts aligned', () => {
		const header = getModelUsageHeader();
		const body = getModelUsageBody();
		const headerColumns = countHeaderColumns(header);
		const rows = body.match(/<tr[\s\S]*?<\/tr>/g) ?? [];

		expect((getModelUsageBlock().match(/<thead/g) ?? []).length).toBe(1);
		expect((getModelUsageBlock().match(/<tbody/g) ?? []).length).toBe(1);
		expect(headerColumns).toBeGreaterThan(0);
		expect(rows).not.toHaveLength(0);
		for (const row of rows) {
			expect((row.match(/<td\b/g) ?? []).length).toBe(headerColumns);
		}
	});

	it('keeps one copy of each GIADA metric cell in model rows', () => {
		const block = getModelUsageBlock();
		const rows = block.match(/<tbody>[\s\S]*?<\/tbody>/)?.[0].match(/<tr[\s\S]*?<\/tr>/g) ?? [];
		const firstRow = rows[0] ?? '';

		expect((block.match(/toggleModelSort\('ttft'\)/g) ?? []).length).toBe(1);
		expect((block.match(/toggleModelSort\('tps'\)/g) ?? []).length).toBe(1);
		expect((block.match(/toggleModelSort\('error_rate'\)/g) ?? []).length).toBe(1);
		expect((block.match(/\$i18n\.t\('TTFT'\)/g) ?? []).length).toBe(1);
		expect((block.match(/\$i18n\.t\('Tok\/s'\)/g) ?? []).length).toBe(1);
		expect((block.match(/\$i18n\.t\('Err%'\)/g) ?? []).length).toBe(1);
		expect((firstRow.match(/<td\b/g) ?? []).length).toBe(12);
		expect(block).toContain(
			'selectedModel = { id: model.model_id, name: model.name ?? model.model_id }'
		);
		expect(block).toContain('reloadUserTable();');
	});
});
