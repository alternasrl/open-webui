import { readFileSync, readdirSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

const __dir = dirname(fileURLToPath(import.meta.url));
const localesDir = resolve(__dir, 'locales');
const locales = readdirSync(localesDir, { withFileTypes: true })
	.filter((entry) => entry.isDirectory())
	.map((entry) => entry.name);

const CUSTOM_KEYS = [
	'Clear filter',
	'Err%',
	'Failed to load analytics data',
	'Failed to load routing analytics',
	'Filtered by',
	'Last 1 hour',
	'request errors',
	'Time to First Token is shown when provider usage data includes timing information.',
	'Tok/s',
	'Token/s',
	'Token/s is shown when provider usage data includes throughput or duration details.',
	'TTFT',
	'View details'
];

const keysInSource = (text: string) =>
	[...text.matchAll(/^\t"((?:[^"\\]|\\.)*)":/gm)].map((m) => JSON.parse(`"${m[1]}"`));

describe('custom analytics translations', () => {
	it('covers all 64 locale catalogs', () => {
		expect(locales).toHaveLength(64);
	});

	it.each(locales)('%s is valid JSON without duplicate keys and has the custom keys', (locale) => {
		const text = readFileSync(resolve(localesDir, locale, 'translation.json'), 'utf-8');
		const parsed = JSON.parse(text);
		const keys = keysInSource(text);
		expect(keys.length).toBe(Object.keys(parsed).length);
		expect(new Set(keys).size).toBe(keys.length);
		for (const key of CUSTOM_KEYS) {
			expect(Object.prototype.hasOwnProperty.call(parsed, key), key).toBe(true);
			expect(typeof parsed[key]).toBe('string');
		}
	});

	it('uses every custom key from the sources', () => {
		const files = [
			'../components/admin/Analytics/Dashboard.svelte',
			'../components/admin/Analytics/RoutingUsage.svelte'
		].map((f) => readFileSync(resolve(__dir, f), 'utf-8'));
		const all = files.join('\n');
		for (const key of CUSTOM_KEYS) {
			expect(all.includes(`t('${key}'`) || all.includes(`'${key}'`), key).toBe(true);
		}
	});
});
