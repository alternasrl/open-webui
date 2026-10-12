import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

const __dir = dirname(fileURLToPath(import.meta.url));
const source = readFileSync(resolve(__dir, './Dashboard.svelte'), 'utf-8');

describe('Dashboard token tooltip and metric scales', () => {
	it('opens on hover, focus and click', () => {
		expect(source).toContain("trigger: 'mouseenter focus click'");
		expect(source).toContain('as="button"');
	});

	it('hides on Escape and drops the instance on destroy', () => {
		expect(source).toMatch(
			/<svelte:window[\s\S]*event\.key === 'Escape'\) tokenTooltip\?\.hide\(\)/
		);
		expect(source).toContain('onCreate: (instance) => (tokenTooltip = instance)');
		expect(source).toContain('onDestroy: () => (tokenTooltip = null)');
	});

	it('shows input and output totals, defaulting to zero when the API gives none', () => {
		expect(source).toContain('let totalTokens = { input: 0, output: 0, total: 0 };');
		expect(source).toContain(
			'${$i18n.t(\'Input\')}</span><span class="tabular-nums">${totalTokens.input.toLocaleString()}'
		);
		expect(source).toContain(
			'${$i18n.t(\'Output\')}</span><span class="tabular-nums">${totalTokens.output.toLocaleString()}'
		);
		expect(source).toContain('tokenStats[model.model_id]?.input_tokens ?? 0');
		expect(source).toContain('tokenStats[model.model_id]?.output_tokens ?? 0');
	});

	it('keeps the custom metrics next to the token tooltip, with missing values as N/A or dash', () => {
		expect(source).toContain(
			"summary.avg_ttft_ms != null ? `${summary.avg_ttft_ms.toFixed(0)} ms` : 'N/A'"
		);
		expect(source).toContain(
			"model.avg_ttft_ms != null ? model.avg_ttft_ms.toFixed(0) + ' ms' : '—'"
		);
		expect(source).toContain('model.avg_tokens_per_second != null');
		expect(source).toContain("{$i18n.t('request errors')}");
	});

	it('keeps the two error-rate scales: summary in percent, per-model as a fraction', () => {
		expect(source).toContain('summary.error_rate.toFixed(1)');
		expect(source).not.toContain('summary.error_rate * 100');
		expect(source).toContain('(model.error_rate * 100).toFixed(1)');
	});
});
