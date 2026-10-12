import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { settleConnectionSave } from './connections-save';

const __dir = dirname(fileURLToPath(import.meta.url));
const read = (file: string) => readFileSync(resolve(__dir, file), 'utf-8');

const ok = (): Promise<boolean | null> => Promise.resolve(true);
const failed = (): Promise<boolean | null> => Promise.resolve(false);
const skipped = (): Promise<boolean | null> => Promise.resolve(null);
const rejects = (): Promise<boolean | null> => Promise.reject(new Error('boom'));

describe('settleConnectionSave', () => {
	it('is saved only when every attempted section persisted', async () => {
		expect(await settleConnectionSave([ok(), ok()])).toEqual({ saved: true, errors: [] });
		expect(await settleConnectionSave([ok(), skipped()])).toEqual({ saved: true, errors: [] });
	});

	it('does not report success when both sections fail', async () => {
		expect((await settleConnectionSave([failed(), failed()])).saved).toBe(false);
	});

	it('does not report success when nothing was attempted', async () => {
		expect((await settleConnectionSave([skipped(), skipped()])).saved).toBe(false);
	});

	it('does not report success on partial success', async () => {
		expect((await settleConnectionSave([ok(), failed()])).saved).toBe(false);
		expect((await settleConnectionSave([failed(), ok()])).saved).toBe(false);
	});

	it('treats a rejected promise as a failure and surfaces the error', async () => {
		const result = await settleConnectionSave([ok(), rejects()]);
		expect(result.saved).toBe(false);
		expect(result.errors).toHaveLength(1);
	});
});

describe('Connections save wiring', () => {
	const connections = read('./Connections.svelte');

	it('dispatches save only from the settled outcome, after persistence', () => {
		expect(connections.match(/dispatch\('save'\)/g)).toHaveLength(1);
		const submit = connections.split('const submitHandler')[1];
		expect(submit.indexOf('await settleConnectionSave')).toBeGreaterThan(-1);
		expect(submit.indexOf('await settleConnectionSave')).toBeLessThan(
			submit.indexOf("dispatch('save')")
		);
		expect(submit).toContain('if (saved)');
		expect(submit).toContain('await config.set(await getBackendConfig())');
	});

	it('returns null for a skipped section, false for a failure and true for success', () => {
		for (const handler of ['updateOpenAIHandler', 'updateOllamaHandler']) {
			const body = connections.split(`const ${handler}`)[1].split('const update')[0];
			expect(body).toContain('return true;');
			expect(body).toContain('return false;');
			expect(body).toContain('return null;');
		}
	});

	it('awaits the parent onSubmit in both connection wrappers', () => {
		for (const file of [
			'./Connections/OpenAIConnection.svelte',
			'./Connections/OllamaConnection.svelte'
		]) {
			expect(read(file)).toContain('await onSubmit(connection);');
		}
	});
});
