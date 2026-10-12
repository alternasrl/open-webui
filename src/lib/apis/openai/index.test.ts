import { afterEach, describe, expect, it, vi } from 'vitest';
import { getErrorMessage, getOpenAIModels } from './index';

afterEach(() => {
	vi.unstubAllGlobals();
});

const failWith = (status: number, json: () => Promise<unknown>) =>
	vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: false, status, json }));

describe('getOpenAIModels errors', () => {
	it('falls back to the HTTP status for a non-JSON error body', async () => {
		failWith(502, async () => {
			throw new SyntaxError('Unexpected token <');
		});
		await expect(getOpenAIModels('t')).rejects.toBe('OpenAI: HTTP 502');
	});

	it('uses the nested string message of an OpenAI error body', async () => {
		failWith(401, async () => ({ error: { message: 'Bad key' } }));
		await expect(getOpenAIModels('t')).rejects.toBe('OpenAI: Bad key');
	});

	it('uses a string detail', async () => {
		failWith(400, async () => ({ detail: 'Invalid connection' }));
		await expect(getOpenAIModels('t')).rejects.toBe('OpenAI: Invalid connection');
	});

	it('never renders arrays or objects as the error text', async () => {
		failWith(422, async () => ({ detail: [{ loc: ['body'], msg: 'bad' }] }));
		await expect(getOpenAIModels('t')).rejects.toBe('OpenAI: Network Problem');
		failWith(500, async () => ({ error: { message: { nested: true } } }));
		await expect(getOpenAIModels('t')).rejects.toBe('OpenAI: Network Problem');
	});

	it('reports a network failure', async () => {
		vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new TypeError('Failed to fetch')));
		await expect(getOpenAIModels('t')).rejects.toBe('OpenAI: Failed to fetch');
	});
});

describe('getErrorMessage', () => {
	it('picks the first string and ignores arrays', () => {
		expect(getErrorMessage({ detail: { error: { message: 'deep' } } })).toBe('deep');
		expect(getErrorMessage([{ msg: 'x' }])).toBe('Server connection failed');
		expect(getErrorMessage({ detail: { a: 1 } }, 'fb')).toBe('fb');
	});
});
