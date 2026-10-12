import { afterEach, describe, expect, it, vi } from 'vitest';
import { getModelAnalytics, getTokenUsage, getUserAnalytics, getRoutingSummary } from './index';

const okResponse = (body: unknown) => ({ ok: true, json: async () => body });

afterEach(() => {
	vi.unstubAllGlobals();
});

const stubFetch = (response: unknown) => {
	const fetchMock = vi.fn().mockResolvedValue(response);
	vi.stubGlobal('fetch', fetchMock);
	return fetchMock;
};

const urlOf = (fetchMock: ReturnType<typeof vi.fn>) =>
	new URL(fetchMock.mock.calls[0][0], 'http://x');

describe('analytics API client', () => {
	it('sends the cross-filter user_id and model_id parameters', async () => {
		let fetchMock = stubFetch(okResponse({ models: [] }));
		await getModelAnalytics('t', 1, 2, 'g1', 'u1');
		expect(urlOf(fetchMock).searchParams.get('user_id')).toBe('u1');
		expect(urlOf(fetchMock).searchParams.get('group_id')).toBe('g1');

		fetchMock = stubFetch(okResponse({ users: [] }));
		await getUserAnalytics('t', 1, 2, 50, 'g1', 'm1');
		expect(urlOf(fetchMock).searchParams.get('model_id')).toBe('m1');

		fetchMock = stubFetch(okResponse({ models: [] }));
		await getTokenUsage('t', null, null, null, 'u1', 'm1');
		const params = urlOf(fetchMock).searchParams;
		expect(params.get('user_id')).toBe('u1');
		expect(params.get('model_id')).toBe('m1');
		expect(params.has('start_date')).toBe(false);
	});

	it('omits empty filters', async () => {
		const fetchMock = stubFetch(okResponse({ models: [] }));
		await getModelAnalytics('t');
		expect([...urlOf(fetchMock).searchParams.keys()]).toEqual([]);
	});

	it('sends routing filters and the model mode', async () => {
		const fetchMock = stubFetch(okResponse([]));
		await getRoutingSummary('t', { modelSelected: 'a', modelRequested: 'b', modelMode: 'and' });
		const params = urlOf(fetchMock).searchParams;
		expect(params.get('model_selected')).toBe('a');
		expect(params.get('model_requested')).toBe('b');
		expect(params.get('model_mode')).toBe('and');
	});

	it('throws the backend detail on an error response', async () => {
		stubFetch({ ok: false, json: async () => ({ detail: 'forbidden' }) });
		vi.spyOn(console, 'error').mockImplementation(() => {});
		await expect(getModelAnalytics('t')).rejects.toBe('forbidden');
	});
});
