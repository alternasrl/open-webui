// Each section resolves to true (persisted), false (failed) or null (not attempted).
export const settleConnectionSave = async (
	sections: Promise<boolean | null>[]
): Promise<{ saved: boolean; errors: unknown[] }> => {
	const results = await Promise.allSettled(sections);
	const errors = results.flatMap((r) => (r.status === 'rejected' ? [r.reason] : []));
	const outcomes = results.map((r) => (r.status === 'fulfilled' ? r.value : false));

	return {
		saved: outcomes.some((o) => o === true) && !outcomes.some((o) => o === false),
		errors
	};
};
