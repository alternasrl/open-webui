<script lang="ts">
	export let trend: Array<{ bucket: string; count: number }> = [];
	export let label = '';

	const W = 400;
	const H = 120;
	const PAD = 24;

	$: counts = trend.map((t) => t.count);
	$: maxCount = Math.max(...counts, 1);
	$: points = trend.map((t, i) => {
		const x = PAD + (i / Math.max(trend.length - 1, 1)) * (W - PAD * 2);
		const y = PAD + (1 - t.count / maxCount) * (H - PAD * 2);
		return `${x},${y}`;
	});
</script>

<div>
	{#if label}
		<p class="text-xs font-medium text-gray-700 dark:text-gray-300 mb-1 truncate" title={label}>
			{label}
		</p>
	{/if}
	{#if trend.length < 2}
		<p class="text-xs text-gray-400 text-center py-4">Dati insufficienti per il grafico</p>
	{:else}
		<svg
			viewBox="0 0 {W} {H}"
			class="w-full h-28"
			aria-label="Trend del cluster {label}"
			role="img"
		>
			<!-- grid lines -->
			{#each [0, 0.5, 1] as t}
				<line
					x1={PAD}
					y1={PAD + (1 - t) * (H - PAD * 2)}
					x2={W - PAD}
					y2={PAD + (1 - t) * (H - PAD * 2)}
					stroke="currentColor"
					stroke-width="0.5"
					class="text-gray-200 dark:text-gray-700"
					stroke-dasharray="4 4"
				/>
			{/each}
			<!-- line -->
			<polyline
				fill="none"
				stroke="currentColor"
				stroke-width="2"
				stroke-linejoin="round"
				stroke-linecap="round"
				class="text-blue-500"
				points={points.join(' ')}
			/>
			<!-- dots -->
			{#each trend as t, i}
				{@const x = PAD + (i / Math.max(trend.length - 1, 1)) * (W - PAD * 2)}
				{@const y = PAD + (1 - t.count / maxCount) * (H - PAD * 2)}
				<circle cx={x} cy={y} r="3" class="fill-blue-500" />
				{#if i === 0 || i === trend.length - 1}
					<text
						x={x}
						y={H - 4}
						text-anchor={i === 0 ? 'start' : 'end'}
						font-size="8"
						class="fill-gray-400 dark:fill-gray-500"
					>
						{t.bucket.slice(0, 10)}
					</text>
				{/if}
			{/each}
		</svg>
	{/if}
</div>
