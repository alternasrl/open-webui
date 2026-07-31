<script lang="ts">
	export let clusters: Array<{
		id: string;
		canonical_label: string;
		cluster_size: number;
	}> = [];

	$: sorted = [...clusters].sort((a, b) => b.cluster_size - a.cluster_size);
	$: max = sorted[0]?.cluster_size ?? 1;
</script>

<div class="space-y-1.5">
	{#each sorted as c (c.id)}
		<div class="flex items-center gap-2 text-xs">
			<span
				class="w-40 truncate text-right text-gray-700 dark:text-gray-300 shrink-0"
				title={c.canonical_label}>{c.canonical_label}</span
			>
			<div class="flex-1 bg-gray-100 dark:bg-gray-800 rounded-full h-4 overflow-hidden">
				<div
					class="h-4 rounded-full bg-blue-500 dark:bg-blue-600 transition-all duration-300"
					style="width: {Math.round((c.cluster_size / max) * 100)}%"
				></div>
			</div>
			<span class="w-8 text-right text-gray-500 dark:text-gray-400 shrink-0">{c.cluster_size}</span>
		</div>
	{/each}
	{#if sorted.length === 0}
		<p class="text-xs text-gray-400 text-center py-2">Nessun cluster disponibile</p>
	{/if}
</div>
