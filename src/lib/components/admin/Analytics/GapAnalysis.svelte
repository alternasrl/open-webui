<script lang="ts">
	export let gaps: Array<{
		cluster_label: string;
		gap_type: 'KB' | 'Skill' | 'Routing';
		confidence: number;
	}> = [];

	const gapTypeColor: Record<string, string> = {
		KB: 'bg-purple-100 text-purple-700 dark:bg-purple-900/30 dark:text-purple-300',
		Skill: 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-300',
		Routing: 'bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-300'
	};
</script>

{#if gaps.length === 0}
	<p class="text-xs text-gray-400 text-center py-4">Nessuna lacuna identificata</p>
{:else}
	<div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
		{#each gaps as g (g.cluster_label + g.gap_type)}
			<div class="border border-gray-200 dark:border-gray-700 rounded-lg p-3 space-y-1.5">
				<p class="text-xs font-medium text-gray-900 dark:text-white truncate" title={g.cluster_label}>
					{g.cluster_label}
				</p>
				<div class="flex items-center justify-between">
					<span
						class="text-xs font-semibold px-2 py-0.5 rounded {gapTypeColor[g.gap_type] ??
							'bg-gray-100 text-gray-600'}">{g.gap_type}</span
					>
					<span class="text-xs text-gray-500"
						>Confidenza: {Math.round(g.confidence * 100)}%</span
					>
				</div>
			</div>
		{/each}
	</div>
{/if}
