<script lang="ts">
	export let topics: Array<{
		canonical_label: string;
		recent_count: number;
		total_count: number;
		growth_ratio: number;
	}> = [];

	function badge(ratio: number) {
		if (ratio >= 3) return { text: '🔥 Nuovo', cls: 'text-red-600 dark:text-red-400' };
		if (ratio >= 1.5) return { text: '📈 Crescita', cls: 'text-amber-600 dark:text-amber-400' };
		return { text: '→ Stabile', cls: 'text-gray-400' };
	}
</script>

<div class="scrollbar-hidden overflow-x-auto">
	<table class="w-full text-sm text-left text-gray-500 dark:text-gray-400 table-auto">
		<thead class="text-xs text-gray-800 uppercase bg-transparent dark:text-gray-200">
			<tr class="border-b-[1.5px] border-gray-50 dark:border-gray-850/30">
				<th class="px-2.5 py-2">Argomento</th>
				<th class="px-2.5 py-2 text-right">Recenti</th>
				<th class="px-2.5 py-2 text-right">Totale</th>
				<th class="px-2.5 py-2 text-right">Crescita</th>
				<th class="px-2.5 py-2 text-right">Stato</th>
			</tr>
		</thead>
		<tbody>
			{#each topics as t (t.canonical_label)}
				{@const b = badge(t.growth_ratio)}
				<tr class="bg-white dark:bg-gray-900 text-xs hover:bg-gray-50 dark:hover:bg-gray-800">
					<td class="px-3 py-1.5 font-medium text-gray-900 dark:text-white max-w-[16rem] truncate"
						>{t.canonical_label}</td
					>
					<td class="px-3 py-1.5 text-right">{t.recent_count}</td>
					<td class="px-3 py-1.5 text-right text-gray-400">{t.total_count}</td>
					<td class="px-3 py-1.5 text-right"
						>{t.growth_ratio >= 9999 ? '∞' : t.growth_ratio.toFixed(1)}×</td
					>
					<td class="px-3 py-1.5 text-right font-medium {b.cls}">{b.text}</td>
				</tr>
			{/each}
			{#if topics.length === 0}
				<tr
					><td colspan="5" class="px-3 py-3 text-center text-gray-400"
						>Nessun argomento emergente</td
					></tr
				>
			{/if}
		</tbody>
	</table>
</div>
