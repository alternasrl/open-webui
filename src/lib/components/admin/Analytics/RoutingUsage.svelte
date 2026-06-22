<script lang="ts">
	import Spinner from '$lib/components/common/Spinner.svelte';

	export let pairs: Array<{
		requested_model_id: string;
		selected_model_id: string;
		count: number;
		percentage: number;
	}> = [];

	export let events: Array<{
		message_id: string;
		chat_id: string;
		user_id?: string | null;
		created_at: number;
		requested_model_id: string;
		selected_model_id: string;
	}> = [];

	export let loading = false;
	export let modelMode: 'or' | 'and' | 'selected' | 'requested' = 'or';
	export let selectedPair: { requested_model_id: string; selected_model_id: string } | null = null;
	export let modelFilterLabel: string | null = null;
	export let userFilterLabel: string | null = null;

	export let onModelModeChange: (mode: 'or' | 'and' | 'selected' | 'requested') => void;
	export let onSelectPair: (requestedModelId: string, selectedModelId: string) => void;
	export let onClearPair: () => void;
</script>

<div>
	<div class="flex items-center justify-between text-xs font-medium text-gray-700 dark:text-gray-300 mb-1 px-0.5">
		<span>Routing (Requested → Selected)</span>
		<div class="flex items-center gap-2">
			{#if modelFilterLabel}
				<span class="text-blue-500 font-normal">Filtered model: <span class="font-medium">{modelFilterLabel}</span></span>
			{/if}
			{#if userFilterLabel}
				<span class="text-blue-500 font-normal ml-2">Filtered user: <span class="font-medium">{userFilterLabel}</span></span>
			{/if}
			<label class="text-gray-500 dark:text-gray-400 font-normal" for="routing-mode">Mode</label>
			<select
				id="routing-mode"
				value={modelMode}
				class="rounded-sm px-1.5 py-0.5 text-xs bg-transparent border border-gray-200 dark:border-gray-700"
				on:change={(e) => onModelModeChange((e.currentTarget as HTMLSelectElement).value as 'or' | 'and' | 'selected' | 'requested')}
			>
				<option value="or">or</option>
				<option value="and">and</option>
				<option value="selected">selected</option>
				<option value="requested">requested</option>
			</select>
		</div>
	</div>

	{#if loading}
		<div class="my-6 flex justify-center">
			<Spinner className="size-4" />
		</div>
	{:else}
		<div class="grid md:grid-cols-2 gap-4">
			<div class="scrollbar-hidden relative whitespace-nowrap overflow-x-auto max-w-full">
				<table class="w-full text-sm text-left text-gray-500 dark:text-gray-400 table-auto">
					<thead class="text-xs text-gray-800 uppercase bg-transparent dark:text-gray-200">
						<tr class="border-b-[1.5px] border-gray-50 dark:border-gray-850/30">
							<th class="px-2.5 py-2 w-8">#</th>
							<th class="px-2.5 py-2">Requested</th>
							<th class="px-2.5 py-2">Selected</th>
							<th class="px-2.5 py-2 text-right">Count</th>
							<th class="px-2.5 py-2 text-right">%</th>
						</tr>
					</thead>
					<tbody>
						{#each pairs as pair, idx (`${pair.requested_model_id}-${pair.selected_model_id}`)}
							<tr
								class="bg-white dark:bg-gray-900 dark:border-gray-850 text-xs cursor-pointer hover:bg-gray-50 dark:hover:bg-gray-800 transition-colors"
								class:bg-blue-50={selectedPair?.requested_model_id === pair.requested_model_id && selectedPair?.selected_model_id === pair.selected_model_id}
								class:dark:bg-blue-950={selectedPair?.requested_model_id === pair.requested_model_id && selectedPair?.selected_model_id === pair.selected_model_id}
								on:click={() => onSelectPair(pair.requested_model_id, pair.selected_model_id)}
							>
								<td class="px-3 py-1 text-gray-400">{idx + 1}</td>
								<td class="px-3 py-1 font-medium text-gray-900 dark:text-white">{pair.requested_model_id}</td>
								<td class="px-3 py-1">{pair.selected_model_id}</td>
								<td class="px-3 py-1 text-right">{pair.count.toLocaleString()}</td>
								<td class="px-3 py-1 text-right text-gray-400">{pair.percentage.toFixed(1)}%</td>
							</tr>
						{/each}
						{#if pairs.length === 0}
							<tr><td colspan="5" class="px-3 py-2 text-center text-gray-400">No routing data</td></tr>
						{/if}
					</tbody>
				</table>
			</div>

			<div>
				<div class="flex items-center justify-between text-xs text-gray-600 dark:text-gray-400 mb-1">
					<span>Routing Events</span>
					{#if selectedPair}
						<button class="text-blue-500 hover:text-blue-600" on:click={onClearPair}>Clear pair</button>
					{/if}
				</div>
				<div class="scrollbar-hidden relative whitespace-nowrap overflow-x-auto max-w-full">
					<table class="w-full text-sm text-left text-gray-500 dark:text-gray-400 table-auto">
						<thead class="text-xs text-gray-800 uppercase bg-transparent dark:text-gray-200">
							<tr class="border-b-[1.5px] border-gray-50 dark:border-gray-850/30">
								<th class="px-2.5 py-2">Time</th>
								<th class="px-2.5 py-2">Requested</th>
								<th class="px-2.5 py-2">Selected</th>
							</tr>
						</thead>
						<tbody>
							{#each events as event (event.message_id)}
								<tr class="bg-white dark:bg-gray-900 dark:border-gray-850 text-xs">
									<td class="px-3 py-1 text-gray-400">{new Date(event.created_at * 1000).toLocaleString()}</td>
									<td class="px-3 py-1">{event.requested_model_id}</td>
									<td class="px-3 py-1">{event.selected_model_id}</td>
								</tr>
							{/each}
							{#if events.length === 0}
								<tr><td colspan="3" class="px-3 py-2 text-center text-gray-400">No events</td></tr>
							{/if}
						</tbody>
					</table>
				</div>
			</div>
		</div>
	{/if}
</div>