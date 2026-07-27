<script lang="ts">
	import { onDestroy } from 'svelte';
	import Spinner from '$lib/components/common/Spinner.svelte';
	import ClusterBarChart from './ClusterBarChart.svelte';
	import ClusterTrendLine from './ClusterTrendLine.svelte';
	import EmergingTopics from './EmergingTopics.svelte';
	import GapAnalysis from './GapAnalysis.svelte';

	export let summary: {
		latest_run: {
			id: string;
			status: string;
			total_prompts: number | null;
			clusters_found: number | null;
			created_at: number;
			completed_at: number | null;
		} | null;
		active_run: { id: string; status: string } | null;
		total_runs: number;
	} | null = null;

	export let clusters: Array<{
		id: string;
		canonical_label: string;
		cluster_size: number;
		run_id: string;
		created_at: number;
	}> = [];

	export let emerging: Array<{
		canonical_label: string;
		recent_count: number;
		total_count: number;
		growth_ratio: number;
	}> = [];

	export let trend: Array<{ bucket: string; count: number }> = [];

	export let loading = false;
	export let error: string | null = null;

	export let onRefresh: () => void = () => {};
	export let onLoadData: () => void = () => {};
	export let onSelectCluster: (id: string, label: string) => void = () => {};

	let selectedClusterId: string | null = null;
	let selectedClusterLabel = '';

	function selectCluster(id: string, label: string) {
		if (selectedClusterId === id) {
			selectedClusterId = null;
			selectedClusterLabel = '';
		} else {
			selectedClusterId = id;
			selectedClusterLabel = label;
			onSelectCluster(id, label);
		}
	}

	$: hasRun = summary?.latest_run != null;
	$: isRunning = summary?.active_run != null;
	$: lastRun = summary?.latest_run;

	let pollInterval: ReturnType<typeof setInterval> | null = null;

	$: {
		if (isRunning) {
			if (!pollInterval) {
				pollInterval = setInterval(onLoadData, 5000);
			}
		} else {
			if (pollInterval) {
				clearInterval(pollInterval);
				pollInterval = null;
			}
		}
	}

	onDestroy(() => {
		if (pollInterval) clearInterval(pollInterval);
	});
</script>

<div class="space-y-4">
	<!-- Header -->
	<div class="flex items-center justify-between">
		<span class="text-xs font-medium text-gray-700 dark:text-gray-300">
			Prompt Insights
			{#if lastRun}
				<span class="ml-2 font-normal text-gray-400">
					— ultima analisi {new Date(lastRun.created_at * 1000).toLocaleString('it-IT')}
					{#if lastRun.clusters_found != null}
						· {lastRun.clusters_found} cluster
					{/if}
					{#if lastRun.total_prompts != null}
						· {lastRun.total_prompts} prompt
					{/if}
				</span>
			{/if}
		</span>
		<button
			class="text-xs px-2.5 py-1 rounded bg-blue-600 hover:bg-blue-700 text-white transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
			disabled={loading || isRunning}
			on:click={onRefresh}
		>
			{#if isRunning}
				<span class="flex items-center gap-1"><Spinner className="size-3" /> In corso…</span>
			{:else}
				Avvia analisi
			{/if}
		</button>
	</div>

	<!-- Loading -->
	{#if loading}
		<div class="flex justify-center py-8">
			<Spinner className="size-5" />
		</div>

	<!-- Error -->
	{:else if error}
		<div class="text-xs text-red-500 dark:text-red-400 py-2">
			Errore: {error}
			<button class="ml-2 underline" on:click={onRefresh}>Riprova</button>
		</div>

	<!-- Empty state -->
	{:else if !hasRun}
		<div class="flex flex-col items-center justify-center py-10 gap-3 text-center">
			<p class="text-sm text-gray-500 dark:text-gray-400">
				Nessuna analisi disponibile. Avvia la prima analisi.
			</p>
			<button
				class="text-xs px-3 py-1.5 rounded bg-blue-600 hover:bg-blue-700 text-white transition-colors"
				on:click={onRefresh}
			>
				Avvia analisi
			</button>
		</div>

	<!-- Data -->
	{:else}
		<div class="grid md:grid-cols-2 gap-6">
			<!-- Clusters bar chart -->
			<div>
				<p class="text-xs font-medium text-gray-600 dark:text-gray-400 mb-2">
					Cluster per volume
				</p>
				<div class="space-y-1">
					{#each [...clusters].sort((a, b) => b.cluster_size - a.cluster_size) as c (c.id)}
						<button
							class="w-full text-left rounded transition-colors {selectedClusterId === c.id
								? 'ring-1 ring-blue-400'
								: ''}"
							on:click={() => selectCluster(c.id, c.canonical_label)}
						>
							<ClusterBarChart clusters={[c]} />
						</button>
					{/each}
					{#if clusters.length === 0}
						<p class="text-xs text-gray-400 text-center py-2">Nessun cluster disponibile</p>
					{/if}
				</div>
			</div>

			<!-- Trend -->
			<div>
				<p class="text-xs font-medium text-gray-600 dark:text-gray-400 mb-2">
					{selectedClusterLabel ? `Trend: ${selectedClusterLabel}` : 'Trend (seleziona un cluster)'}
				</p>
				{#if selectedClusterId && trend.length > 0}
					<ClusterTrendLine {trend} label={selectedClusterLabel} />
				{:else}
					<p class="text-xs text-gray-400 text-center py-8">
						{selectedClusterId ? 'Nessun dato di trend disponibile' : 'Seleziona un cluster per visualizzare il trend'}
					</p>
				{/if}
			</div>
		</div>

		<!-- Emerging topics -->
		<div>
			<p class="text-xs font-medium text-gray-600 dark:text-gray-400 mb-2">Argomenti emergenti</p>
			<EmergingTopics topics={emerging} />
		</div>

		<!-- Gap analysis -->
		<div>
			<p class="text-xs font-medium text-gray-600 dark:text-gray-400 mb-2">Analisi lacune</p>
			<GapAnalysis gaps={[]} />
		</div>
	{/if}
</div>
