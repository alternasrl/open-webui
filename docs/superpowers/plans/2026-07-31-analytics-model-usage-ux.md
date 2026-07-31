# Analytics Model Usage UX Alignment Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Restore a single coherent Model Usage table in GIADA analytics on v0.11.x, keep GIADA per-model metrics visible, and remove the duplicate table fragments left by the upstream merge.

**Architecture:** Keep backend analytics untouched. Fix the frontend in one place, `src/lib/components/admin/Analytics/Dashboard.svelte`, so the admin analytics modal renders one Model Usage table with one header/body schema and preserves existing cross-filter, sort, and model-modal behavior. Lock the table shape with one small Vitest source test that reads the Svelte file directly, matching the repo’s existing lightweight frontend test style.

**Tech Stack:** Svelte 5, TypeScript, Vitest, existing analytics API client, `npm run check`, `npm run test:frontend`.

## Global Constraints

- No backend/API changes
- No routing analytics changes
- No prompt insights changes
- No new charts or summary cards
- Safe to ship as a frontend-only merge cleanup. No migration or feature flag required.

---

## File structure map

- Modify: `src/lib/components/admin/Analytics/Dashboard.svelte`
  - Responsibility: render one Model Usage table and one User Activity table, with one set of headers and one matching row layout.
- Create: `src/lib/components/admin/Analytics/Dashboard.test.ts`
  - Responsibility: assert the Model Usage block in `Dashboard.svelte` has exactly one table header/body pair and one copy of each GIADA metric column.

---

### Task 1: Lock the current broken table shape with a failing source test

**Files:**

- Create: `src/lib/components/admin/Analytics/Dashboard.test.ts`
- Test: `src/lib/components/admin/Analytics/Dashboard.test.ts`

**Interfaces:**

- Consumes: `Dashboard.svelte` as plain text via `node:fs`.
- Produces: a test that fails while the Model Usage block still contains duplicate headers/body cells.

- [ ] **Step 1: Write the failing test**

```ts
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

const __filename = fileURLToPath(import.meta.url);
const __dir = dirname(__filename);

function getModelUsageBlock() {
	const source = readFileSync(resolve(__dir, './Dashboard.svelte'), 'utf-8');
	return source.split('<!-- Model Usage Table -->')[1].split('<!-- User Activity Table -->')[0];
}

describe('Analytics dashboard Model Usage layout', () => {
	it('keeps one Model Usage table block with one header and one body', () => {
		const block = getModelUsageBlock();

		expect((block.match(/<thead/g) ?? []).length).toBe(1);
		expect((block.match(/<tbody/g) ?? []).length).toBe(1);
	});

	it('keeps one copy of each GIADA metric column in the Model Usage header', () => {
		const block = getModelUsageBlock();

		expect((block.match(/toggleModelSort\('ttft'\)/g) ?? []).length).toBe(1);
		expect((block.match(/toggleModelSort\('tps'\)/g) ?? []).length).toBe(1);
		expect((block.match(/toggleModelSort\('error_rate'\)/g) ?? []).length).toBe(1);
		expect((block.match(/\$i18n\.t\('TTFT'\)/g) ?? []).length).toBe(1);
		expect((block.match(/\$i18n\.t\('Tok\/s'\)/g) ?? []).length).toBe(1);
		expect((block.match(/\$i18n\.t\('Err%'\)/g) ?? []).length).toBe(1);
	});

	it('keeps the existing drill-down affordance on model rows', () => {
		const block = getModelUsageBlock();

		expect(block).toContain("selectedModel = { id: model.model_id, name: model.name ?? model.model_id }");
		expect(block).toContain('reloadUserTable();');
	});
});
```

- [ ] **Step 2: Run test to verify it fails**

Run:

```bash
npm run test:frontend -- src/lib/components/admin/Analytics/Dashboard.test.ts
```

Expected: fail because the current `Dashboard.svelte` Model Usage block contains duplicated `thead`/`tbody` fragments.

- [ ] **Step 3: Commit the failing test**

```bash
git add src/lib/components/admin/Analytics/Dashboard.test.ts
git commit -m "test(analytics): lock model usage table shape"
```

---

### Task 2: Remove duplicated Model Usage fragments and keep v0.11 ordering

**Files:**

- Modify: `src/lib/components/admin/Analytics/Dashboard.svelte`

**Interfaces:**

- Consumes: `modelStats`, `sortedModels`, `tokenStats`, `filterByModelId`, `filterByUserId`, `selectedModel`, `showModelModal`.
- Produces: one Model Usage table in this order: `Model`, `Messages`, `Users`, `Chats`, `Tokens`, `TTFT`, `Tok/s`, `Err%`, `%`.

- [ ] **Step 1: Re-run the failing test to confirm the broken shape is still red before editing**

Run:

```bash
npm run test:frontend -- src/lib/components/admin/Analytics/Dashboard.test.ts
```

Expected: fail while the duplicate blocks are still present.

- [ ] **Step 2: Edit the dashboard to keep one header/body pair only**

```svelte
<thead>
	<tr>
		<th>#</th>
		<th>Model</th>
		<th>Messages</th>
		<th>Users</th>
		<th>Chats</th>
		<th>Tokens</th>
		<th>TTFT</th>
		<th>Tok/s</th>
		<th>Err%</th>
		<th>%</th>
	</tr>
</thead>
<tbody>
	{#each sortedModels as model, idx (model.model_id)}
		<tr
			on:click={() => {
				const next = toggleSelection(filterByModelId, model.model_id);
				filterByModelId = next;
				filterByModelName = next ? (model.name ?? model.model_id) : null;
				reloadUserTable();
			}}
		>
			<td>{idx + 1}</td>
			<td>{model.name}</td>
			<td>{model.count}</td>
			<td>{model.unique_users ?? 0}</td>
			<td>{model.unique_chats ?? 0}</td>
			<td>{formatNumber(tokenStats[model.model_id]?.total_tokens ?? 0)}</td>
			<td>{model.avg_ttft_ms != null ? model.avg_ttft_ms.toFixed(0) + ' ms' : '—'}</td>
			<td>{model.avg_tokens_per_second != null ? model.avg_tokens_per_second.toFixed(1) : '—'}</td>
			<td>{model.error_rate != null ? (model.error_rate * 100).toFixed(1) + '%' : '—'}</td>
			<td>{totalModelMessages > 0 ? ((model.count / totalModelMessages) * 100).toFixed(1) : 0}%</td>
		</tr>
	{/each}
</tbody>
```

- [ ] **Step 3: Re-run the focused check**

Run:

```bash
npm run test:frontend -- src/lib/components/admin/Analytics/Dashboard.test.ts
```

Expected: pass after the duplicate fragments are removed.

- [ ] **Step 4: Run repository frontend validation**

Run:

```bash
npm run check
```

Expected: no Svelte/type errors in `Dashboard.svelte`.

- [ ] **Step 5: Commit the fix**

```bash
git add src/lib/components/admin/Analytics/Dashboard.svelte
git commit -m "fix(analytics): restore single model usage table"
```

---

### Task 3: Final validation and handoff

**Files:**

- No new files expected

**Interfaces:**

- Consumes: the cleaned dashboard and the source test.
- Produces: a stable v0.11 analytics UX with GIADA metrics preserved and no duplicate table markup.

- [ ] **Step 1: Run the focused frontend test**

Run:

```bash
npm run test:frontend -- src/lib/components/admin/Analytics/Dashboard.test.ts
```

Expected: pass.

- [ ] **Step 2: Run full frontend check**

Run:

```bash
npm run check
```

Expected: pass.

- [ ] **Step 3: Smoke the admin analytics modal in the app**

Open the admin analytics tab and confirm:

- Model Usage renders once
- User Activity renders once
- TTFT, Tok/s, Err% and % appear once
- clicking a model row still filters User Activity
- arrow button still opens model modal

- [ ] **Step 4: Commit the final state**

```bash
git add src/lib/components/admin/Analytics/Dashboard.svelte src/lib/components/admin/Analytics/Dashboard.test.ts
git commit -m "fix(analytics): align model usage ux with v0.11"
```
