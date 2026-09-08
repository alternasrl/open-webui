DONE

Files changed:
- `src/lib/components/admin/Analytics/Dashboard.test.ts`

Commits created:
- `3a914c8cd` — `test(analytics): lock model usage table shape`

Test command run:
- `npx vitest --run src/lib/components/admin/Analytics/Dashboard.test.ts`

Test result:
- Pass: 3 tests passed in 1 test file.

---

Fix update:
- `src/lib/components/admin/Analytics/Dashboard.test.ts` now checks header/body parity and duplicate GIADA metric cells in first model row.
- Re-ran: `npx vitest --run src/lib/components/admin/Analytics/Dashboard.test.ts`
- Result: fail as expected on current markup; 2 tests failed, catching 13 body cells vs 10 header cells and duplicated TTFT/Tok/s/Err% cells.

Second fix:
- Removed unstable property-name frequency checks from row test.
- Row test now asserts first model row has exactly 10 `<td>` cells.
- Re-ran: `npx vitest --run src/lib/components/admin/Analytics/Dashboard.test.ts`
- Result: fail as expected on current markup; 2 tests failed, both showing 13 cells instead of 10.
