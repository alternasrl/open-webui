# Patches — integration-v0.10.1

**Base upstream tag:** `v0.10.1` (SHA `b711935dd57dbc223ebbf410175a8bbe7e4efafb`)  
**Regenerated:** 2026-06-30

## Patch series

| #         | File                                                                    | Description                                                            |
| --------- | ----------------------------------------------------------------------- | ---------------------------------------------------------------------- |
| 0001–0002 | `feat-analytics-add-TTFT…`                                              | Analytics: TTFT, Token/s, error metrics (two-part)                     |
| 0003      | `fix-analytics-restore-userId…`                                         | Analytics: restore cross-filter params                                 |
| 0004      | `fix-await-save-handlers…`                                              | Fix async save handlers in connection modal                            |
| 0005–0007 | `feat-*NIS2*`                                                           | NIS2 compliance: custom access log, audit utilities, oauth/OIDC claims |
| 0008–0009 | `feat-add-routing-analytics…`, `fix-analytics-add-merge_routing_usage…` | Routing analytics endpoints + RoutingUsage component                   |
| 0010      | `chore-bump-version…`                                                   | Version bump to `0.10.1-260630`                                        |

> **Note:** Commit `30405a635` (`feat(nis2): add NIS2 rules for 6 new v0.9.6 endpoints`) is an empty
> commit (no file changes) and is intentionally absent from the patch series.

## Applying

```bash
git checkout v0.10.1
git am patches/*.patch
```
