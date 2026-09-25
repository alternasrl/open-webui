# SonarQube HIGH/CRITICAL Security Remediation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Verify and preserve the absence of HIGH/CRITICAL security findings on PR #7 without changing code for lower-priority findings.

**Architecture:** SonarQube Cloud is the authoritative source. The plan queries the PR-specific Quality Gate, vulnerabilities, MQR security impacts, and security hotspots; it performs no source-code remediation while all HIGH/CRITICAL result sets remain empty. Any future matching finding starts a new, finding-specific TDD remediation task rather than expanding this plan to MEDIUM/LOW issues.

**Tech Stack:** SonarQube Cloud Web API, GitHub Checks API, `curl`, Python 3 JSON assertions, GitHub CLI.

**Spec:** User scope: security issues classified HIGH or CRITICAL only; exclude MEDIUM, LOW, reliability, maintainability, duplication, and coverage findings.

## Global Constraints

- Analyze PR #7 at its authoritative remote head, currently `6ace39382e45c6880d80af54e6ce298a8c82eab3`.
- Sonar project key is `efficiento_open-webui`; pull request key is `7`.
- Remediation scope contains only MQR Security impacts `HIGH`/`BLOCKER`, legacy Vulnerabilities `CRITICAL`/`BLOCKER`, and Security Hotspots with HIGH vulnerability probability.
- Do not modify, suppress, accept, or resolve MEDIUM/LOW security findings.
- Do not modify reliability or maintainability issues.
- Do not claim the complete Quality Gate will become green from this scoped plan: the current gate is also blocked by out-of-scope conditions.
- Re-query Sonar after every PR-head update; never rely on a previous analysis attached to an older SHA.

---

## Verified Baseline — 2026-09-09

### Quality Gate

| New-code condition | Required | Actual | Status | In scope |
|---|---:|---:|---|---|
| Reliability rating | A (`≤ 1`) | D (`4`) | FAIL | No |
| Security rating | A (`≤ 1`) | C (`3`) | FAIL | Only HIGH/CRITICAL findings; none exist |
| Maintainability rating | A (`≤ 1`) | A (`1`) | PASS | No |
| Duplicated lines density | `≤ 3%` | `2.3%` | PASS | No |
| Security hotspots reviewed | `100%` | `100%` | PASS | HIGH hotspots only; none exist |

GitHub check `102468970027` reports `Quality Gate failed` because Reliability is D and Security is C.

### Scoped Security Findings

| Scope | Query | Result |
|---|---|---:|
| PR new code | MQR Security impact `HIGH,BLOCKER` | 0 |
| PR new code | Legacy Vulnerability severity `CRITICAL,BLOCKER` | 0 |
| PR new code | HIGH-probability Security Hotspots | 0 |
| Overall `main` | MQR Security impact `HIGH,BLOCKER` | 0 |
| Overall `main` | HIGH-probability Security Hotspots | 0 |

The PR contains 25 security-impact issues outside scope: 24 LOW and 1 MEDIUM. The MEDIUM finding is `pythonsecurity:S5144` at `backend/open_webui/routers/retrieval.py:2186` (user-controlled URL construction). It contributes to Security rating C but MUST NOT be changed under this plan.

---

### Task 1: Reconfirm the analysis target and Quality Gate

**Files:**
- Validate only: GitHub PR #7 metadata
- Validate only: SonarQube Cloud project `efficiento_open-webui`

**Interfaces:**
- Consumes: GitHub PR head SHA and Sonar project/pull-request identifiers.
- Produces: a verified mapping between the PR head and the Sonar analysis being evaluated.

- [ ] **Step 1: Read the current PR head and Sonar check**

```bash
PR_HEAD=$(gh pr view 7 --repo alternasrl/open-webui --json headRefOid -q .headRefOid)
gh pr checks 7 --repo alternasrl/open-webui
printf 'PR_HEAD=%s\n' "$PR_HEAD"
```

Expected: the SonarCloud check is present. At plan creation, `PR_HEAD=6ace39382e45c6880d80af54e6ce298a8c82eab3`.

- [ ] **Step 2: Fetch and assert the exact gate conditions**

```bash
curl -fsSL \
  'https://sonarcloud.io/api/qualitygates/project_status?projectKey=efficiento_open-webui&pullRequest=7' \
  -o /tmp/sonar-pr7-gate.json
python3 - <<'PY'
import json
from pathlib import Path

status = json.loads(Path('/tmp/sonar-pr7-gate.json').read_text())['projectStatus']
conditions = {row['metricKey']: row for row in status['conditions']}
assert status['status'] == 'ERROR'
assert conditions['new_reliability_rating']['actualValue'] == '4'
assert conditions['new_security_rating']['actualValue'] == '3'
assert conditions['new_maintainability_rating']['status'] == 'OK'
assert conditions['new_duplicated_lines_density']['actualValue'] == '2.3'
assert conditions['new_security_hotspots_reviewed']['actualValue'] == '100.0'
print('Quality Gate conditions confirmed')
PY
```

Expected: the assertion passes. If actual values changed, update the evidence section before making any remediation decision.

- [ ] **Step 3: Remove the temporary response**

```bash
rm -f /tmp/sonar-pr7-gate.json
```

### Task 2: Prove that the HIGH/CRITICAL remediation set is empty

**Files:**
- Validate only: SonarQube Cloud issue and hotspot indexes

**Interfaces:**
- Consumes: current Sonar analysis for PR #7.
- Produces: three independently verified empty finding sets.

- [ ] **Step 1: Assert zero MQR HIGH/BLOCKER security impacts**

```bash
curl -fsSL \
  'https://sonarcloud.io/api/issues/search?componentKeys=efficiento_open-webui&pullRequest=7&issueStatuses=OPEN,CONFIRMED&impactSoftwareQualities=SECURITY&impactSeverities=HIGH,BLOCKER&ps=100' \
  -o /tmp/sonar-pr7-high-security.json
python3 - <<'PY'
import json
from pathlib import Path

data = json.loads(Path('/tmp/sonar-pr7-high-security.json').read_text())
assert data['total'] == 0, [
    (issue['key'], issue['rule'], issue['component'], issue.get('line'))
    for issue in data['issues']
]
print('MQR HIGH/BLOCKER security impacts: 0')
PY
```

- [ ] **Step 2: Assert zero legacy CRITICAL/BLOCKER vulnerabilities**

```bash
curl -fsSL \
  'https://sonarcloud.io/api/issues/search?componentKeys=efficiento_open-webui&pullRequest=7&issueStatuses=OPEN,CONFIRMED&types=VULNERABILITY&severities=CRITICAL,BLOCKER&ps=100' \
  -o /tmp/sonar-pr7-critical-vulnerabilities.json
python3 - <<'PY'
import json
from pathlib import Path

data = json.loads(Path('/tmp/sonar-pr7-critical-vulnerabilities.json').read_text())
assert data['total'] == 0, [
    (issue['key'], issue['rule'], issue['component'], issue.get('line'))
    for issue in data['issues']
]
print('Legacy CRITICAL/BLOCKER vulnerabilities: 0')
PY
```

- [ ] **Step 3: Assert zero HIGH-probability hotspots**

```bash
curl -fsSL \
  'https://sonarcloud.io/api/hotspots/search?projectKey=efficiento_open-webui&pullRequest=7&status=TO_REVIEW&ps=500' \
  -o /tmp/sonar-pr7-hotspots.json
python3 - <<'PY'
import json
from pathlib import Path

data = json.loads(Path('/tmp/sonar-pr7-hotspots.json').read_text())
high = [
    (item['key'], item['component'], item.get('line'), item['message'])
    for item in data.get('hotspots', [])
    if item.get('vulnerabilityProbability') == 'HIGH'
]
assert not high, high
print('HIGH-probability security hotspots: 0')
PY
```

- [ ] **Step 4: Remove temporary responses**

```bash
rm -f \
  /tmp/sonar-pr7-high-security.json \
  /tmp/sonar-pr7-critical-vulnerabilities.json \
  /tmp/sonar-pr7-hotspots.json
```

Expected: all three assertions pass. Therefore no code, tests, suppressions, or Sonar issue-status changes are permitted by the requested scope.

### Task 3: Revalidate after the next PR-head update

**Files:**
- Validate only: PR #7 and SonarQube Cloud analysis

**Interfaces:**
- Consumes: a new PR-head SHA and its completed Sonar analysis.
- Produces: either a clean scoped result or a concrete follow-up plan per matching finding.

- [ ] **Step 1: Wait for Sonar to finish on the new head**

```bash
gh pr checks 7 --repo alternasrl/open-webui --watch --interval 15
```

Expected: `SonarCloud Code Analysis` reaches a completed state. The overall check may remain failed because out-of-scope MEDIUM security and reliability issues are not addressed here.

- [ ] **Step 2: Repeat all Task 2 assertions**

Run the commands from Task 2 unchanged.

Expected: all HIGH/CRITICAL result sets remain empty.

- [ ] **Step 3: Stop without source changes when results remain empty**

```bash
git status --short
```

Expected: no source-code changes created by this plan.

If a Task 2 assertion fails in a future analysis, stop this plan and create a new finding-specific plan containing, for each returned issue: exact Sonar rule key, file and line, source-to-sink trace, failing security regression test, minimal implementation, focused test command, full security suite command, and post-push Sonar revalidation. Do not batch unrelated rules into one implementation task.

---

## Completion Criteria

- The Quality Gate conditions are captured from the PR-specific Sonar API.
- All three HIGH/CRITICAL security result sets are independently confirmed empty.
- No MEDIUM/LOW, reliability, maintainability, duplication, or coverage issue is modified.
- No source-code remediation is performed while the scoped result set is empty.
- The plan explicitly records that it cannot make the current overall Quality Gate green within the requested scope.
