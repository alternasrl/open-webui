# Custom Patches — open-webui (alternasrl)

Questo directory contiene le patch custom applicate sopra la release upstream di open-webui.  
Sono numerate progressivamente e vanno applicate in ordine con:

```bash
git am patches/*.patch
```

> **Nota v0.9.2**: rimossi tutti i workaround Azure WAF (ex 0003-0008/0010-0012 nella serie v0.9.1) — totale sceso da 24 a **16 patch**.  
> **Nota v0.9.5**: aggiunte regole NIS2 per nuovi endpoint — totale **19 patch**.  
> **Nota v0.9.6 (2026-06-04)**: aggiornamento a upstream v0.9.6 (`1a97751e3`). Patch 0004 (path validation) **rimossa** — fix equivalente incluso in v0.9.6 upstream (commit `b0fa4384e`). Patch precedenti 0005-0019 consolidate in 0004-0007. Aggiunta patch 0007 con 6 nuove regole NIS2 per endpoint v0.9.6. Totale: **8 patch** (incluso bump versione).

---

## Gruppi funzionali

### 📊 Analytics

Nuove metriche e filtri nella dashboard admin Analytics (riscritte per SQLAlchemy 2.0 async).

| # | File | Descrizione |
|---|------|-------------|
| 0001 | `feat-analytics-add-TTFT-Token-s-and-error-metrics-as...` | Nuove metriche aggregate async: **TTFT** (Time To First Token), **Token/s** (throughput), **Error rate**. Aggiunge `get_performance_metrics_by_model` e `get_performance_metrics` al modello `ChatMessage` (SQLAlchemy 2.0 AsyncSession). Espone i campi `avg_ttft_ms`, `avg_tokens_per_second`, `error_requests`, `total_requests`, `error_rate` via `analytics.py`. |
| 0002 | `feat-analytics-add-TTFT-error-UI-1h-filter-cross-fil...` | Frontend: colonne TTFT/Token/s/Error nella tabella Model Usage, filtro periodo "1h", cross-filter interattivo per modello/utente. Parametri `userId` e `modelId` aggiunti alle API call frontend. |

---

### 🔧 Fix Frontend

| # | File | Descrizione |
|---|------|-------------|
| 0003 | `fix-await-save-handlers-before-dispatching-save-even...` | Fix async nel frontend: `await` sui save handler (`updateOpenAIHandler`, `updateOllamaHandler`) prima di fare dispatch dell'evento `save`. Handlers ritornano `true/false` per consentire la propagazione condizionale. Propagato lungo la catena dei connection modals (`OllamaConnection.svelte`, `OpenAIConnection.svelte`). |

---

### 🔒 Sicurezza — Path Validation

> **Patch 0004 path-validation rimossa in v0.9.6.** La correzione path traversal per `main.py` è inclusa upstream (commit `b0fa4384e`). La sanitizzazione estensione in `audio.py` potrà essere reintrodotta come patch separata se necessario.

---

### 📋 NIS2 — Access Logging Middleware

Implementa un middleware di access log conforme alla direttiva NIS2 per la registrazione degli accessi alle API (~165+ regole regex, compatibile con v0.9.6).

| # | File | Descrizione |
|---|------|-------------|
| 0004 | `feat-custom-access-log-NIS2-compliant...` | Introduce `access_log.py` (middleware NIS2), `.github/copilot-instructions.md` (caveman mode + dev guidelines), `main.py` (registrazione middleware). |
| 0005 | `feat-Enhance-NIS2-compliance-in-access-logging-and-a...` | Aggiunge campi NIS2 estesi all'`AuditLogEntry`: `correlation_id` (da header X-Request-ID / X-Azure-Ref) e `oidc_claims` (dal JWT). Aggiunge `OIDCClaims` dataclass, `docker-compose.yaml` env vars NIS2. |
| 0006 | `feat-apply-patches-0007-NIS2-access_log-full-impl-oa...` | Implementazione completa NIS2: cache thread-safe user context (TTL 300s, maxsize 2048), 165+ action rules con regex, `_NIS2_SECURITY_ACTIONS` frozenset, OIDC claims extraction (response Set-Cookie + request.state fallback), `log_scheduled_activity()`, `execute_automation()` trigger-aware, 128 test pytest. Include anche patch oauth.py: `invalidate_user_cache` (0008), `oidc_raw_id_token` per login falliti (0013). |
| 0007 | `feat-nis2-add-NIS2-rules-for-6-new-v0.9.6-endpoints-...` | Nuove regole NIS2 per i 6 endpoint introdotti in v0.9.6: `FILE_RENAME`, `KNOWLEDGE_FILES_PENDING`, `KNOWLEDGE_SYNC_DIFF`, `KNOWLEDGE_SYNC_CLEANUP`, `USER_ACCESS_PREVIEW`, `GROUP_ACCESS_PREVIEW`. I tipi di azione sync e preview aggiunti a `_NIS2_SECURITY_ACTIONS`. |

---

## Base upstream

Le patch sono generate a partire dal tag upstream open-webui **v0.9.6** (commit `1a97751e3`).  
Ultima rigenerazione: **8 patch** (HEAD `1213ec137`, 4 giugno 2026).

```bash
# Applica tutte le patch su un branch da v0.9.6
git checkout -b my-branch v0.9.6
git am patches/*.patch

# Per la prossima integrazione upstream
git checkout -b integration-vX.Y.Z vX.Y.Z
git am patches/*.patch
# risolvi conflitti, poi rigenera:
git format-patch vX.Y.Z..HEAD --no-signature --output-directory patches/ -- ':!patches/'
```

### CVE risolte in v0.9.6 (automaticamente con il merge)

| CVE | Descrizione | Fix |
|-----|-------------|-----|
| CVE-2026-48710 | BadHost — Host header injection in `auth.py` | `request.scope["path"]` invece di `request.url.path` (commit `66126f386`) |
| — | Path traversal sibling-prefix in `serve_cache_file` | `os.path.abspath` + `os.sep` boundary check (commit `b0fa4384e`) |
| — | SSRF multiple (redirect, webhook, URL parser, OAuth profile picture, Playwright) | Fix applicativi in v0.9.6 |
| — | XSS (Mermaid, SVG upload, model profile image, iframe CSP) | Fix applicativi in v0.9.6 |
| — | IDOR (prompt history, cross-user file, RAG collection access) | Fix applicativi in v0.9.6 |

### Patch rimosse rispetto alla serie v0.9.1

| Ex # (v0.9.1) | Motivo rimozione |
|----------------|-----------------|
| 0003 `fix-enhance-error-handling` | Workaround Azure WAF — error handling HTML 502/503 |
| 0004 `fix-handle-non-JSON-error` | Workaround Azure WAF — non-JSON error parse |
| 0005 `fix-azure-verify-fallback` | Workaround Azure WAF — fallback `model_ids` |
| 0007 `fix-mask-API-keys` | Workaround Azure WAF — mask keys in GET responses |
| 0008 `fix-wrap-JSON-config-Base64` | Workaround Azure WAF — Base64 retrieval config |
| 0010 `fix-route-OpenAI-config` | Workaround Azure WAF — alias endpoint `/api/v1/configs/openai` |
| 0011 `fix-mask-OpenAI-API-keys-configs` | Workaround Azure WAF — mask keys alias endpoint |
| 0012 `fix-Base64-encode-OpenAI-config` | Workaround Azure WAF — Base64 payload OpenAI config |
| 0004 `fix-enhance-path-validation` (v0.9.5) | Path traversal fix incluso in upstream v0.9.6 (commit `b0fa4384e`) |


---

## Gruppi funzionali

### 📊 Analytics

Nuove metriche e filtri nella dashboard admin Analytics (riscritte per SQLAlchemy 2.0 async).

| # | File | Descrizione |
|---|------|-------------|
| 0001 | `feat-analytics-add-TTFT-Token-s-and-error-metrics-as...` | Nuove metriche aggregate async: **TTFT** (Time To First Token), **Token/s** (throughput), **Error rate**. Aggiunge `get_performance_metrics_by_model` e `get_performance_metrics` al modello `ChatMessage` (SQLAlchemy 2.0 AsyncSession). Espone i campi `avg_ttft_ms`, `avg_tokens_per_second`, `error_requests`, `total_requests`, `error_rate` via `analytics.py`. |
| 0002 | `feat-analytics-add-TTFT-error-UI-1h-filter-cross-fil...` | Frontend: colonne TTFT/Token/s/Error nella tabella Model Usage, filtro periodo "1h", cross-filter interattivo per modello/utente. Parametri `userId` e `modelId` aggiunti alle API call frontend. |

---

### 🔧 Fix Frontend

| # | File | Descrizione |
|---|------|-------------|
| 0003 | `fix-await-save-handlers-before-dispatching-save-even...` | Fix async nel frontend: `await` sui save handler (`updateOpenAIHandler`, `updateOllamaHandler`) prima di fare dispatch dell'evento `save`. Handlers ritornano `true/false` per consentire la propagazione condizionale. Propagato lungo la catena dei connection modals (`OllamaConnection.svelte`, `OpenAIConnection.svelte`). |

---

### 🔒 Sicurezza — Path Validation

| # | File | Descrizione |
|---|------|-------------|
| 0004 | `fix-enhance-path-validation-and-sanitization-for-fil...` | Rafforzamento della validazione e sanitizzazione dei path nei file handler del backend (`main.py`, `audio.py`). Previene path traversal e accessi a file fuori dalle directory consentite usando `Path.resolve()`. |

---

### 📋 NIS2 — Access Logging Middleware

Implementa un middleware di access log conforme alla direttiva NIS2 per la registrazione degli accessi alle API (~165 regole regex, compatibile con v0.9.x).

| # | File | Descrizione |
|---|------|-------------|
| 0005 | `feat-custom-access-log-NIS2-compliant...` | Introduce `access_log.py`: middleware FastAPI che intercetta ogni richiesta HTTP e scrive un log strutturato con utente, IP, metodo, path, status code e durata. |
| 0006 | `feat-Enhance-NIS2-compliance-in-access-logging-and-a...` | Aggiunge campi NIS2 estesi all'`AuditLogEntry`: `correlation_id` (da header X-Request-ID / X-Azure-Ref) e `oidc_claims` (dal JWT). La source IP ora traversa i proxy Azure WAF. |
| 0007 | `feat-Implement-thread-safe-caching-for-user-context-...` | Cache thread-safe per la risoluzione del contesto utente nel middleware di access log (evita query ripetute al DB per ogni richiesta). |
| 0008 | `feat-Invalidate-access-log-cache-on-OAuth-session-up...` | Invalida la cache del middleware quando la sessione OAuth viene aggiornata (`oauth.py`), garantendo che il log usi sempre i dati utente correnti. |
| 0009 | `feat-Enhance-NIS2-compliance-in-access-logging-middl...` | Classificazione dettagliata delle azioni (CREATE, READ, UPDATE, DELETE, LOGIN, …) tramite regex sul path, per la reportistica NIS2 / LOG360. |
| 0010 | `Enhance-access-log-middleware-with-additional-regex-...` | Estende il set di regex per coprire ulteriori endpoint (audio, retrieval, tools, functions, ecc.) e aggiunge nuovi tipi di azione. |
| 0011 | `feat-audit-OIDC-OAuth2-callback-track-AUTH_OIDC_LOGI...` | Aggiunge regole per gli endpoint OIDC/OAuth2 callback (`/oauth/{provider}/callback`, `/oauth/clients/{id}/callback`), mappandoli al tipo `AUTH_OIDC_LOGIN`. HTTP 4xx produce `AUTH_OIDC_LOGIN_FAIL  nis2=Y` per il rilevamento brute-force in Log360. |
| 0012 | `feat-extract-OIDC-claims-from-response-Set-Cookie-in...` | Nel callback OIDC il cookie `oauth_id_token` è nella *response*. Il middleware lo cerca nei `Set-Cookie` headers dopo `call_next()` e decodifica `oidc_sub` / `mfa` in-place per la riga `AUTH_OIDC_LOGIN`. |
| 0013 | `feat-log-OIDC-claims-on-both-success-and-failed-logi...` | `oauth.py` salva l'`id_token` grezzo in `request.state.oidc_raw_id_token` per i login falliti (dominio non consentito, ruolo mancante). Il middleware lo usa come fallback: `oidc_sub` e `mfa` sono popolati sia per login riusciti (307) che falliti (4xx). |
| 0014 | `feat-log-full-OIDC-token-claims-in-AUTH_OIDC_LOGIN-a...` | Aggiunge il campo `claims=<json>` alla riga `AUTH_OIDC_LOGIN`. Nuovo helper `_decode_full_id_token()` decodifica il JWT senza verifica firma e rimuove claim opachi (`at_hash`, `nonce`, `jti`). |
| 0015 | `feat-nis2-add-NIS2-rules-for-v0.9.x-new-endpoints-au...` | Aggiunge ~20 nuove regole per le superfici introdotte in v0.9.0: Automations (CREATE/UPDATE/RUN/TOGGLE/DELETE), Calendar (CRUD eventi, RSVP), OAuth MCP (`AUTH_OAUTH_AUTHORIZE`, `AUTH_LOGOUT` backchannel), Terminal policy (`CONFIG_TERMINAL_SERVERS_VERIFY`, `CONFIG_TERMINAL_SERVERS_POLICY`). |
| 0016 | `docs-nis2-update-access_log.py-module-docstring-for-...` | Aggiorna il docstring di `access_log.py`: ~150 regole totali, sezione Compatibility per v0.9.x, categorie CALENDAR_* e nuovi subtype AUTH_*/CONFIG_*. |
| 0017 | `feat-nis2-update-access-log-for-v0.9.5-fix-signout-P...` | Integrazione v0.9.5: corregge `signout` GET→POST (breaking change v0.9.3); aggiunge `AUTH_LOGOUT` per OAuth session revoke (`DELETE /auths/oauth/sessions/{p}`); aggiunge 13 nuove regole per skills CRUD (`RESOURCE_CREATE/UPDATE/TOGGLE/DELETE_SKILL`, `ACCESS_SKILL_UPDATE`), chat (`CHAT_PIN`, `CHAT_MOVE_FOLDER`, `ACCESS_SHARE_CHAT_UPDATE`), note (`NOTE_PIN`), knowledge (`KNOWLEDGE_FILE_UPDATE`, `KNOWLEDGE_REINDEX`), config retrieval/audio/images (`CONFIG_RETRIEVAL_EMBEDDING`, `CONFIG_RETRIEVAL`, `DATA_RESET_RETRIEVAL_DB/UPLOADS`, `CONFIG_AUDIO`, `CONFIG_IMAGES`). Aggiunge 10 nuovi action type a `_NIS2_SECURITY_ACTIONS` e il pattern `/skills/id/{id}` a `_OBJECT_ID_PATTERNS`. |
| 0018 | `feat-nis2-add-task-calendar-scheduled-automation-log...` | Estende il logging NIS2 su tre fronti: **(1)** 9 nuove regole per task AI (`CONFIG_TASKS`, `TASK_TITLE_GENERATE`, `TASK_FOLLOWUP_GENERATE`, `TASK_TAGS_GENERATE`, `TASK_IMAGE_PROMPT_GENERATE`, `TASK_QUERY_GENERATE`, `TASK_AUTOCOMPLETE_GENERATE`, `TASK_EMOJI_GENERATE`, `TASK_MOA_GENERATE`) + `RESOURCE_VIEW_AUTOMATION_RUNS`; **(2)** aggiunge `CONFIG_TASKS`, `CALENDAR_DELETE`, `TASK_AUTOMATION_SCHEDULED`, `TASK_AUTOMATION_SCHEDULED_ERROR` a `_NIS2_SECURITY_ACTIONS`; **(3)** introduce `log_scheduled_activity()` — funzione che emette righe di log NIS2-compliant per le automazioni eseguite dallo scheduler (nessun HTTP triggerer); **(4)** `execute_automation()` riceve `trigger: str = "scheduler"` — le chiamate manuali passano `trigger="manual"` (già coperte dal middleware HTTP) mentre quelle schedulate emettono `TASK_AUTOMATION_SCHEDULED` / `TASK_AUTOMATION_SCHEDULED_ERROR`. |
| 0019 | `test-nis2-add-128-tests-for-NIS2-access-log-middlewa...` | Aggiunge 128 test pytest in `backend/open_webui/test/middleware/test_access_log.py` coprendo: classificazione azioni per tutte le categorie (auth, user, group, config, tasks, automations, calendar, skills, SCIM, pipelines, channels), membership `_NIS2_SECURITY_ACTIONS`, `_extract_object_ref`, `_outcome_from_status`, `log_scheduled_activity` (formato, campi, livello WARNING, meta, durata), `invalidate_user_cache`. **Bugfix contestuale**: i test hanno rilevato un ordinamento errato in `_compile_object_id_patterns()` — i pattern SCIM `/scim/v2/Users/{id}` e `/calendars/events/{id}` venivano intercettati dai pattern generici `/users/{id}$` e `/calendars/{id}` prima di raggiungere quelli specifici. Fix: pattern più specifici spostati in cima alla lista. |

---

## Base upstream

Le patch sono generate a partire dal tag upstream open-webui **v0.9.5** (commit `3660bc00f`).  
Ultima rigenerazione: **19 patch** (HEAD `06cfcea54`, 12 maggio 2026).

```bash
# Applica tutte le patch su un branch da v0.9.5
git checkout -b my-branch v0.9.5
git am patches/*.patch

# Per la prossima integrazione upstream
git checkout -b integration-vX.Y.Z vX.Y.Z
git am patches/*.patch
# risolvi conflitti, poi rigenera:
git format-patch v0.9.5..HEAD --no-signature --output-directory patches/ -- ':!patches/'
```

### Patch rimosse rispetto alla serie v0.9.1

| Ex # (v0.9.1) | Motivo rimozione |
|----------------|-----------------|
| 0003 `fix-enhance-error-handling` | Workaround Azure WAF — error handling HTML 502/503 |
| 0004 `fix-handle-non-JSON-error` | Workaround Azure WAF — non-JSON error parse |
| 0005 `fix-azure-verify-fallback` | Workaround Azure WAF — fallback `model_ids` |
| 0007 `fix-mask-API-keys` | Workaround Azure WAF — mask keys in GET responses |
| 0008 `fix-wrap-JSON-config-Base64` | Workaround Azure WAF — Base64 retrieval config |
| 0010 `fix-route-OpenAI-config` | Workaround Azure WAF — alias endpoint `/api/v1/configs/openai` |
| 0011 `fix-mask-OpenAI-API-keys-configs` | Workaround Azure WAF — mask keys alias endpoint |
| 0012 `fix-Base64-encode-OpenAI-config` | Workaround Azure WAF — Base64 payload OpenAI config |
