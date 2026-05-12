# Custom Patches — open-webui (alternasrl)

Questo directory contiene le patch custom applicate sopra la release upstream di open-webui.  
Sono numerate progressivamente e vanno applicate in ordine con:

```bash
git am patches/*.patch
```

> **Nota v0.9.2**: rimossi tutti i workaround Azure WAF (ex 0003-0008/0010-0012 nella serie v0.9.1) — totale sceso da 24 a **16 patch**.

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

Implementa un middleware di access log conforme alla direttiva NIS2 per la registrazione degli accessi alle API (~130 regole regex, compatibile con v0.9.x).

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
| 0016 | `docs-nis2-update-access_log.py-module-docstring-for-...` | Aggiorna il docstring di `access_log.py`: ~130 regole totali, sezione Compatibility per v0.9.x, categorie CALENDAR_* e nuovi subtype AUTH_*/CONFIG_*. |

---

## Base upstream

Le patch sono generate a partire dal tag upstream open-webui **v0.9.5** (commit `3660bc00f`).

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
