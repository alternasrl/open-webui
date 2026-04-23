# Custom Patches — open-webui (alternasrl)

Questo directory contiene le patch custom applicate sopra la release upstream di open-webui.  
Sono numerate progressivamente e vanno applicate in ordine con:

```bash
git am patches/*.patch
```

> **Nota**: rispetto alla serie v0.8.12 le patch 0017 (analytics cross-filter), 0018 (analytics 1h), 0021 (WEB_FETCH_MAX_CONTENT_LENGTH) sono ora incluse nell'upstream v0.9.1 e quindi **rimosse** da questo directory. Le analytics backend (ex 0019-0020) sono state riscritte in forma async e consolidate in 0001-0002.

---

## Gruppi funzionali

### 📊 Analytics

Nuove metriche e filtri nella dashboard admin Analytics (riscritte per SQLAlchemy 2.0 async).

| # | File | Descrizione |
|---|------|-------------|
| 0001 | `feat-analytics-add-TTFT-Token-s-and-error-metrics-as...` | Nuove metriche aggregate async: **TTFT** (Time To First Token), **Token/s** (throughput), **Error rate**. Aggiunge `get_performance_metrics_by_model` e `get_performance_metrics` al modello `ChatMessage` (SQLAlchemy 2.0 AsyncSession). Espone i campi `avg_ttft_ms`, `avg_tokens_per_second`, `error_requests`, `total_requests`, `error_rate` via `analytics.py`. |
| 0002 | `feat-analytics-add-TTFT-error-UI-1h-filter-cross-fil...` | Frontend: colonne TTFT/Token/s/Error nella tabella Model Usage, filtro periodo "1h", cross-filter interattivo per modello/utente. Parametri `userId` e `modelId` aggiunti alle API call frontend. |

---

### 🛡️ WAF Bypass — OpenAI / Ollama Config

Correzioni per far funzionare la gestione delle connessioni OpenAI/Ollama dietro un Azure Application Gateway con WAF attivo.

| # | File | Descrizione |
|---|------|-------------|
| 0003 | `fix-enhance-error-handling-in-API-config-updates-and...` | Migliora la gestione degli errori in `openai.py` e `ollama.py` durante l'aggiornamento della config e il refresh dei modelli (try/except con log strutturato). |
| 0004 | `fix-handle-non-JSON-error-responses-in-OpenAI-Ollama...` | Gestione delle risposte di errore non-JSON restituite dai provider (es. HTML 502/503 da Azure WAF), evitando crash nel frontend. |
| 0005 | `fix-azure-verify-fallback-to-model_ids-when-openai-m...` | Fallback su `model_ids` configurati quando l'endpoint `/openai/models` non è raggiungibile attraverso il WAF Azure. |
| 0006 | `fix-await-save-handlers-before-dispatching-save-even...` | Fix async nel frontend: `await` sui save handler prima di fare dispatch dell'evento `save`, propagato lungo la catena del connection modal. |
| 0007 | `fix-mask-API-keys-in-config-responses-to-prevent-WAF...` | Le API key vengono restituite mascherate (`__MASKED__`) nelle risposte GET di config per evitare che il WAF blocchi le response contenenti chiavi in chiaro. Il POST risolve `__MASKED__` → chiave reale prima di salvare. |
| 0008 | `fix-wrap-JSON-config-in-Base64-envelope-to-prevent-W...` | Estende l'envelope Base64 a tutti i payload di config rimanenti (retrieval, embedding), completando la copertura WAF bypass. |
| 0009 | `fix-enhance-path-validation-and-sanitization-for-fil...` | Rafforzamento della validazione e sanitizzazione dei path nei file handler del backend. Previene path traversal e accessi a file fuori dalle directory consentite. |
| 0010 | `fix-route-OpenAI-config-r-w-via-api-v1-configs-opena...` | Aggiunge endpoint alias `GET/POST /api/v1/configs/openai` in `configs.py` che replicano `/openai/config`. Il frontend usa questi path per aggirare le WAF rule che bloccano `/openai/*`. |
| 0011 | `fix-mask-OpenAI-API-keys-in-configs.py-alias-endpoin...` | Estende il masking delle API key anche agli endpoint alias di `configs.py` (0010). |
| 0012 | `fix-Base64-encode-OpenAI-config-payload-to-bypass-WA...` | Il frontend codifica in Base64 il payload JSON prima di inviarlo al backend, aggirando l'ispezione del body da parte del WAF. Il backend decodifica con `_decode_payload()`. |

---

### 📋 NIS2 — Access Logging Middleware

Implementa un middleware di access log conforme alla direttiva NIS2 per la registrazione degli accessi alle API (~130 regole regex, compatibile con v0.9.x).

| # | File | Descrizione |
|---|------|-------------|
| 0013 | `feat-custom-access-log-NIS2-compliant...` | Introduce `access_log.py`: middleware FastAPI che intercetta ogni richiesta HTTP e scrive un log strutturato con utente, IP, metodo, path, status code e durata. |
| 0014 | `feat-Enhance-NIS2-compliance-in-access-logging-and-a...` | Aggiunge campi NIS2 estesi all'`AuditLogEntry`: `correlation_id` (da header X-Request-ID / X-Azure-Ref) e `oidc_claims` (dal JWT). La source IP ora traversa i proxy Azure WAF. |
| 0015 | `feat-Implement-thread-safe-caching-for-user-context-...` | Cache thread-safe per la risoluzione del contesto utente nel middleware di access log (evita query ripetute al DB per ogni richiesta). |
| 0016 | `feat-Invalidate-access-log-cache-on-OAuth-session-up...` | Invalida la cache del middleware quando la sessione OAuth viene aggiornata (`oauth.py`), garantendo che il log usi sempre i dati utente correnti. |
| 0017 | `feat-Enhance-NIS2-compliance-in-access-logging-middl...` | Classificazione dettagliata delle azioni (CREATE, READ, UPDATE, DELETE, LOGIN, …) tramite regex sul path, per la reportistica NIS2 / LOG360. |
| 0018 | `Enhance-access-log-middleware-with-additional-regex-...` | Estende il set di regex per coprire ulteriori endpoint (audio, retrieval, tools, functions, ecc.) e aggiunge nuovi tipi di azione. |
| 0019 | `feat-audit-OIDC-OAuth2-callback-track-AUTH_OIDC_LOGI...` | Aggiunge regole per gli endpoint OIDC/OAuth2 callback (`/oauth/{provider}/callback`, `/oauth/clients/{id}/callback`), mappandoli al tipo `AUTH_OIDC_LOGIN`. HTTP 4xx produce `AUTH_OIDC_LOGIN_FAIL  nis2=Y` per il rilevamento brute-force in Log360. |
| 0020 | `feat-extract-OIDC-claims-from-response-Set-Cookie-in...` | Nel callback OIDC il cookie `oauth_id_token` è nella *response*. Il middleware lo cerca nei `Set-Cookie` headers dopo `call_next()` e decodifica `oidc_sub` / `mfa` in-place per la riga `AUTH_OIDC_LOGIN`. |
| 0021 | `feat-log-OIDC-claims-on-both-success-and-failed-logi...` | `oauth.py` salva l'`id_token` grezzo in `request.state.oidc_raw_id_token` per i login falliti (dominio non consentito, ruolo mancante). Il middleware lo usa come fallback: `oidc_sub` e `mfa` sono popolati sia per login riusciti (307) che falliti (4xx). |
| 0022 | `feat-log-full-OIDC-token-claims-in-AUTH_OIDC_LOGIN-a...` | Aggiunge il campo `claims=<json>` alla riga `AUTH_OIDC_LOGIN`. Nuovo helper `_decode_full_id_token()` decodifica il JWT senza verifica firma e rimuove claim opachi (`at_hash`, `nonce`, `jti`). |
| 0023 | `feat-nis2-add-NIS2-rules-for-v0.9.x-new-endpoints-au...` | **[NUOVO v0.9.x]** Aggiunge ~20 nuove regole per le superfici introdotte in v0.9.0: Automations (CREATE/UPDATE/RUN/TOGGLE/DELETE), Calendar (CRUD eventi, RSVP), OAuth MCP (`AUTH_OAUTH_AUTHORIZE`, `AUTH_LOGOUT` backchannel), Terminal policy (`CONFIG_TERMINAL_SERVERS_VERIFY`, `CONFIG_TERMINAL_SERVERS_POLICY`). |
| 0024 | `docs-nis2-update-access_log.py-module-docstring-for-...` | **[NUOVO v0.9.x]** Aggiorna il docstring di `access_log.py`: ~130 regole totali, sezione Compatibility per v0.9.x, categorie CALENDAR_* e nuovi subtype AUTH_*/CONFIG_*. |

---

## Base upstream

Le patch sono generate a partire dal tag upstream open-webui **v0.9.1** (commit `0a8a620fb`).

```bash
# Applica tutte le patch su un branch da v0.9.1
git checkout -b my-branch v0.9.1
git am patches/*.patch

# Per la prossima integrazione upstream
git checkout -b integration-vX.Y.Z vX.Y.Z
git am patches/*.patch
# risolvi conflitti, poi rigenera:
git format-patch vX.Y.Z..HEAD --no-signature --output-directory patches/ -- ':!patches/'
```

### Patch rimosse rispetto alla serie v0.8.12

| Ex # | Motivo |
|------|--------|
| 0017 (analytics cross-filter) | Già incluso in upstream v0.9.x |
| 0018 (analytics 1h filter) | Già incluso in upstream v0.9.x |
| 0021 (WEB_FETCH_MAX_CONTENT_LENGTH) | Già incluso in `config.py` di v0.9.1 |
