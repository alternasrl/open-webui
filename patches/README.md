# Custom Patches — open-webui (alternasrl)

Questo directory contiene le patch custom applicate sopra la release upstream di open-webui.  
Sono numerate progressivamente e vanno applicate in ordine con:

```bash
git am patches/0001-*.patch patches/0002-*.patch ... patches/0024-*.patch
# oppure in un colpo solo:
git am patches/*.patch
```

---

## Gruppi funzionali

### 🔒 Sicurezza — Path Validation

| # | File | Descrizione |
|---|------|-------------|
| 0001 | `fix-enhance-path-validation...` | Rafforzamento della validazione e sanitizzazione dei path nei file handler del backend. Previene path traversal e accessi a file fuori dalle directory consentite. |

---

### 📋 NIS2 — Access Logging Middleware

Implementa un middleware di access log conforme alla direttiva NIS2 per la registrazione degli accessi alle API.

| # | File | Descrizione |
|---|------|-------------|
| 0002 | `feat-custom-access-log-NIS2...` | Introduce `access_log.py`: middleware FastAPI che intercetta ogni richiesta HTTP e scrive un log strutturato con utente, IP, metodo, path, status code e durata. |
| 0003 | `feat-Enhance-NIS2-compliance-in-access-logging-and-a...` | Aggiunge campi NIS2 estesi all'`AuditLogEntry`: `correlation_id` (da header X-Request-ID / X-Azure-Ref) e `oidc_claims` (dal JWT). La source IP ora traversa i proxy Azure WAF. |
| 0004 | `feat-Implement-thread-safe-caching-for-user-context...` | Cache thread-safe per la risoluzione del contesto utente nel middleware di access log (evita query ripetute al DB per ogni richiesta). |
| 0005 | `feat-Invalidate-access-log-cache-on-OAuth-session-up...` | Invalida la cache del middleware quando la sessione OAuth viene aggiornata (`oauth.py`), garantendo che il log usi sempre i dati utente correnti. |
| 0006 | `feat-Enhance-NIS2-compliance-in-access-logging-middl...` | Classificazione dettagliata delle azioni (CREATE, READ, UPDATE, DELETE, LOGIN, …) tramite regex sul path, per la reportistica NIS2 / LOG360. |
| 0007 | `Enhance-access-log-middleware-with-additional-regex...` | Estende il set di regex per coprire ulteriori endpoint (audio, retrieval, tools, functions, ecc.) e aggiunge nuovi tipi di azione. |
| 0022 | `feat-audit-OIDC-OAuth2-callback-track-AUTH_OIDC_LOGI...` | Aggiunge regole di azione per gli endpoint OIDC/OAuth2 callback (`/oauth/{provider}/login/callback`, `/oauth/{provider}/callback`, `/oauth/clients/{id}/callback`), mappandoli al nuovo tipo `AUTH_OIDC_LOGIN`. Il tipo viene aggiunto a `_NIS2_SECURITY_ACTIONS` (log a livello WARNING) e al blocco di rilevamento fallimenti: un HTTP 4xx sul callback produce `action=AUTH_OIDC_LOGIN_FAIL  nis2=Y`, abilitando il rilevamento brute-force nel SIEM Log360. Prima di questa fix un login OIDC fallito compariva con `action=-  nis2=N`. |
| 0023 | `feat-extract-OIDC-claims-from-response-Set-Cookie-in...` | Nel callback OIDC il cookie `oauth_id_token` viene scritto nella *response*, non nella request. L'`AccessLogMiddleware` non riusciva quindi a leggere `oidc_sub` e `mfa` per la riga di log `AUTH_OIDC_LOGIN` (apparivano come `-`). Fix: dopo `call_next()`, per i soli path `AUTH_OIDC_LOGIN`, il middleware cerca `oauth_id_token` nei response `Set-Cookie` headers e lo decodifica in-place. Nessun overhead per le altre richieste. Sul login riuscito (307): `oidc_sub=<sub>  mfa=pwd`. Sul login fallito (4xx): `oidc_sub=-` perché l'IdP non ha emesso alcun cookie. |
| 0024 | `feat-log-OIDC-claims-on-both-success-and-failed-logi...` | Estende la patch 0023: in caso di login fallito (dominio non consentito, ruolo mancante, signup disabilitato) l'IdP non emette cookie ma il token exchange può essere riuscito. `oauth.py` salva l'`id_token` grezzo in `request.state.oidc_raw_id_token` subito dopo lo scambio del codice. L'`AccessLogMiddleware` lo legge come fallback quando il percorso dei response cookies non trova nulla. Risultato: `oidc_sub` e `mfa` sono popolati nel log sia per login riusciti (307) che falliti (4xx). Unica eccezione: se il token exchange stesso fallisce, nessun `id_token` è disponibile. |

---

### 🛡️ WAF Bypass — OpenAI / Ollama Config

Correzioni per far funzionare la gestione delle connessioni OpenAI/Ollama dietro un Azure Application Gateway con WAF attivo.

| # | File | Descrizione |
|---|------|-------------|
| 0008 | `fix-enhance-error-handling-in-API-config-updates...` | Migliora la gestione degli errori in `openai.py` e `ollama.py` durante l'aggiornamento della config e il refresh dei modelli (try/except con log strutturato). |
| 0009 | `fix-handle-non-JSON-error-responses-in-OpenAI-Ollama...` | Gestione delle risposte di errore non-JSON restituite dai provider (es. HTML 502/503 da Azure WAF), evitando crash nel frontend. |
| 0010 | `fix-azure-verify-fallback-to-model_ids...` | Fallback su `model_ids` configurati quando l'endpoint `/openai/models` non è raggiungibile attraverso il WAF Azure. |
| 0011 | `fix-route-OpenAI-config-r-w-via-api-v1-configs-openai...` | Aggiunge endpoint alias `GET/POST /api/v1/configs/openai` in `configs.py` che replicano `/openai/config`. Il frontend usa questi path per aggirare le WAF rule che bloccano `/openai/*`. |
| 0012 | `fix-await-save-handlers-before-dispatching-save-event...` | Fix async nel frontend: `await` sui save handler prima di fare dispatch dell'evento `save`, propagato lungo la catena del connection modal. |
| 0013 | `fix-mask-API-keys-in-config-responses...` | Le API key vengono restituite mascherate (`__MASKED__`) nelle risposte GET di config per evitare che il WAF blocchi le response contenenti chiavi in chiaro. Il POST risolve `__MASKED__` → chiave reale prima di salvare. |
| 0014 | `fix-mask-OpenAI-API-keys-in-configs.py-alias-endpoints...` | Estende il masking delle API key anche agli endpoint alias di `configs.py` (0011). |
| 0015 | `fix-Base64-encode-OpenAI-config-payload-to-bypass-WAF...` | Il frontend codifica in Base64 il payload JSON prima di inviarlo al backend, aggirando l'ispezione del body da parte del WAF. Il backend decodifica con `_decode_payload()`. |
| 0016 | `fix-wrap-JSON-config-in-Base64-envelope...` | Estende l'envelope Base64 a tutti i payload di config rimanenti (retrieval, embedding), completando la copertura WAF bypass. |

---

### 📊 Analytics

Nuove metriche e filtri nella dashboard admin Analytics.

| # | File | Descrizione |
|---|------|-------------|
| 0017 | `feat-analytics-add-cross-filter-by-model-and-user...` | Cross-filter interattivo: cliccando su un modello o utente nei grafici si filtrano tutti i widget della dashboard. Backend: query aggiornate con filtri per `model_id` e `user_id`. |
| 0018 | `feat-analytics-add-last-1-hour-period-filter...` | Aggiunge il periodo "Ultima ora" (1h) al selettore del range temporale nella dashboard Analytics. |
| 0019 | `feat-analytics-add-TTFT-Token-s-and-request-error-metrics...` | Nuove metriche aggregate: **TTFT** (Time To First Token), **Token/s** (throughput), **Error rate** sulle richieste. Calcolate dal modello `ChatMessage` e esposte via `analytics.py`. |
| 0020 | `feat-analytics-add-per-model-TTFT-Token-s-and-error-metrics...` | Aggiunge le colonne TTFT, Token/s ed Error rate anche alla tabella "Model Usage" nella dashboard, con visualizzazione per-modello. |

---

### ⚙️ Configurazione

| # | File | Descrizione |
|---|------|-------------|
| 0021 | `feat-add-WEB_FETCH_MAX_CONTENT_LENGTH...` | Espone la variabile d'ambiente `WEB_FETCH_MAX_CONTENT_LENGTH` nella pagina Admin > Configurazione, permettendo di limitare la dimensione massima dei contenuti scaricati durante il web fetch RAG. |

---

## Base upstream

Le patch sono generate a partire dal commit `9bd84258d` (upstream open-webui **v0.8.12**).  
Per la prossima integrazione upstream:

```bash
# 1. Crea un branch dal nuovo tag upstream
git checkout -b release/vX.Y.Z-secure-audit-YYYYMMDD upstream/vX.Y.Z

# 2. Applica le patch
git am patches/*.patch

# 3. Risolvi eventuali conflitti, poi rigenera le patch
git format-patch upstream/vX.Y.Z --output-directory patches/
```
