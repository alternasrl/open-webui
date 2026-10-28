# Riconciliazione GIADA Open WebUI su upstream v0.12.4

Data: 2026-10-28

## 1. Sommario

**Obiettivo:** portare le customizzazioni del fork GIADA (esclusa l'analytics custom) sopra Open WebUI upstream v0.12.4, mantenendo le funzionalità analytics standard identiche a upstream.

| Riferimento        | Valore                                                           |
| ------------------ | ---------------------------------------------------------------- |
| Fork sorgente      | tag `v0.12.0-261012`, `ccf8f5fa35a81d7e295e31346ae427a877ffb800` |
| Upstream target    | tag `v0.12.4`, `33c1978d5bad52a31df75ea55143025dfad18d16`        |
| Merge base         | `15818d88fd7bde1b73de33590f50d15d21e8d7c1`                       |
| Branch / worktree  | `integration-v0.12.4` / `.worktrees/integration-v0.12.4`         |
| HEAD all'avvio doc | `489bd8578` (`chore: finalize v0.12.4 reconciliation candidate`) |

**Stato:** candidato. Nessun push, PR, tag, release, immagine Docker o deploy.

Delta del branch rispetto a upstream v0.12.4 (esclusi `patches`, `.superpowers`, `docs`): 51 file, +9147/−99.

## 2. Vincoli applicati

| Vincolo (Global Constraints)                                                                                | Applicazione                                                          |
| ----------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------- |
| Worktree/branch dedicato; nessun file non committato né `.codegraph`/`graphify-out`                         | Lavoro solo in `integration-v0.12.4`; checkout principale non toccato |
| Escludere solo analytics custom; analytics standard = upstream; nei file misti solo delta                   | Vedi sez. 5                                                           |
| Revisioni Alembic pubblicate non riscritte; tabelle Prompt Insights conservate, nessun drop                 | Vedi sez. 7                                                           |
| Ogni endpoint nuovo/modificato classificato (metodo, route, azione, actor, outcome)                         | Catalogo `audit_routes.py`, sez. 6                                    |
| Nessuna registrazione di password, token, recovery code, claim OIDC completi, body auth/chat/canali cifrati | Sez. 6 (privacy)                                                      |
| Test isolati/mock; nessun servizio o dato reale; dipendenze installate solo se mancanti                     | Runner senza rete/DNS, SQLite temporanea; ambiente Python usa-e-getta |
| Nessun push/PR/deploy/tag/release; trailer `Co-authored-by` nei commit                                      | Rispettato                                                            |

## 3. Commit del branch

`git log --oneline 15818d88fd..HEAD --first-parent`:

| SHA         | Soggetto                                         | Scopo                                                                                                             |
| ----------- | ------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------- |
| `ccf8f5fa3` | merge: integrate upstream v0.12.0                | Base: release fork v0.12.0-261012                                                                                 |
| `04ccde08a` | docs: inventory v0.12.4 customizations           | Inventario customizzazioni e ledger decisioni (`patches/integration-v0.12.4-decisions.md`)                        |
| `0d91d70fb` | chore: merge upstream v0.12.4                    | Merge del tag upstream v0.12.4                                                                                    |
| `adc4eba70` | fix: restore proxy and audit cache handling      | Ripristino `trust_env` proxy, chiusura risorse probe retrieval, invalidazione cache utente dopo update persistito |
| `d6659d44c` | test: enforce upstream analytics contracts       | Analytics standard = upstream; test di superficie; endpoint custom assenti                                        |
| `89117932a` | fix: reconcile v0.12.4 NIS2 audit                | Catalogo semantico NIS2, middleware ASGI, redazione payload, copertura delle route v0.12.4                        |
| `74589b47c` | test: adapt MCP and shared-chat tests to v0.12.4 | Test MCP su mcp 2.3.0/httpx2; test shared-chat con semantica upstream                                             |
| `d1088e3aa` | feat: merge v0.12.4 Alembic heads                | Revisione di merge `3a9d5e7c1b42` e test di migrazione                                                            |
| `410916d43` | test: harden migration reconciliation tests      | Grafo rigoroso ripristinato; variabili `DATABASE_*` rimosse dall'ambiente dei test                                |
| `489bd8578` | chore: finalize v0.12.4 reconciliation candidate | CHANGELOG, ledger finale, patch candidata                                                                         |

La task 7 (UI/i18n) non ha prodotto commit (sez. 9).

## 4. Customizzazioni preservate/adattate

### Backend

| Area                                          | Stato        | File chiave                                                                                              |
| --------------------------------------------- | ------------ | -------------------------------------------------------------------------------------------------------- |
| OAuth/OIDC, MFA, SCIM                         | adattato     | `utils/oauth.py`, `utils/auth.py`, `test/routers/test_v0120_mfa_oauth.py`                                |
| Admin guards                                  | preservato   | `routers/users.py`, `test/routers/test_v0114_admin_guards.py`                                            |
| Audit automazioni                             | adattato     | `utils/automations.py`, `routers/automations.py`, `test/utils/test_automations_audit.py`                 |
| Middleware NIS2 (`setup_access_logging(app)`) | ripristinato | `main.py`, `middleware/access_log.py`, `middleware/audit_routes.py`, `utils/audit.py`, `utils/logger.py` |
| Redazione audit apps/canali                   | adattato     | `routers/apps.py`, `routers/channels.py`, `utils/audit.py`, `utils/middleware.py`                        |
| Client MCP su mcp 2.3.0 / httpx2              | adattato     | `utils/mcp/client.py`, `test/utils/test_mcp_v0120.py`                                                    |
| Retrieval: `trust_env`, sicurezza web loader  | adattato     | `retrieval/utils.py`, `retrieval/web/utils.py`, `test/retrieval/test_web_loader_safety.py`               |
| Validazione path audio                        | preservato   | `routers/audio/__init__.py`, `test/routers/test_v0120_audio_validation.py`                               |
| Invalidazione cache utente                    | ripristinato | `utils/oauth.py`, `routers/users.py` (fix `adc4eba70`)                                                    |
| Shared-chat                                   | adattato     | `test/routers/test_v0120_shared_chat_analytics.py` (solo test; il delta di `utils/chat.py` riguarda lo stripping degli header Ollama)                                      |

### Frontend

| Area                                                                 | File chiave                                                                                                                                                          |
| -------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Settings/Connections (submit atteso, salvataggio solo se persistito) | `admin/Settings/Connections.svelte`, `Connections/OpenAIConnection.svelte`, `Connections/OllamaConnection.svelte`, `connections-save.ts`, `Connections.save.test.ts` |
| API OpenAI (fallback errore HTTP non JSON)                           | `src/lib/apis/openai/index.ts`, `index.test.ts`                                                                                                                      |

Il delta frontend rispetto a upstream è esattamente questi 7 file sorgente più 2 test. Il resto di `src/` è identico a v0.12.4.

### Configurazione

| File                                                      | Contenuto                                    |
| --------------------------------------------------------- | -------------------------------------------- |
| `docker-compose.yaml`                                     | Default env NIS2 audit-logging e cookie OIDC |
| `.github/copilot-instructions.md`                         | Istruzioni Copilot del fork                  |
| `.gitignore`, `open-webui.code-workspace`, `CHANGELOG.md` | Voci del fork                                |

## 5. Customizzazioni rimosse (analytics custom)

Rimossi: Prompt Insights, routing analytics, UI cross-filter (TTFT, Tok/s, errori analytics), relativi endpoint, metriche, test e chiavi di traduzione (nel fork: 65 file locale, 890 righe aggiunte rispetto alla merge base; verificato con `git diff --stat 15818d88fd..ccf8f5fa3 -- src/lib/i18n`).

**Analytics standard = upstream byte-identico.** Evidenza:

| Verifica                                                                                                                            | Esito                                                                                    |
| ----------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------- |
| `git diff 33c1978d5 HEAD` su `src/lib/components/admin/Analytics`, `src/lib/apis/analytics`, `routers/analytics.py`, `src/lib/i18n` | vuoto (Task 8)                                                                           |
| 73 file analytics API/UI/modelli/locale (64 cataloghi)                                                                              | uguali a upstream (Task 3)                                                               |
| 35 percorsi runtime/UI/test analytics custom                                                                                        | assenti                                                                                  |
| `test_v0124_analytics_surface.py`                                                                                                   | 27 test: 8 `GET` upstream; 8 endpoint Prompt Insights/routing ritirati → 404; gate admin |
| Route Prompt Insights/routing in `main.py`/router                                                                                   | nessuna                                                                                  |

Gli unici percorsi con "analytics" nel nome che differiscono da upstream sono le due migrazioni Prompt Insights (conservate) e due test.

## 6. NIS2

**Catalogo:** `backend/open_webui/middleware/audit_routes.py` — 602 policy business esplicite (metodo/template, azione semantica, actor, severità). I fallback regex legacy non contano come copertura. Una guardia sul `main.app` reale fallisce per nuove route, policy obsolete o mount opachi non classificati.

| Profilo                                     | Totale | Classificate | Esenti | Non classificate |
| ------------------------------------------- | -----: | -----------: | -----: | ---------------: |
| Sviluppo, SCIM attivo (tutte le route HTTP) |    610 |          602 |      8 |                0 |
| Produzione, SCIM disattivo                  |    592 |          587 |      5 |                0 |

**Le 8 esenzioni:** `GET /health`, `GET /health/db`, `GET /ready`, `GET /manifest.json`, `GET /opensearch.xml` (probe/descrittori pubblici) più, solo in sviluppo, `GET /openapi.json`, `GET /docs`, `GET /docs/oauth2-redirect`. Mount tecnici opachi riportati a parte: Socket.IO `/ws` e `StaticFiles` `/static`. SCIM attivo aggiunge 15 coppie, tutte classificate.

### Appendice A: 19 route

| Metodo e route                                       | Azione                        | Actor  |
| ---------------------------------------------------- | ----------------------------- | ------ |
| `GET /api/v1/apps`                                   | `APP_LIST_READ`               | utente |
| `GET /api/v1/apps/{app_id}`                          | `APP_READ`                    | admin  |
| `POST /api/v1/apps/manifest/preview`                 | `APP_MANIFEST_PREVIEW`        | admin  |
| `POST /api/v1/apps`                                  | `APP_CREATE`                  | admin  |
| `PATCH /api/v1/apps/{app_id}`                        | `APP_UPDATE`                  | admin  |
| `POST /api/v1/apps/{app_id}/connect`                 | `APP_CONNECT`                 | admin  |
| `DELETE /api/v1/apps/{app_id}`                       | `APP_DELETE`                  | admin  |
| `POST /api/v1/apps/{app_id}/interactions`            | `APP_INTERACTION`             | utente |
| `GET /api/v1/channels/{channel_id}/apps`             | `CHANNEL_APPS_READ`           | utente |
| `POST /api/v1/channels/{channel_id}/apps`            | `CHANNEL_APP_ADD`             | utente |
| `DELETE /api/v1/channels/{channel_id}/apps/{app_id}` | `CHANNEL_APP_REMOVE`          | utente |
| `POST /api/v1/channels/{id}/members/mute`            | `CHANNEL_MEMBER_MUTE`         | utente |
| `POST /api/v1/channels/{id}/access/update`           | `CHANNEL_ACCESS_UPDATE`       | utente |
| `GET /api/v1/files/user/search`                      | `FILES_SEARCH_READ`           | utente |
| `GET /api/v1/files/user/count`                       | `FILES_COUNT_READ`            | utente |
| `GET /api/v1/search`                                 | `WORKSPACE_SEARCH_READ`       | utente |
| `PATCH /api/v1/chats/{id}/params`                    | `CHAT_PARAMS_UPDATE`          | utente |
| `POST /api/v1/calendars/{calendar_id}/access/update` | `CALENDAR_ACCESS_UPDATE`      | utente |
| `POST /api/v1/configs/interface/visibility`          | `INTERFACE_VISIBILITY_UPDATE` | admin  |

"Utente" = utente verificato; i controlli di owner/manager restano negli handler. La route esistente `POST /api/v1/channels/{id}/members/active` ha l'azione esplicita `CHANNEL_MEMBER_ACTIVE`. Le 19 coppie sono state verificate anche contro `app.routes` runtime di upstream (597 coppie montate, 0 mancanti).

### Protezioni privacy

- Gli eventi NIS2 non registrano body di richiesta/risposta né query string; URI nei log con template di route (niente token webhook, nomi file, path proxy arbitrari).
- Body disattivati in entrambi gli stream di audit (NIS2 e `AuditLoggingMiddleware` upstream) per tutte le azioni `APP_*` e `CHANNEL_*` (varianti con slash, 2xx/4xx/5xx), più calendar access, interface visibility e workspace search; evento di metadati comunque mantenuto.
- Claim OIDC consentiti solo `sub`, `mfa`, `auth_time` (limitati), mai claim/gruppi completi o recovery code.
- Esclusi i body di chat (`/api/v1/chat/`, `/api/v1/chats`).
- Test sui canali cifrati con `Relay` reale: update/access/delete/rimozione membri/active invalidano lo stato; nessun contenuto cifrato negli audit.

### Correzioni

- `file:user`: `files/user/search` e `files/user/count` (anche con slash finale o in errore) non producono più l'oggetto `file:user`.
- ID app/canale: `APP_CREATE` registra l'ID restituito tramite hook su request state senza leggere la risposta; add/remove app di canale conservano channel ID e app ID; i riferimenti webhook identificano il webhook, non il token né un finto canale `webhooks`.
- Middleware convertito in ASGI puro (nessun buffering della risposta); fallimento a stream avviato produce un solo evento di errore.

## 7. Database e migrazioni

| Elemento                                            | Dettaglio                                                                                                                            |
| --------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------ |
| Revisione di merge                                  | `3a9d5e7c1b42` (genitori `0bd252b206fb` + `e304e2e7c45a`), upgrade/downgrade no-op, nessun DDL                                       |
| Head                                                | singola                                                                                                                              |
| Prompt Insights                                     | `f8a9b0c1d2e3`, `6c7d8e9f0a1b` invariate; tabelle/dati mai eliminati (`drop_table` solo nel downgrade); nessun runtime               |
| Revisioni pubblicate                                | ID e parent non riscritti                                                                                                            |
| `test_migration_v0124_reconciliation.py` (nuovo)    | head unico; DB vuoto → head; DB a `e304e2e7c45a` con righe sentinella e Prompt Insights, upgrade ripetuto due volte senza modifiche  |
| `test_migration_v0120_reconciliation.py` (adattato) | check del grafo rigoroso (`set(graph) - set(published) == {head}`), con grafi di `v0.12.4` e `ccf8f5fa` come pubblicati              |
| Isolamento test                                     | SQLite usa-e-getta, subprocess alembic con `DATABASE_URL`/`DATA_DIR` espliciti; `DATABASE_TYPE/USER/PASSWORD/HOST/PORT/NAME` rimosse |

## 8. Dipendenze e build

- `requirements.txt`, `requirements-slim.txt`, `pyproject.toml`, `package.json`, `package-lock.json`: diff vuoto rispetto a upstream v0.12.4 (`httpx2==2.16.0`, `mcp==2.3.0`).
- `npm run crypto:verify`: verificato.
- Nessuna dipendenza analytics custom residua.

## 9. Decisioni rilevanti

| Decisione                                                                                                                                                        | Motivo / costo se errata                                                                                                                                                                                                                             |
| ---------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Migrazioni Prompt Insights conservate, nessun drop, nessun runtime                                                                                               | Evita rotture negli upgrade e perdita dati; pulizia richiede approvazione separata                                                                                                                                                                   |
| Ambiente Python 3.12 usa-e-getta con requisiti slim v0.12.4 pinnati per la verifica runtime                                                                      | Import mancanti/non allineati nell'ambiente condiviso; nessuna modifica ai manifest                                                                                                                                                                  |
| `setup_access_logging(app)` preservato; `AuditLoggingMiddleware` upstream non equivalente                                                                        | Il wiring manca in upstream; coprono scopi diversi                                                                                                                                                                                                   |
| Shared-chat: semantica upstream (l'attore può modificare/rigenerare una risposta assistente che possiede); un collaboratore non può modificare messaggi di altri | Test diviso in due asserzioni invece di cancellato. Se errata, va riaggiunta una guardia più stretta in `models/chats.py`. Il router `update_chat_message_by_id` resta solo owner/admin (comportamento upstream)                                     |
| Task 7 no-op                                                                                                                                                     | Nessun commit: il merge aveva già portato i 7 file non-analytics; le 65 localizzazioni differenti erano solo chiavi analytics, correttamente scartate; verificato dal controller. Review del task saltata (nessun diff), coperta dalla review finale |
| Timeout httpx/`follow_redirects` del client MCP fork sostituiti dai valori upstream                                                                              | Contratto upstream adottato; annotato come customizzazione scartata                                                                                                                                                                                  |
| Implementatore Task 5 rilanciato su altro modello (401 sul primo)                                                                                                | Nessun impatto                                                                                                                                                                                                                                       |

## 10. Verifica

| Controllo                      | Comando / contesto                                                                                                                                   | Esito                                                                                           |
| ------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------- |
| Backend completo               | `pytest backend/` via runner isolato (runtime slim pinnato, rete/DNS bloccati, SQLite temporanea)                                                    | **732 passed, 3 skipped**, 0 failed (dopo i fix della review finale, HEAD `4e398be70`)                                                             |
| Skip                           | Test PostgreSQL di migrazione (`TEST_POSTGRES_URL` non impostato)                                                                                    | Non prova il comportamento su PostgreSQL                                                        |
| Middleware + audit automazioni | Suite `test/middleware` (incl. test redazione segreti, claim OIDC, log injection)                                                                                                       | 513 passed                                                                                      |
| Guardia route NIS2             | Inventario runtime dev/SCIM on e prod/SCIM off + `test_access_log_route_coverage.py` (175 passed)                                                      | 610/602/8/0 e 592/587/5/0                                                                       |
| Regressione CHANGELOG          | `test/utils/test_changelog_env.py` + `import open_webui.main` (parsing di `env.py`)                                                                  | passed                                                                                          |
| Migrazioni                     | `test_migration_v0120_*` + `test_migration_v0124_*`                                                                                                  | 8 passed, 3 skipped (PostgreSQL)                                                                |
| Analytics                      | `test_v0124_analytics_surface.py`                                                                                                                    | 27 passed                                                                                       |
| Frontend                       | `npx vitest run` (Node 22); `npm run test:frontend` è in modalità watch                                                                              | 3 file, 18 test passed                                                                          |
| `npm run check`                | svelte-check                                                                                                                                         | 5646 errori / 188 warning in 319 file; 0 diagnostica nei 7 file sorgente differenti da upstream |
| `npm run crypto:verify`        | Node 22                                                                                                                                              | OK                                                                                              |
| `git diff --check`             | Codice/config                                                                                                                                        | Pulito (rumore solo in archivi docs e riga nota di THIRD_PARTY_LICENSES vendored)               |
| Patch candidata                | `patches/integration-v0.12.4-customizations-from-main.patch` (49 file, +8959/−106); `git apply --check` e apply reale su checkout v0.12.4 usa-e-getta | OK, albero identico a HEAD                                                                      |

**Interpretazione `npm run check`:** i 5646 errori derivano da upstream: tutti i file `src/` non elencati sono byte-identici a v0.12.4, quindi nessuna nuova diagnostica. Baseline upstream non rieseguita su checkout pristine (inferita per identità dei file).

### Fix della review finale (HEAD `4e398be70`)

- CHANGELOG: intestazione datata `## [0.12.4-261028] - 2026-10-28 (...)`; prima rompeva `env.py` (`split(' - ')[1]`) e quindi l'import del backend. Test di regressione `test/utils/test_changelog_env.py`.
- Audit: `redact_passwords` maschera ricorsivamente le chiavi `*password|*secret|*credential|authorization|*api_key(s)|*token(s)|key(s)|*_key(s)` (JSON valido, con fallback regex per body troncati) e il body non viene catturato per le azioni `CONFIG_*` e `USER_VARIABLES_*`; test montati con marker `sk-` su 7 route di configurazione.
- Audit: i claim OIDC provengono solo da `request.state.oidc_audit_claims` o dal contesto server-side (`_resolve_user_context`); cookie/Bearer non verificati non sono più decodificati.
- Access log: `log_scheduled_activity` codifica email, ruolo, azione, object e meta (anti log injection).
- Catalogo: severità banner invertita correttamente.

## 11. Limitazioni e rischi residui

- Non eseguiti: PostgreSQL, MariaDB, servizi reali, build Docker; 3 test PostgreSQL saltati.
- Baseline svelte-check alta (ereditata da upstream, non riverificata).
- Warning baseline nei test (click/typer, `declarative_base` SQLAlchemy, Pydantic V1 in `ollama.py` e `retrieval/utils.py`, `InsecureKeyLengthWarning`).

**Finding Minor differiti (dalle review, da valutare nella review finale):**

| Task | Finding                                                                                                                                                                |
| ---- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 4    | Path non corrispondenti loggati come `[unmatched]` (perso il path reale: rilevamento scansioni)                                                                        |
| 4    | Riuso di metodi di `AccessLogMiddleware` con `self` di un'altra classe e import locali (`utils/audit.py`)                                                              |
| 4    | Controllo duplicati del catalogo con `assert` (rimosso con `python -O`) → usare `ValueError`                                                                           |
| 4    | Severità banner corrette in review finale (`GET /configs/banners` access, `POST` security); delete chat/file/note/messaggio canale restano `access`                     |
| 4    | Matching delle route ripetuto più volte per richiesta (risolvere una volta e cache in `scope['state']`)                                                                |
| 4    | Esclusioni body-capture incoerenti: `/api/chat/completions`, `/api/v1/messages`, `/openai/*`, `/ollama/*` restano catturati a livello REQUEST (comportamento upstream) |
| 4    | Richieste cancellate (`CancelledError`) non loggate (comportamento ereditato)                                                                                          |
| 4    | Lavoro duplicato in `__call__`/`dispatch` (session ID, esclusioni)                                                                                                     |
| 4    | 20 warning nei test; chiave JWT di test da 25 byte (< 32)                                                                                                              |
| 5    | `test_initialize_failure_cleans_failed_session` debole (passerebbe anche su upstream); verificare `read_timeout_seconds=MCP_INITIALIZE_TIMEOUT`                        |
| 5    | `assert 'initialize' in seen` più debole della sequenza esatta; usare `seen[:2] == ['server/discover', 'initialize']`                                                  |
| 5    | Timeout httpx configurabile e `follow_redirects=True` del fork scartati, non documentati nel report                                                                    |
| 5    | Warning baseline non elencati nel report                                                                                                                               |
| 6    | `test_migration_v0124`: `DATA_DIR`/`DATABASE_URL` impostati a livello di sessione all'import, senza cleanup (`mkdtemp` mai rimossa)                                    |
| 6    | `VECTOR_DB='pgvector'` in `_upgrade` senza spiegazione                                                                                                                 |
| 6    | `test_migration_v0120` non rimuove le variabili DB all'import (solo nel subprocess; fragile se si aggiungono run alembic in-process)                                   |

## 12. Prossimi passi

1. Review finale dell'intero branch (copre anche il frontend, poiché la Task 7 non ha avuto review) e valutazione dei Minor differiti.
2. Solo su approvazione: tag sorgente `v0.12.4-YYMMDD` (es. `v0.12.4-261028`; regex `^v\d+\.\d+\.\d+(-[a-z0-9]+)?-\d{6}[b-z]?$`).
3. Tag immagine Docker `{tag}-build-YYYYMMDD.NN` (es. `v0.12.4-261028-build-20261028.01`), riferimento ACR `craltea.azurecr.io/open-webui:{tag-immagine}`.
4. PR verso `dev` (non `main`), con template del repository e changelog.
