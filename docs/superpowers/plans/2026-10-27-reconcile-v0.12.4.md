# Riconciliazione customizzazioni su upstream v0.12.4 - Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** portare su Open WebUI upstream v0.12.4 tutte le customizzazioni GIADA non analytics, mantenere l'Analytics upstream invariata e garantire logging NIS2 coerente per ogni endpoint v0.12.4.

**Architecture:** fissare gli SHA del fork e dell'upstream, eseguire il merge in un worktree isolato e classificare il delta custom effettivo rispetto a v0.12.4. Ripristinare l'implementazione upstream per ogni personalizzazione analytics; adattare le altre customizzazioni ai nuovi contratti upstream. La copertura NIS2 deriva dall'inventario delle route FastAPI del target e ammette solo eccezioni esplicite e motivate.

**Tech Stack:** Git, FastAPI/Python, pytest, SQLAlchemy/Alembic, SvelteKit/TypeScript, Vitest, npm, Rust per gli artefatti di cifratura upstream.

**Spec:** richiesta utente del 2026-10-27; baseline e decisioni precedenti in `docs/superpowers/plans/2026-10-12-reconcile-v0.12.0.md`, `patches/integration-v0.12.0-decisions.md` e `patches/integration-v0.12.0-customizations-files.txt`.

## Global Constraints

- Fork sorgente: tag `v0.12.0-261012`, commit `ccf8f5fa35a81d7e295e31346ae427a877ffb800`.
- Target upstream: tag `v0.12.4`, commit `33c1978d5bad52a31df75ea55143025dfad18d16`.
- Eseguire il merge in un worktree/branch dedicato `integration-v0.12.4`; non modificare il `main` sporco né importare file non committati o artefatti `.codegraph`/`graphify-out`.
- Escludere esclusivamente le customizzazioni analytics del fork: Prompt Insights, routing analytics e relativi endpoint/UI/metriche/traduzioni/test. Mantenere le funzionalità analytics standard esattamente come in upstream v0.12.4. Nei file misti eliminare solo il delta analytics.
- Le revisioni Alembic già pubblicate e i loro ID/parent non si riscrivono. Conservare senza eseguire drop le tabelle/dati Prompt Insights eventualmente già presenti: la feature runtime non viene portata, la pulizia dei dati richiederebbe approvazione separata.
- Per ogni endpoint nuovo o modificato, classificare metodo, route, azione, actor e outcome NIS2. Escludere solo route tecniche documentate; mai usare esclusioni generalizzate per prefisso o metodo.
- Non registrare password, token, recovery code, claim OIDC completi, body di autenticazione o payload di chat/canali cifrati.
- Test DB, storage, provider, OAuth ed embedding isolati o mock; nessun accesso a servizi/dati reali. Non installare dipendenze finché un test non segnala che mancano o finché non cambia un manifest.
- Non fare push, PR, deploy, tag o release. Ogni commit esecutivo deve includere `Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>`.

## Review Focus

1. Route business aggiunte o rinominate upstream ma assenti dalla copertura NIS2: il test deve enumerare il router FastAPI effettivamente montato e fallire su ogni route non classificata.
2. Fallimenti auth/MFA/SCIM e richieste non valide: registrare outcome e actor disponibili senza salvare segreti o claim sensibili.
3. Apps e canali cifrati: tracciare eventi amministrativi e membership senza loggare contenuti, chiavi o ciphertext.
4. Rimozione del codice analytics custom con DB già migrato: mantenere migrazioni e dati storici senza riattivare la feature né cancellare tabelle.
5. File condivisi con codice analytics e non analytics: rimuovere soltanto il delta analytics, mantenendo le altre personalizzazioni e i contratti upstream.

---

## Struttura dei file e responsabilità

- `patches/integration-v0.12.4-customizations-files.txt`: inventario ricalcolato dal commit fork al tag upstream; non riusare l'inventario v0.12.0 come delta attuale.
- `patches/integration-v0.12.4-decisions.md`: decisione per ogni percorso custom (`preserve`, `adapt`, `upstream-standard`, `provenance`) con motivo e test.
- `backend/open_webui/middleware/access_log.py`, `backend/open_webui/utils/middleware.py`, `backend/open_webui/main.py`: preservare e adattare audit NIS2 e lifecycle alla registrazione middleware upstream.
- `backend/open_webui/utils/audit.py`: mantenere l'audit upstream, ma impedire la cattura dei body di Apps e canali, che possono contenere API key o contenuti privati.
- `backend/open_webui/test/middleware/access_log_route_coverage.py`, `backend/open_webui/test/middleware/test_access_log_route_coverage.py`, `backend/open_webui/test/middleware/test_access_log.py`: inventario e prove della copertura route/audit.
- `backend/open_webui/migrations/versions/`: revisioni upstream v0.12.4 più revisioni custom storiche non analytics; revisioni Prompt Insights già pubblicate restano immutate per compatibilità DB, senza nuovo codice runtime.
- `backend/open_webui/routers/analytics.py`, `src/lib/apis/analytics/index.ts`, `src/lib/components/admin/Analytics.svelte`, `src/lib/components/admin/Analytics/**`: implementazione upstream v0.12.4; nessuna UI o API custom analytics.
- `backend/open_webui/models/chat_messages.py`, `backend/open_webui/utils/oauth.py`, `backend/open_webui/utils/automations.py`, `backend/open_webui/utils/mcp/client.py`, `backend/open_webui/retrieval/**` e rispettivi test: adattare le personalizzazioni non analytics ai modelli e alle API upstream.
- `src/lib/i18n/locales/**/translation.json`, manifest, lockfile e configurazioni: mantenere le traduzioni e le dipendenze non analytics; non reintrodurre chiavi o pacchetti usati solo dai componenti esclusi.
- `CHANGELOG.md`: documentare l'integrazione solo dopo aver verificato il delta finale; nessuna release viene creata in questo piano.

## Task 1: Congelare baseline, inventario e decisioni

**Files:**
- Create: `patches/integration-v0.12.4-customizations-files.txt`
- Create: `patches/integration-v0.12.4-decisions.md`
- Temporary: artefatti di confronto in `files/reconcile-v0.12.4/` nella sessione

**Interfaces:**
- Consumes: SHA fork/upstream dai Global Constraints.
- Produces: inventario ricalcolato, matrice per file e worktree pulito da usare nei task successivi.

- [ ] **Step 1: Verificare ref, ancestry, stato e worktree senza modificarli.** Confermare i due tag/SHA e che esista una base comune; registrare i file sporchi già presenti e non incorporarli.
- [ ] **Step 2: Creare un worktree `integration-v0.12.4` dal commit fork e acquisire il tag upstream v0.12.4 come ref locale.** Se il path/branch esiste già, ispezionarlo e riutilizzarlo solo se corrisponde agli SHA; non sovrascrivere worktree esistenti.
- [ ] **Step 3: Calcolare diff, file comuni e merge-tree tra i due SHA.** Produrre inventario binario/non binario completo; classificare come analytics solo codice, schema accessorio, test, traduzioni e patch la cui finalità è Prompt Insights/routing analytics/TTFT-token/s custom.
- [ ] **Step 4: Scrivere la matrice decisionale.** Per i file misti, specificare i singoli simboli/porzioni da mantenere o riportare upstream; archivi di patch e documenti storici sono provenienza, non patch da riapplicare.
- [ ] **Step 5: Verificare il perimetro analytics.** Nel branch di integrazione, confrontare con upstream i file analytics-only e confermare che gli endpoint/UI custom non siano inclusi; per i file misti, documentare i delta non analytics residui.
- [ ] **Step 6: Verificare l'inventario NIS2 dell'appendice A contro `app.routes`.** Il subagent ha trovato 19 method/path nuovi o senza regole semantiche equivalenti; confermare il conteggio sul tree risultante prima di iniziare Task 4.
- [ ] **Step 7: Assegnare ogni personalizzazione non analytics a un task.** Nessun percorso `preserve`/`adapt` del manifest può restare senza proprietario e verifica.

**Check:** nessuna modifica applicativa; `rtk git diff --check` pulito. La matrice contiene una decisione e un test per ciascun percorso effettivamente divergente.

## Task 2: Integrare il tag upstream v0.12.4

**Files:**
- Modify: tutti i percorsi divergenti elencati nell'inventario, classificati dalla matrice
- Modify: `CHANGELOG.md` solo nel task finale

**Interfaces:**
- Consumes: inventario e matrice Task 1.
- Produces: branch con il tree upstream v0.12.4 integrato e tutte le personalizzazioni non analytics preservate o assegnate a task successivi.

- [ ] **Step 1: Eseguire il merge dei due SHA nel worktree isolato.** Non produrre commit parziali con `MERGE_HEAD` presente.
- [ ] **Step 2: Risolvere i conflitti testuali seguendo la matrice.** Nei file analytics-only usare l'implementazione upstream; nei file misti integrare entrambi i comportamenti non analytics.
- [ ] **Step 3: Verificare il grafo Git e lo stato del merge.** Nessun conflitto residuo; il commit di merge conserva entrambi i genitori e usa il trailer richiesto.

**Check:** `rtk git diff --check`; i path analytics-only risultano identici al target upstream v0.12.4. La verifica non sostituisce i test semantici dei task seguenti.

## Task 3: Mantenere le analytics standard ed escludere solo le custom

**Files:**
- Upstream standard: `backend/open_webui/routers/analytics.py`, `src/lib/apis/analytics/index.ts`, `src/lib/components/admin/Analytics.svelte`, `src/lib/components/admin/Analytics/**`
- Fork analytics da escludere dal runtime: `backend/open_webui/models/prompt_insights.py`, `backend/open_webui/prompt_insights/**`, endpoint/UI custom Prompt Insights e routing, metriche dedicate, test e chiavi i18n usate esclusivamente da esse
- File misti da adattare: `backend/open_webui/models/chat_messages.py`, `backend/open_webui/utils/audit.py`, `src/lib/i18n/locales/**/translation.json`
- Migrations: `backend/open_webui/migrations/versions/f8a9b0c1d2e3_add_prompt_insights_tables.py`, `backend/open_webui/migrations/versions/6c7d8e9f0a1b_add_prompt_insights_active_claim.py`
- Create: `backend/open_webui/test/routers/test_v0124_analytics_surface.py`

**Interfaces:**
- Consumes: matrice Task 1 e merge Task 2.
- Produces: superfici analytics runtime conformi a v0.12.4; schema/migrazioni storiche preservati senza runtime Prompt Insights.

- [ ] **Step 1: Ripristinare le superfici analytics standard da upstream.** Conservare dashboard, API, metriche e comportamento v0.12.4 senza cross-filter, routing analytics o Prompt Insights custom.
- [ ] **Step 2: Rimuovere solo codice analytics custom dai file misti.** In particolare, non rimuovere audit NIS2 o log di sicurezza solo perché condividono file/termini con analytics; non rimuovere campi/comportamenti non analytics da `chat_messages.py`.
- [ ] **Step 3: Rimuovere import, registrazioni, scheduler, job, dipendenze runtime e chiavi i18n esclusivamente legati alla feature Prompt Insights.** Conservare i documenti/patch storici come provenienza, non come codice eseguibile.
- [ ] **Step 4: Conservare le revisioni Prompt Insights già pubblicate con ID e parent invariati e non aggiungere una migrazione distruttiva.** Il codice deve poter aggiornare DB già marcati su tali revisioni senza perdere dati.
- [ ] **Step 5: Verificare la parità upstream.** Controllare i file analytics-only contro `33c1978d5bad52a31df75ea55143025dfad18d16`; in `test_v0124_analytics_surface.py` verificare l'insieme method/path analytics upstream e l'assenza degli endpoint custom routing/Prompt Insights.
- [ ] **Step 6: Eseguire il test di contratto.**

```bash
rtk proxy python -m pytest -q backend/open_webui/test/routers/test_v0124_analytics_surface.py
```

Atteso: route e risposta standard corrispondono al target v0.12.4, nessuna route analytics custom è registrata.

**Check:** nessun test Prompt Insights/routing analytics è raccolto come feature runtime; le migrazioni storiche restano riconoscibili dall'upgrade test del Task 6.

## Task 4: Riconciliare audit NIS2 con tutte le route v0.12.4

**Files:**
- Modify: `backend/open_webui/middleware/access_log.py`
- Modify: `backend/open_webui/utils/middleware.py`
- Modify: `backend/open_webui/utils/audit.py`
- Modify: `backend/open_webui/main.py`
- Modify: `backend/open_webui/test/middleware/access_log_route_coverage.py`
- Modify: `backend/open_webui/test/middleware/test_access_log_route_coverage.py`
- Modify: `backend/open_webui/test/middleware/test_access_log.py`
- Route inventory: appendice A di questo piano, da verificare sul runtime risultante prima dell'esecuzione

**Interfaces:**
- Consumes: route inventory upstream v0.12.4 e classificazione Task 1.
- Produces: una classificazione NIS2 verificabile per ogni route FastAPI registrata e test che fallisce per route business nuova/non coperta.

- [ ] **Step 1: Aggiornare l'installazione middleware al lifecycle v0.12.4.** Preservare ordine, actor resolution, correlation ID, outcome HTTP/exception, cache invalidation e sanificazione del fork.
- [ ] **Step 2: Preservare il wiring NIS2 effettivo in `main.py`.** Il fork chiama `setup_access_logging(app)`; upstream v0.12.4 non lo chiama. Mantenere il middleware custom attivo nel runtime aggiornato, rispettare l'ordine ASGI upstream e provare una richiesta tramite l'app montata; l'`AuditLoggingMiddleware` upstream non è un sostituto della classificazione NIS2.
- [ ] **Step 3: Classificare tutte le route del target.** Per ciascuna coppia metodo/path registrare azione semantica, requisito di actor, evento/outcome e policy dati. Le 19 route mancanti elencate nell'appendice A ricevono azioni esplicite; route non catalogate devono fallire la suite.
- [ ] **Step 4: Estendere `test_access_log_route_coverage.py`.** Confrontare l'intero insieme di route runtime con il catalogo classificato, comprese le route già presenti con comportamento materialmente cambiato. Nessuna route business può essere coperta solo da `WRITE_OTHER`, `DELETE_OTHER` o `READ`.
- [ ] **Step 5: Aggiungere test per le nuove azioni e gli identificatori.** Verificare esito positivo/negativo, attore, object ID e outcome; attribuire anche `app_id` su route channel-app e l'ID restituito dopo creazione app. Correggere l'estrazione file affinché `/api/v1/files/user/search` e `/user/count` non siano classificati come oggetto `file:user`.
- [ ] **Step 6: Disabilitare la cattura dei body in `AuditLoggingMiddleware` per Apps e canali.** Gli eventi di audit possono conservare path/azione/actor/outcome; non registrare API key, contesto d'interazione, messaggi, body o ciphertext. La protezione non deve disabilitare il log dell'evento.
- [ ] **Step 7: Verificare che i log non contengano segreti o contenuti.** Asserire assenza di password/token/recovery code/claim OIDC completi/body auth e payload/ciphertext dei canali cifrati.
- [ ] **Step 8: Eseguire i test di audit.**

```bash
rtk proxy python -m pytest -q backend/open_webui/test/middleware/test_access_log.py backend/open_webui/test/middleware/test_access_log_route_coverage.py backend/open_webui/test/routers/test_v0120_mfa_oauth.py
```

Atteso: tutti i test passano; un test ASGI conferma che il middleware NIS2 è installato sul runtime; ogni route di business v0.12.4 è classificata e ogni eccezione è esplicita.

## Task 5: Adattare le personalizzazioni backend non analytics

**Files:**
- Modify: percorsi `adapt` del manifest backend, in particolare `backend/open_webui/models/chat_messages.py`, `backend/open_webui/utils/oauth.py`, `backend/open_webui/utils/automations.py`, `backend/open_webui/utils/mcp/client.py`, `backend/open_webui/retrieval/**`, `backend/open_webui/main.py`
- Keep: componenti Prompt Insights e test solo se storici; non registrare runtime o import analytics custom
- Test: `backend/open_webui/test/routers/test_v0120_mfa_oauth.py`, `backend/open_webui/test/routers/test_v0114_admin_guards.py`, `backend/open_webui/test/utils/test_automations_audit.py`, `backend/open_webui/test/utils/test_mcp_v0120.py`, `backend/open_webui/test/retrieval/test_web_loader_safety.py`

**Interfaces:**
- Consumes: upstream v0.12.4 e matrice Task 1.
- Produces: custom auth, OAuth, automazioni, MCP e retrieval compatibili col target, escluso il delta analytics.

- [ ] **Step 1: Adattare OAuth/MFA/SCIM e i guard amministrativi.** Conservare gli hook custom non analytics; integrare le correzioni upstream per auth records, revoche, sessioni e protezione degli admin.
- [ ] **Step 2: Adattare automazioni, MCP e retrieval.** Mantenere audit non analytics, controlli di sicurezza e forwarding custom; adottare i nuovi protocolli/contratti upstream senza outbound reale nei test.
- [ ] **Step 3: Adattare `chat_messages.py` e gli altri file condivisi.** Mantenere solo le personalizzazioni non analytics e integrare le modifiche upstream per compaction, ownership e messaggi condivisi.
- [ ] **Step 4: Eseguire i test backend mirati.**

```bash
rtk proxy python -m pytest -q backend/open_webui/test/routers/test_v0120_mfa_oauth.py backend/open_webui/test/routers/test_v0114_admin_guards.py backend/open_webui/test/utils/test_automations_audit.py backend/open_webui/test/utils/test_mcp_v0120.py backend/open_webui/test/retrieval/test_web_loader_safety.py
```

Atteso: test verdi con provider, API e rete esterna mockati; non raccogliere i test Prompt Insights/routing analytics custom come prova di funzionalità.

## Task 6: Riconciliare schema, dipendenze e build upstream

**Files:**
- Modify: `backend/open_webui/migrations/env.py`, `backend/open_webui/migrations/versions/**`
- Modify as required: `backend/requirements.txt`, `backend/requirements-slim.txt`, `pyproject.toml`, `package.json`, `package-lock.json`, `crypto/encryption/**`, workflow/container files
- Create: `backend/open_webui/test/models/test_migration_v0124_reconciliation.py`

**Interfaces:**
- Consumes: merge Task 2 e decisioni analytics Task 3.
- Produces: upgrade compatibile con DB del fork e v0.12.4, head Alembic unica, dipendenze/build che includono le funzioni upstream.

- [ ] **Step 1: Integrare le revisioni upstream senza riscrivere revisioni fork pubblicate.** Risolvere i parent con una nuova merge revision solo se il grafo la richiede; mantenere anche le revisioni Prompt Insights già in storia.
- [ ] **Step 2: Scrivere `test_migration_v0124_reconciliation.py`.** Verificare upgrade DB vuoto e DB disposable già alla head fork, dati non analytics sentinel, head unica e assenza di perdita dei dati legacy Prompt Insights.
- [ ] **Step 3: Allineare requisiti e lockfile ai manifest upstream.** Rimuovere solo dipendenze legate esclusivamente all'analytics custom; mantenere pin security non analytics se compatibili, spiegando ogni delta.
- [ ] **Step 4: Verificare artefatti crittografici e migrazioni.**

```bash
rtk proxy python -m pytest -q backend/open_webui/test/models/test_migration_v0124_reconciliation.py
rtk npm run crypto:verify
```

Atteso: upgrade isolati passano, un solo head, hash/artefatti crypto verificati; nessuna scrittura o migrazione su DB reale.

## Task 7: Portare UI e traduzioni non analytics

**Files:**
- Modify: componenti Svelte e API frontend nel manifest `adapt` non analytics
- Modify: `backend/open_webui/static/BRANDING.md`, `docker-compose.yaml`, istruzioni di repo e documentazione custom solo se classificati `preserve`/`adapt` nel manifest
- Modify: `src/lib/i18n/locales/**/translation.json` conservando chiavi custom non analytics
- Keep upstream standard: `src/lib/components/admin/Analytics/**`, `src/lib/apis/analytics/index.ts`
- Test: `src/lib/components/admin/Settings/Connections.save.test.ts`, `src/lib/apis/openai/index.test.ts`, test mirati aggiunti per altri componenti modificati, `npm run check`

**Interfaces:**
- Consumes: merge Task 2 e superficie analytics standard Task 3.
- Produces: custom UI non analytics adattata a v0.12.4 senza componenti/copy custom analytics.

- [ ] **Step 1: Portare componenti non analytics e i contratti API aggiornati.** Coprire settings/connessioni, chat, workspace, skills e funzioni custom rimaste nel manifest; non introdurre cambi non richiesti nei componenti Analytics.
- [ ] **Step 2: Risolvere traduzioni file per file.** Mantenere le chiavi custom usate fuori analytics e rimuovere soltanto chiavi usate dalle customizzazioni analytics escluse.
- [ ] **Step 3: Eseguire i test frontend mirati e il type check.**

```bash
rtk npm run test:frontend -- --run src/lib/components/admin/Settings/Connections.save.test.ts src/lib/apis/openai/index.test.ts
rtk npm run check
```

Atteso: Vitest raccoglie i test selezionati e passa; aggiungere al comando i test specifici introdotti per ogni altra UI custom preservata. Svelte/TypeScript non introduce nuove diagnostiche. Non usare `--passWithNoTests` come prova.

## Task 8: Verifica finale e handoff del candidato

**Files:**
- Modify: `CHANGELOG.md`
- Update: `patches/integration-v0.12.4-decisions.md`
- Create: `patches/integration-v0.12.4-customizations-from-main.patch` solo come artefatto del delta effettivo e replayable

**Interfaces:**
- Consumes: task 1-7 completati.
- Produces: candidato verificato sul branch `integration-v0.12.4`; nessuna release o deploy.

- [ ] **Step 1: Eseguire le suite backend e frontend documentate.**

```bash
rtk proxy python -m pytest -q backend/
rtk npm run test:frontend
rtk npm run check
```

Atteso: test passati; eventuali skip/limiti sono riportati esplicitamente, mai interpretati come prova di feature.

- [ ] **Step 2: Verificare requisito analytics.** Comparare le superfici analytics-only con l'upstream v0.12.4, controllare che le route custom non esistano e che i dati storici non siano stati cancellati.
- [ ] **Step 3: Verificare copertura NIS2.** Eseguire i test dell'appendice A e salvare nell'handoff il conteggio route totali/classificate/esentate; il numero di route non classificate deve essere zero.
- [ ] **Step 4: Eseguire `rtk git diff --check` e rigenerare la patch dal delta corrente.** Non applicare patch storiche in sequenza e non includere archivi/documenti come codice.
- [ ] **Step 5: Aggiornare changelog e decision ledger con esiti e prove.** Indicare le differenze preservate, quelle eliminate perché analytics e ogni limitazione di test/build.

**Handoff:** richiedere review del candidato. Nessun tag (il suffisso data YYMMDD), immagine Docker, push o PR finché non vengono richiesti e approvati separatamente.

## Appendice A: Inventario route upstream e copertura NIS2

Inventario read-only svolto dal subagent `Endpoint inventory` (`general-purpose`) con Codegraph e confronto dei due tree. I router `apps` e `search` sono montati upstream (`main.py:894, 898`) ma non nel fork. La tabella elenca le 19 route/method introdotte o senza regole semantiche equivalenti nel fork; gli ID mostrati sono proposte di azione da fissare nella matrice NIS2.

| Metodo e route | Azione NIS2 da classificare | Dati e verifiche |
|---|---|---|
| `GET /api/v1/apps` | `APP_LIST_READ` | Read a severità bassa; actor/outcome, nessun body. |
| `GET /api/v1/apps/{app_id}` | `APP_READ` | Read a severità bassa; record access grants senza dettagli sensibili. |
| `POST /api/v1/apps/manifest/preview` | `APP_MANIFEST_PREVIEW` | Actor/outcome; non registrare manifest/body o segreti. |
| `POST /api/v1/apps` | `APP_CREATE` | Actor/outcome; app ID dal risultato strutturato, mai API key/body. |
| `PATCH /api/v1/apps/{app_id}` | `APP_UPDATE` | Actor, app ID e outcome; accesso/permessi trattati come modifica sensibile. |
| `POST /api/v1/apps/{app_id}/connect` | `APP_CONNECT` | Actor/app ID/outcome; escludere credenziali e API key. |
| `DELETE /api/v1/apps/{app_id}` | `APP_DELETE` | Actor/app ID/outcome. |
| `POST /api/v1/apps/{app_id}/interactions` | `APP_INTERACTION` | Evento minimale; niente contesto, input, output o messaggi. |
| `GET /api/v1/channels/{channel_id}/apps` | `CHANNEL_APPS_READ` | Read a severità bassa; channel ID, actor/outcome. |
| `POST /api/v1/channels/{channel_id}/apps` | `CHANNEL_APP_ADD` | Modifica membership sensibile; registrare channel e app ID, actor/outcome. |
| `DELETE /api/v1/channels/{channel_id}/apps/{app_id}` | `CHANNEL_APP_REMOVE` | Modifica membership sensibile; registrare entrambi gli ID, actor/outcome. |
| `POST /api/v1/channels/{id}/members/mute` | `CHANNEL_MEMBER_MUTE` | Actor, channel ID e outcome. |
| `POST /api/v1/channels/{id}/access/update` | `CHANNEL_ACCESS_UPDATE` | Modifica ACL ad alta rilevanza; actor, channel ID e outcome. |
| `GET /api/v1/files/user/search` | `FILES_SEARCH_READ` | Read a bassa severità; mai termini, contenuti o risultati; non classificarla come file ID `user`. |
| `GET /api/v1/files/user/count` | `FILES_COUNT_READ` | Read a bassa severità con actor/outcome; non escludere per frequenza senza prova e decisione documentata. |
| `GET /api/v1/search` | `WORKSPACE_SEARCH_READ` | Actor/outcome; non registrare query o contenuti restituiti. |
| `PATCH /api/v1/chats/{id}/params` | `CHAT_PARAMS_UPDATE` | Modifica con actor, chat ID e outcome; escludere prompt/parametri sensibili dal body. |
| `POST /api/v1/calendars/{calendar_id}/access/update` | `CALENDAR_ACCESS_UPDATE` | Modifica ACL sensibile; actor, calendar ID e outcome. |
| `POST /api/v1/configs/interface/visibility` | `INTERFACE_VISIBILITY_UPDATE` | Modifica configurazione admin; actor/outcome e chiave, senza valori sensibili. |

### Route esistenti con comportamento cambiato da ricontrollare

- `POST /api/v1/channels/{id}/members/active`: deve avere regola semantica esplicita. Rimozione membri, update canale, update ACL e delete invalidano lo stato di cifratura; il test deve attestare evento/action e invalidazione, mai il contenuto cifrato.
- Auth admin config/LDAP, create/delete utenti SCIM, update contenuto file e create/update/access skills risultano già classificati nel fork: verificare che route e regole restino valide dopo il merge.
- MFA/SCIM non aggiungono route nuove secondo il diff d'inventario, ma i relativi outcome/attori e le migrazioni auth vanno mantenuti.
- Health è già escluso dal custom access logger; le eccezioni static/OpenAPI/polling/socket devono rimanere puntuali e documentate. La classificazione generica del middleware upstream non dimostra copertura NIS2.
- Il middleware NIS2 è effettivamente installato dal fork con `setup_access_logging(app)` in `main.py`; il corrispondente wiring manca nel `main.py` upstream v0.12.4 e va ripristinato. È distinto da `AuditLoggingMiddleware`, installato condizionalmente tramite `AUDIT_LOG_LEVEL`.

### Test richiesti per l'appendice

- Estendere `backend/open_webui/test/middleware/access_log_route_coverage.py` e il wrapper `test_access_log_route_coverage.py`: ogni method/path montato deve comparire nel catalogo o in un'esenzione motivata; fallback generici non contano come copertura business.
- Estendere `backend/open_webui/test/middleware/test_access_log.py`: test per nuove azioni, object ID, actor/outcome, read sensibili, redazione body e risposta non riuscita.
- Aggiungere test ASGI sul `main.app` configurato: verificare che `setup_access_logging(app)` resti installato nel merge e che le nuove route producano gli eventi attesi.
- Per `apps` e `/channels`, verificare anche la redazione nel distinto `AuditLoggingMiddleware` di `backend/open_webui/utils/audit.py`; la sola redazione password non è sufficiente.
