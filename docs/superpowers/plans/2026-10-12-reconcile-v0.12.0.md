# Riconciliazione upstream v0.12.0 - Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** integrare upstream v0.12.0 nel fork GIADA preservando le funzionalita
custom pubblicate e producendo un candidato verificato, non una release automatica.

**Architecture:** worktree isolato e merge a tre vie di due SHA immutabili, con
un unico commit di merge dopo la risoluzione completa dei conflitti. Correzioni
semantiche, regressioni, migrazioni e documentazione seguono in task verificabili;
le personalizzazioni si valutano dal delta attuale, non da vecchi seed.

**Tech Stack:** Git, FastAPI/Python, pytest, SQLAlchemy/Alembic, SvelteKit/TypeScript,
Vitest, npm, Docker.

**Spec:** `docs/superpowers/specs/2026-10-12-reconcile-v0.12.0-design.md`.

## Global Constraints

- Fork: `6d4a5ebd5fb3f1f0c4c3de210fe5da8395c37153`.
- Upstream: `15818d88fd7bde1b73de33590f50d15d21e8d7c1`.
- Base comune: `8bd8b4fac5e059578ac0c74b3c18d11139f88b7d`.
- Branch: `integration-v0.12.0`; mai eseguire il merge nel worktree sporco di `main`.
- Non importare cambi non committati di altri worktree. Il commit del branch
  `fix/user-context-forwarding` e gia antenato del main fissato; il nome branch
  non identifica da solo una feature da portare.
- Risolvere tutti i conflitti prima del commit atomico di merge; nessun commit
  parziale mentre `MERGE_HEAD` e presente.
- Non modificare identificativi/parent di revisioni Alembic gia pubblicate.
- Database, storage, provider, embedding e OAuth di test devono essere isolati
  o mock; vietati production DB, credenziali reali e download impliciti.
- `WRITE_OTHER`/`DELETE_OTHER` non provano copertura semantica NIS2.
- Non registrare token, recovery code, password, claim completi o payload.
- Non retrocedere dipendenze upstream per riprodurre vecchi pin custom;
  lockfile rigenerato con npm, non risolto manualmente.
- Conservare i requisiti runtime dei manifest target; installare dipendenze
  solo se un comando di verifica ne segnala la mancanza o dopo modifica manifest.
- Tutti i commit esecutivi includono
  `Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>`.
- Nessun push, PR, deploy, tag o release in questo piano senza autorizzazione
  successiva. Il target PR documentato e `dev`, non `main`: al momento nessuna
  ref locale/remota `dev` e disponibile, quindi risolvere il target prima di una PR.

## Review Focus

1. Sessione revocata o MFA incompleta: negare accesso e live updates, mantenendo
   un audit di fallimento senza dati di autenticazione.
2. Chat condivisa con autore diverso dal proprietario: attribuire audit e
   statistiche all'identita corretta senza concedere modifica dei messaggi altrui.
3. Upgrade di un DB fork con Prompt Insights gia popolato: preservare dati e
   revisioni mentre si applicano nuove migrazioni MFA/cronologie/gruppi.
4. Tool round multipli, routing o risposta interrotta: preservare selected/requested
   model e metrica token senza doppio conteggio o audit di successo fittizio.
5. Salvataggio connessione respinto o catalogo traduzioni modificato da entrambe
   le parti: nessun evento di successo anticipato e nessuna perdita di chiavi custom.

## Evidenza di pianificazione

| Misura | Risultato |
| --- | --- |
| Commit esclusivi fork / upstream | 151 / 584 |
| Percorsi modificati fork / upstream rispetto alla base | 217 / 542 |
| Intersezione attuale | 99: 35 non-i18n + 64 traduzioni |
| Conflitti della simulazione merge-tree | 76: 12 non-i18n + 64 traduzioni |
| Inventario storico v0.11.4 | 150 percorsi, 38 overlap: NON il delta attuale |

La simulazione non esegue l'app e non modifica index/worktree; scrive oggetti Git.
I 12 conflitti non-i18n sono elencati nello spec. Assenza di conflitto testuale
non autorizza a saltare i gate semantici.

## Modelli e coordinamento dei subagent

La preparazione usa analisti `general-purpose` con `gpt-6.1-sol` per backend,
frontend e grafo migrazioni; `claude-sonnet-5.5` per il controllo delimitato i18n.
Per l'esecuzione:

| Lavoro | Agent / modello | Perche |
| --- | --- | --- |
| Merge atomico, DB, auth/NIS2, chat/tooling | `general-purpose` / `gpt-6.1-sol` | Interfacce interdipendenti e regressioni ad alto impatto |
| UI Analytics, traduzioni e documentazione | `general-purpose` / `claude-sonnet-5.5` | Compiti delimitati, con contratto e test gia specificati |
| Comandi test/build e raccolta diagnostiche | `task` / `claude-haiku-5.5` | Esecuzione deterministica, nessuna decisione architetturale |
| Review semantica dei commit e gate finale | `code-review` / `gpt-6.1-sol` | Autorizzazioni, privacy, compatibilita e assenza di perdite custom |

Non avviare un workflow massivo o un worker pool. Un implementer nuovo per
task; test runner solo se libera l'implementer per lavoro indipendente.
In fase di merge pendente usare **un unico writer**: task 2 non si puo distribuire
fra agent che modificano simultaneamente lo stesso index. Le analisi read-only
possono essere parallele; le correzioni auth/chat condividono middleware e sono
sequenziali. Ogni handoff contiene spec, SHA, file posseduti, test attesi e limiti.
Se il modello indicato non e disponibile, dichiararlo e usare un modello
disponibile di capacita equivalente; non ridurre silenziosamente i gate.

---

### Task 1: Congelare baseline e ambiente isolato

**Files:**
- Create: `patches/integration-v0.12.0-customizations-files.txt`.
- Create: `patches/integration-v0.12.0-decisions.md`.
- Artefatti temporanei: directory `files/reconcile-v0.12.0/` del workspace di sessione.

**Interfaces:**
- Consumes: i tre SHA del Global Constraints.
- Produces: worktree pulito, inventario completo del delta attuale e tabella
  `path | keep/adapt/drop-upstream-equivalent | motivo | test | task`.

**Prerequisiti:** approvazione del piano; skill `using-git-worktrees`.

- [ ] **Step 1: Verificare ref e stato senza modificare il worktree originale.**

```bash
rtk git rev-parse main origin/main upstream/v0.11.4 upstream/v0.12.0
rtk git merge-base 6d4a5ebd5fb3f1f0c4c3de210fe5da8395c37153 15818d88fd7bde1b73de33590f50d15d21e8d7c1
rtk git worktree list --porcelain
rtk git status --short --branch
```

Atteso: SHA dichiarati e base `8bd8b4fac...`. Se la baseline si e mossa,
rigenerare l'analisi prima di continuare. Registrare i file sporchi preesistenti;
non stasharli, cancellarli o importarli.

- [ ] **Step 2: Creare il worktree da upstream.**

Dal repository originale, soltanto se path e branch non esistono:

```bash
rtk git worktree add -b integration-v0.12.0 ../open-webui-integration-v0.12.0 15818d88fd7bde1b73de33590f50d15d21e8d7c1
```

Atteso: nuovo worktree pulito. Se esiste gia, ispezionarlo e riusarlo solo
se compatibile; non sovrascrivere altri task. Eseguire i comandi successivi
nel nuovo worktree; non assumere che `cd` persista fra tool call.

- [ ] **Step 3: Esportare il delta attuale usando output Git non filtrato.**

```bash
rtk proxy git diff --name-only 8bd8b4fac5e059578ac0c74b3c18d11139f88b7d 6d4a5ebd5fb3f1f0c4c3de210fe5da8395c37153
rtk proxy git diff --binary 8bd8b4fac5e059578ac0c74b3c18d11139f88b7d 6d4a5ebd5fb3f1f0c4c3de210fe5da8395c37153 -- . ':(exclude)patches/**' ':(exclude)docs/**' ':(exclude).superpowers/**'
```

Salvare il primo output nell'inventario (217 percorsi); il secondo nel workspace
di sessione come evidenza, non come patch da applicare automaticamente.
Usare `rtk proxy` per output destinato a patch/manifests: un filtro RTK puo
alterare il contenuto. Classificare anche file auto-merged, test e traduzioni;
gli archivi storici restano provenienza e non si riapplicano uno dopo l'altro.

- [ ] **Step 4: Preparare ambienti di test e baseline diagnostiche.**

Usare Python 3.11/3.12 e Node compatibile col manifest target; provider mock,
DB temporaneo e data dir temporanea. Acquisire le diagnostiche upstream sullo
SHA target e quelle custom sullo SHA fork prima di attribuire fallimenti al merge.
Non creare dump di dati reali nella repository. Gli import possono avviare
migrazioni/caricare `.env`, e variabili DB separate possono sovrascrivere l'URL.
Prima della collection predisporre un harness dedicato che blocchi rete/download
(non un nuovo conftest globale che alteri suite non pertinenti), con data/cache/temp
in directory di sessione e lifespan reale disabilitato. Test Alembic usano database
file temporanei propri; non affidarsi a `sqlite:///:memory:` fra connessioni diverse.

Tutti i comandi pytest dei task 3-7 vanno eseguiti in un processo con queste
variabili, usando il Python del venv 3.11/3.12, non Python globale non verificato:
`PYTHONPATH=backend:backend/open_webui/test`, `PYTHONDONTWRITEBYTECODE=1`,
`PYTHON_DOTENV_DISABLED=1`, `ENABLE_DB_MIGRATIONS=false`, `OFFLINE_MODE=true`,
`HF_HUB_OFFLINE=1`, `TRANSFORMERS_OFFLINE=1`, `ENABLE_VERSION_UPDATE_CHECK=false`,
`PROMPT_INSIGHTS_ENABLED=false`, `WEBUI_SECRET_KEY=reconciliation-tests-only`.
`DATABASE_URL` deve puntare al DB disposable; svuotare `DATABASE_TYPE`,
`DATABASE_USER`, `DATABASE_PASSWORD`, `DATABASE_HOST`, `DATABASE_PORT`,
`DATABASE_NAME`, `DATABASE_SCHEMA` e disabilitare IAM token auth. Impostare
`DATA_DIR`, `CACHE_DIR`, `TMPDIR` ai percorsi temporanei espliciti. Le fixture
che testano migrazioni/scheduler riattivano solo il comportamento mockato necessario.
Ogni test runner riceve ambiente completo: un export/cd di un tool call non persiste.

**Checkpoint:** inventario e matrice sono artefatti del prossimo commit di merge;
non committarli prima di iniziare l'integrazione, evitando parent upstream
artificiali. Nessuna modifica applicativa in questo task.

### Task 2: Produrre un merge atomico coerente

**Files:**
- Modify: i 12 conflitti non-i18n dello spec.
- Modify: `src/lib/i18n/locales/*/translation.json` (64 conflitti).
- Verify: tutti i 35 overlap non-i18n, inclusi quelli auto-merged.
- Create: gli artefatti definiti nel task 1, dopo il merge.

**Interfaces:**
- Consumes: worktree e matrice task 1.
- Produces: commit con entrambi gli SHA originali nell'ancestry, nessun entry
  unmerged e candidato importabile per i task semantici successivi.

- [ ] **Step 1: Avviare il merge nel worktree isolato.**

```bash
rtk git merge --no-commit --no-ff 6d4a5ebd5fb3f1f0c4c3de210fe5da8395c37153
rtk proxy git diff --name-only --diff-filter=U
```

Atteso: merge pendente e i 76 conflitti gia simulati. Exit nonzero dovuto ai
conflitti e previsto: controllare esplicitamente `MERGE_HEAD` e inventario,
non nascondere qualsiasi errore con `|| true`.

- [ ] **Step 2: Risolvere backend mantenendo l'architettura upstream.**

In ordine: `main.py`/`events.py`; `oauth.py`; `utils/middleware.py`;
`routers/automations.py`/`folders.py`; `retrieval/utils.py`.
Trasferire i soli comportamenti custom ancora necessari, non copiare il vecchio
file completo. Verificare anche auth/sessioni/chat/audit/migrazioni auto-merged.
La risoluzione include migrazioni e compatibilita semantica, non soltanto
import/collection. I task 3-8 sono sottogate obbligatori prima del commit:
non lasciare MFA, privacy audit o schema incompatibile per un hardening futuro.

- [ ] **Step 3: Risolvere UI e cataloghi per comportamento/chiave.**

Mantenere Analytics routing/Prompt Insights e nuove colonne input/output token,
unica tabella model usage, scroll upstream e filtro group upstream.
Unire le 64 traduzioni per chiave; per conflitti su una chiave custom usata
dalla UI conservare la traduzione corretta e i placeholder originali.
Non scegliere in blocco un catalogo `ours` o `theirs`.

- [ ] **Step 4: Risolvere metadati e rigenerare il lockfile.**

Tenere versione applicativa upstream `0.12.0` fino al task release metadata;
preservare dipendenze target e quelle custom giustificate. Rigenerare
`package-lock.json` col package manager. Integrare il changelog upstream
con le note storiche del fork senza sostituire la sezione v0.12.0.

- [ ] **Step 5: Provare completezza e smoke test.**

```bash
rtk proxy git diff --name-only --diff-filter=U
rtk git diff --check
rtk proxy git grep -n -E '^(<<<<<<< |=======|>>>>>>> )' -- '*.py' '*.svelte' '*.ts' '*.json' '*.md'
```

Atteso: nessun percorso unmerged, nessun marker reale (verificare eventuali
separatori Markdown legittimi), nessun errore whitespace. Eseguire i test
custom pertinenti dei task seguenti sul candidato; se falliscono per
incompatibilita del merge, correggere prima del commit.

- [ ] **Step 6: Committare il merge atomico e verificarne i parent.**

Stage solo file del merge e artefatti previsti, non file del worktree originale.
Messaggio `merge: reconcile upstream v0.12.0` con trailer Copilot. Poi:

```bash
rtk proxy git show -s --format='%P' HEAD
rtk git merge-base --is-ancestor 15818d88fd7bde1b73de33590f50d15d21e8d7c1 HEAD
rtk git merge-base --is-ancestor 6d4a5ebd5fb3f1f0c4c3de210fe5da8395c37153 HEAD
```

Atteso: due parent e due exit code 0; nessun `MERGE_HEAD` residuo.
Review indipendente del merge prima dei task successivi.

### Task 3: Collegare le migrazioni senza riscrivere la storia

**Dipendenze:** task 1 e risoluzione testuale del task 2; eseguire prima del commit del task 2.
**Modello:** `general-purpose` / `gpt-6.1-sol`; unico writer coordinato durante il merge.

**Files:**
- Create: `backend/open_webui/migrations/versions/<revision>_merge_v0120_fork_heads.py` (nome generato da Alembic).
- Create: `backend/open_webui/test/models/test_migration_v0120_reconciliation.py`.
- Verify: `backend/open_webui/migrations/env.py`, `backend/open_webui/config.py`, `backend/open_webui/internal/db.py` e tutte le revisioni pubblicate.

**Interfaces:** Consumes: grafo Alembic combinato; produces: nuova head unica senza DDL proprio e upgrade compatibile con entrambe le storie.

- [ ] **Step 1: Aggiungere test del grafo e verificarne il fallimento.** `test_single_head_and_published_parents_unchanged` deve riconoscere assegnazioni semplici e annotate, non trovare duplicati/cicli/parent mancanti e confrontare i parent pubblicati con i blob originali. Prima della nuova merge revision sono attese due head: `6c7d8e9f0a1b`, `b8f2c6d91a04`. `config.py` usa attualmente `head` sia nel fork (:75) sia upstream (:76), non `heads`: il vecchio commit multi-head non rappresenta lo stato attuale. Conservare le protezioni PostgreSQL schema/search_path upstream di `migrations/env.py:77-99` e verificare che gli errori startup non siano mascherati dal semplice logging.
- [ ] **Step 2: Generare la merge revision.** Con ambiente isolato del task 1, usare `python -m alembic -c backend/alembic.ini merge -m 'merge v0.12.0 fork heads' 6c7d8e9f0a1b b8f2c6d91a04` dalla directory compatibile con `script_location` dell'ini; controllare il percorso prima del comando. `down_revision = ('6c7d8e9f0a1b', 'b8f2c6d91a04')`, `upgrade()`/`downgrade()` vuoti; nessuna modifica ai parent precedenti.
- [ ] **Step 3: Provare upgrade su DB disposable.** `test_upgrade_preserves_fork_data` crea dati sentinel Prompt Insights e applica l'upgrade dal fork; `test_upgrade_from_upstream_head` prova la storia opposta; `test_empty_database_upgrade` prova un database vuoto. Verificare tabelle PI/history, colonne MFA/session stamp, dati e singola head. Per PostgreSQL verificare anche l'esistenza dell'indice pending files: il raggiungimento della head non prova l'esecuzione dell'indice.
- [ ] **Step 4: Eseguire** `rtk proxy python -m pytest -q backend/open_webui/test/models/test_migration_v0120_reconciliation.py backend/open_webui/test/models/test_prompt_insights_migration.py`. Atteso: test raccolti e passati. Registrare separatamente SQLite e istanze server disposable effettivamente provate; rollback completo tramite restore, non downgrade distruttivo su dati reali.

### Task 4: Integrare MFA, sessioni e doppio audit NIS2

**Dipendenze:** task 3; obbligatorio prima del commit del task 2.
**Modello:** `general-purpose` / `gpt-6.1-sol`.

**Files:**
- Modify: `backend/open_webui/utils/oauth.py`, `utils/audit.py`, `utils/auth.py`, `middleware/access_log.py`, `routers/mfa.py`, `routers/users.py`, `test/middleware/access_log_route_coverage.py`, `test/middleware/test_access_log.py`, `test/middleware/test_access_log_route_coverage.py` (tutti sotto `backend/open_webui/`).
- Create: `backend/open_webui/test/routers/test_v0120_mfa_oauth.py`.

**Interfaces:** Consumes: `create_signin_response`, `create_session_response`, `get_human_user`, session stamp upstream; produces: invalidazione cache audit conservata, login completato distinto da challenge/pending e inventario HTTP piu verifica WebSocket separata.

- [ ] **Step 1: Aggiungere test che falliscono sul candidato non adattato.** `test_pending_mfa_has_no_application_session`; `test_oauth_mfa_emits_one_completed_login`; `test_revoked_stamp_denies_live_and_derived_access`; `test_auth_body_never_logged`; `test_role_change_evicts_context_and_disconnects`. Assert: challenge non accetta accesso API, nessun successo login anticipato su 200 challenge/302 callback, token/recovery code/password assenti in entrambi i layer audit, cache invalidata dopo aggiornamenti OAuth, sessioni revocate negate.
- [ ] **Step 2: Trasferire gli hook senza ripristinare auth legacy.** Conservare i token `typ`, `session_stamp`, `auth_method`, `auth_time`, `mfa_verified`, primo admin protetto e revoca upstream; spostare invalidazione cache sul salvataggio OAuth effettivo. Non usare `amr/acr` IdP come prova automatica di MFA locale. Conservare le nuove esclusioni dei body auth/OAuth in `utils/audit.py` e sanificare l'eventuale token OIDC prima di qualunque log.
- [ ] **Step 3: Estendere regole e test parametrizzati con questo contratto.** Prefissi HTTP reali da confermare nell'inventario runtime; regole letterali prima dei parametri e catch-all. Le azioni proposte sono decisioni della riconciliazione, non nomi gia upstream:

| Prefisso/operazione | Metodo | Azione proposta | Security-critical |
| --- | --- | --- | --- |
| `/api/v1/auths/mfa/challenge` | POST | `AUTH_MFA_CHALLENGE` | si |
| `/api/v1/auths/mfa/enroll/start`, `/enroll/confirm` | POST | `AUTH_MFA_ENROLL_START`, `AUTH_MFA_ENROLL_CONFIRM` | si |
| `/api/v1/auths/mfa/verify`, `/replace`, `/recover` | POST | `AUTH_MFA_VERIFY`, `AUTH_MFA_REPLACE`, `AUTH_MFA_RECOVER` | si |
| `/api/v1/auths/mfa/recovery/codes` | POST | `AUTH_MFA_RECOVERY_ROTATE` | si |
| `/api/v1/users/{user_id}/sessions/revoke` | POST | `AUTH_SESSIONS_REVOKE` | si |
| functions/tools `/id/{id}/history/{history_id}` | DELETE | `FUNCTION_HISTORY_DELETE`, `TOOL_HISTORY_DELETE` | si |
| functions/tools `/id/{id}/update/version` | POST | `FUNCTION_VERSION_RESTORE`, `TOOL_VERSION_RESTORE` | si |
| models `/model/history/{history_id}`, `/model/update/version` | DELETE/POST | `MODEL_HISTORY_DELETE`, `MODEL_VERSION_RESTORE` | si |
| skills history/version/clone/import | DELETE/POST | `SKILL_HISTORY_DELETE`, `SKILL_VERSION_RESTORE`, `SKILL_CLONE`, `SKILL_IMPORT` | si |
| skills `/import/preview`, `/load/url` | POST | `SKILL_IMPORT_PREVIEW`, `SKILL_URL_LOAD` | si (outbound/input processing; non creazione persistita) |
| MFA status; history/version/file; group members; tool specs | GET | `AUTH_MFA_STATUS`, `WORKSPACE_HISTORY_READ`, `SKILL_FILE_READ`, `GROUP_MEMBERS_READ`, `TOOL_SPECS_READ` | no; letture comunque esplicite |

Non loggare contenuto history, codici MFA o payload dei file. Oggetto audit: solo tipo/ID sanificato e outcome. Per route create nel delta non presenti qui, assegnare azione/esenzione motivata nella matrice, non whitelist generica.

- [ ] **Step 4: Verificare variazioni non soltanto nuove route.** Sharing chat, policy admin MFA, `/ollama/verify` admin-only, path converter leaderboard e WebSocket `/api/v1/audio/realtime`. L'inventario attuale usa `APIRoute` e non copre WebSocket: test dedicati per permission call, revoca sessione e fine connessione. `build_report()` e sincrono: tutte le sei liste del report devono essere vuote dopo aggiornamento delle aspettative, incluse mutazioni generiche e regole morte.
- [ ] **Step 5: Eseguire** `rtk proxy python -m pytest -q backend/open_webui/test/middleware/test_access_log.py backend/open_webui/test/middleware/test_access_log_route_coverage.py backend/open_webui/test/routers/test_v0120_mfa_oauth.py backend/open_webui/test/routers/test_v0114_admin_guards.py`. Atteso: successo, nessun download/servizio reale; test status 401/422/429/503 e attribuzione attore inclusi.

### Task 5: Preservare routing, Analytics backend e ownership chat

**Dipendenze:** task 4; obbligatorio prima del commit del task 2.
**Modello:** `general-purpose` / `gpt-6.1-sol`.

**Files:**
- Modify: `backend/open_webui/utils/middleware.py`, `models/chat_messages.py`, `routers/analytics.py`, `routers/chats.py`, `routers/folders.py`, `events.py`.
- Modify: `backend/open_webui/test/middleware/test_routing_usage_merge.py`, `test/models/test_chat_messages_token_usage_unit.py`, `test/routers/test_analytics_routing_unit.py`.
- Create: `backend/open_webui/test/routers/test_v0120_shared_chat_analytics.py`.

**Interfaces:** Consumes: session/actor contract del task 4 e `merge_routing_usage`; produces: requested/selected model persistiti senza doppio conteggio, ownership upstream conservata e input/output token disponibili alla UI.

- [ ] **Step 1: Caratterizzare streaming/non-streaming.** Aggiornare lo stub `test_chat_messages_token_usage_unit.py:36-42` per il nuovo import upstream `group_user_memberships`; preservare `_routing_match`, `_summarize_routing_pairs` e `merge_routing_usage` usati dai test custom. Estendere test per routing metadata presenti anche dopo update successivi usage, round tool multipli, risposta interrotta e provider senza timing. Verificare token input/output separati, TTFT/token-s mancanti non convertiti in valori fittizi, filtri user/model/requested/selected in entrambe le modalita e timestamp upstream anche millisecondi.
- [ ] **Step 2: Testare chat condivisa.** `test_shared_reply_preserves_owner_settings_and_actor` e `test_collaborator_cannot_edit_others_message`: autore messaggio distinto dal proprietario, audit attribuito al chiamante, impostazioni owner intatte. Registrare la semantica analytics scelta e compatibile coi dati esistenti; non attribuire tutte le risposte al proprietario soltanto perche possiede la chat.
- [ ] **Step 3: Integrare il ciclo upstream mantenendo gli hook GIADA.** Collocare il merge routing in tutti gli update usage streaming/non-streaming; mantenere revoca, compaction, approval, tool dinamici e settings owner upstream. Non riscrivere la pipeline intera con il blob fork.
- [ ] **Step 4: Eseguire** `rtk proxy python -m pytest -q backend/open_webui/test/middleware/test_routing_usage_merge.py backend/open_webui/test/models/test_chat_messages_token_usage_unit.py backend/open_webui/test/routers/test_analytics_routing_unit.py backend/open_webui/test/routers/test_v0120_shared_chat_analytics.py`. Atteso: tutti verdi e richieste provider mockate.

### Task 6: Prompt Insights, automazioni e lifespan

**Dipendenze:** task 3-5; obbligatorio prima del commit del task 2.
**Modello:** `general-purpose` / `gpt-6.1-sol`.

**Files:**
- Modify: `backend/open_webui/main.py`, `utils/automations.py`, `routers/automations.py`, `models/prompt_insights.py`, `prompt_insights/pipeline.py` solo se necessario.
- Modify: `backend/open_webui/test/utils/test_automations_audit.py`, `test/models/test_prompt_insights_scheduler.py`, `test/models/test_prompt_insights_transactions.py`, `test/models/test_prompt_insights_pipeline.py`, `test/routers/test_analytics_prompt_insights.py`.

**Interfaces:** Consumes: `execute_automation(app, automation, trigger='scheduler')`, auth stamp upstream e scheduler PI; produces: run manuale/scheduler distinti, job PI singolo tracciato e shutdown pulito.

- [ ] **Step 1: Aggiornare mock e test prima degli adattamenti.** Stub `Auths.get_auth_by_id` oltre a `create_token`; owner inattivo/revocato negato, token automazione con `typ='automation'` e stamp corretto, trigger manuale non duplica l'audit scheduler. Testare esito failure senza falso success.
- [ ] **Step 2: Integrare lifecycle.** Conservare timer poll/jitter/claim batch upstream; task PI non bloccante, claim atomico unico, rollback transazioni e task cancellato/atteso allo shutdown. Test: due claim concorrenti producono un solo run, scrub avviene prima dell'embedding, fallimento non lascia cluster/trend parziali, API PI non accessibile a non-admin.
- [ ] **Step 3: Registrare baseline funzionali reali.** Il riferimento PI a `generate_completion` e il comportamento fallback vanno caratterizzati: non presentare etichettatura ML come verificata se fallback/skipped. Verificare dipendenze ML dichiarate/transitive, nessuna installazione preventiva per nascondere skip. `GapAnalysis` UI riceve attualmente lista vuota: non aggiungere una nuova feature in questa riconciliazione.
- [ ] **Step 4: Eseguire** `rtk proxy python -m pytest -q backend/open_webui/test/utils/test_automations_audit.py backend/open_webui/test/models/test_prompt_insights_schema.py backend/open_webui/test/models/test_prompt_insights_migration.py backend/open_webui/test/models/test_prompt_insights_scheduler.py backend/open_webui/test/models/test_prompt_insights_transactions.py backend/open_webui/test/models/test_prompt_insights_pipeline.py backend/open_webui/test/models/test_prompt_insights_privacy.py backend/open_webui/test/models/test_prompt_insights_ml.py backend/open_webui/test/routers/test_analytics_prompt_insights.py`. Atteso: successo; skip ML documentati, non equivalenti a feature provata.

### Task 7: Retrieval, MCP e refactoring audio

**Dipendenze:** task 1 e risoluzione testuale del task 2; prima del commit atomico. Analisi indipendente parallelizzabile, scritture serializzate con il merge writer.
**Modello:** `general-purpose` / `gpt-6.1-sol`.

**Files:**
- Modify: `backend/open_webui/retrieval/utils.py`, `retrieval/web/utils.py`, `utils/mcp/client.py`, `routers/audio/__init__.py`.
- Modify: `backend/open_webui/test/retrieval/test_web_loader_safety.py`.
- Create: `backend/open_webui/test/utils/test_mcp_v0120.py`, `backend/open_webui/test/routers/test_v0120_audio_validation.py`.

**Interfaces:** Consumes: `_SSRFSafeAdapter`, MCP SDK target `1.27.2`, nuova firma `connect(..., auth=None)`; produces: loader/transport compatibili e validazione audio custom trasferita dal vecchio modulo al nuovo package.

- [ ] **Step 1: Testare senza rete.** Loader: schemi/URL ambigui, IPv4 embedded, MIME, YouTube short URL, redirect/DNS e `response.close` mockati. MCP: retry 401 soltanto dopo rotazione token, timeout, elicitation validata/cancellata, structuredContent non duplicato; testare firma transport oltre all'alias import. Audio: payload/path rifiutati dal hardening fork restano rifiutati nel package upstream.
- [ ] **Step 2: Integrare cambi upstream senza eliminare guard custom.** Preservare configurazione loader esplicita, sessione SSRF-safe, ordine probe YouTube e cleanup; riportare hardening audio in `routers/audio/__init__.py`, non ricreare il vecchio `audio.py`.
- [ ] **Step 3: Eseguire** `rtk proxy python -m pytest -q backend/open_webui/test/retrieval/test_web_loader_safety.py backend/open_webui/test/utils/test_mcp_v0120.py backend/open_webui/test/routers/test_v0120_audio_validation.py`. Atteso: test raccolti e verdi senza outbound reale.

### Task 8: Analytics UI, connessioni, traduzioni e manifest

**Dipendenze:** task 5 per contratto token; task 2 in fase di risoluzione; prima del commit atomico.
**Modello:** `general-purpose` / `claude-sonnet-5.5`.

**Files:**
- Modify: `src/lib/components/admin/Analytics.svelte`, `Analytics/Dashboard.svelte`, `Analytics/ChartLine.svelte`, `Analytics/Dashboard.test.ts`, `src/lib/apis/openai/index.ts`, `src/lib/components/admin/Settings/Connections.svelte`, `Connections/OpenAIConnection.svelte`, `Connections/OllamaConnection.svelte`, i 64 cataloghi i18n, `package.json`, `package-lock.json`, `CHANGELOG.md`.
- Create: `src/lib/components/admin/Analytics/Dashboard.cross-filter.test.ts`, `Dashboard.token-tooltip.test.ts`, `prompt-insights.lifecycle.test.ts` nella stessa cartella; `src/lib/components/admin/Settings/Connections.save.test.ts`; `src/lib/apis/analytics/index.test.ts`, `src/lib/apis/openai/index.test.ts`; `src/lib/i18n/custom-analytics-translations.test.ts`.

**Interfaces:** Consumes: API Analytics del task 5, callback connessioni awaitable e parser i18n upstream; produces: token tooltip e metriche custom insieme, nessun falso save, cataloghi upstream completi con le 13 chiavi fork.

- [ ] **Step 1: Aggiornare regression test UI.** Test tabella unica e header/celle allineati con nuove colonne input/output: non congelare il vecchio conteggio 10 senza considerare il nuovo schema. Test: tooltip hover/focus/click, Escape/cleanup, valori mancanti, scala percentuale, modello selezionato/requested, richiesta obsoleta ignorata; cambio periodo/gruppo cancella coppia e modello ma conserva utente. Summary/daily oggi non sono globalmente filtrati per user/model: non estendere il comportamento implicitamente. PI polling 5 secondi soltanto con run attivo, stop a conclusione/unmount.
- [ ] **Step 2: Risolvere Analytics per comportamento.** Scroll upstream `overflow-y-auto scrollbar-hover pr-1.5` assorbe il fix fork; conservare localizzazione `ChartLine`, input/output tooltip e correzioni gruppo/hourly upstream insieme a RoutingUsage, Prompt Insights, 1h, TTFT, token/s ed errori custom.
- [ ] **Step 3: Testare i salvataggi connessioni e API errori.** Nessun evento save prima della persistenza; entrambi falliti non emettono successo; successo parziale e rigetto Promise devono avere comportamento esplicito senza falso successo. Preservare `await onSubmit` e refresh. API OpenAI: fallback non-JSON `HTTP <status>` insieme a scelta messaggio stringa upstream; niente array/oggetti come testo errore.
- [ ] **Step 4: Unire i cataloghi usando lo SHA upstream esplicito.** In questo worktree `ours` significa upstream: evitare istruzioni `--theirs` ambigue. Tutte le 13 aggiunte fork sono valori vuoti; partire da ciascun JSON upstream e aggiungere soltanto chiavi custom mancanti, mai sovrascrivere valori non vuoti. Le chiavi sono:

`Clear filter`, `Err%`, `Failed to load analytics data`, `Failed to load routing analytics`, `Filtered by`, `Last 1 hour`, `request errors`, `Time to First Token is shown when provider usage data includes timing information.`, `Tok/s`, `Token/s`, `Token/s is shown when provider usage data includes throughput or duration details.`, `TTFT`, `View details`.

Eseguire `rtk npm run i18n:parse` dopo il merge delle sorgenti (comando mutante), poi verificare JSON senza chiavi duplicate, placeholder, le 13 chiavi usate e nessuna perdita inattesa upstream nei 64 locale. Parser: sort true, defaultValue vuoto, keepRemoved false; rivedere le rimozioni, non accettarle automaticamente.

- [ ] **Step 5: Adottare dipendenze realmente target.** Fork npm cambia solo versione; requirements fork cambia solo commenti. Conservare manifest/lock upstream: nessun pin storico NLTK da reintrodurre; mantenere marker SciPy e headless OpenCV. Rigenerare lock solo dopo modifica manifest. Vincoli target: Node `>=18.13.0 <=22.x.x`, Python `>=3.11,<3.13`. Nel changelog mantenere sezione upstream 0.12.0 e reinserire la sezione fork 0.11.4-260925 in ordine cronologico, senza creare release futura gia dichiarata.
- [ ] **Step 6: Eseguire** `rtk npm run test:frontend -- --run src/lib/components/admin/Analytics src/lib/components/admin/Settings/Connections.save.test.ts src/lib/apis/analytics/index.test.ts src/lib/apis/openai/index.test.ts src/lib/i18n/custom-analytics-translations.test.ts`. Atteso: tutti i file richiesti raccolti e test verdi; `--passWithNoTests` non e evidenza sufficiente.

**Gate comune dei task 3-8:** durante `MERGE_HEAD` nessun commit parziale. Il writer integra tutti i deliverable, esegue le verifiche e torna al task 2 Step 6 per il solo commit atomico. Correzioni ulteriori successive possono essere committate per area con trailer Copilot e test mirati.

### Task 9: Chiudere il gate di qualita e le prove di deployment

**Files:**
- Modify: `patches/integration-v0.12.0-decisions.md`.
- Verify: `Dockerfile`, `docker-compose.yaml`, `.github/workflows/`.
- Evidenze/log: workspace di sessione, non output voluminosi committati.

**Interfaces:**
- Consumes: candidate completo e test dei task 3-8.
- Produces: tabella `comando | exit code | risultato | SHA | baseline issue`,
  digest immagine candidata, elenco configurazioni e piano rollback.

- [ ] **Step 1: Eseguire i test mirati per tutti i task, poi suite aggregate.**

Usare un runner non-watch (`--run` per Vitest), provider mock e database
temporaneo. Registrare anche skip/xfail e il motivo. Se una suite fallisce,
non chiamare il candidato verificato; risolvere i fallimenti introdotti e
riportare i preesistenti riprodotti sullo SHA upstream.

- [ ] **Step 2: Eseguire type-check e formatter non distruttivi.**

```bash
rtk npm run check
rtk git diff --check
```

Atteso: zero diagnostiche nuove rispetto al target upstream. Conservare
anche il conteggio assoluto delle diagnostiche; "zero nuove" non equivale
a "type-check passato". Non usare `npm run lint:frontend` come verifica
non mutante senza considerare il suo auto-fix. Verificare solo i file cambiati
con i formatter gia disponibili, poi esaminare qualsiasi modifica prodotta.

- [ ] **Step 3: Costruire e avviare l'immagine candidata in isolamento.**

Usare il percorso Docker/CI documentato con heap frontend esplicito e Pyodide
gia preparato. Installare/downloadare dipendenze soltanto quando richiesto
dalla build in ambiente controllato. Non modificare globalmente il sistema
per far passare il candidato.

Atteso: build terminata con exit 0; container su porta libera e dati temporanei,
health endpoint responsivo, nuova versione e feature custom visibili.
Riavviare e provare persistenza delle tabelle custom, login, Analytics e
automazioni con provider mock. Fermare il container/helper di verifica al termine.

- [ ] **Step 4: Verificare operativita multi-instance e rollback.**

Le migrazioni upstream richiedono aggiornamento simultaneo delle istanze:
non proporre rolling update sullo stesso database. Se Redis e usato, provare
streaming/approvazioni/ripresa sessione e ACL `PUBLISH`, `SUBSCRIBE`, `PSUBSCRIBE`,
canali `&socketio` e `&socketio#*`. `WEBSOCKET_REDIS_ROOM_CHANNELS=false` e solo
compatibilita messaggi, non deroga al vincolo schema. Se Milvus e usato, fare
backup verificato, spazio per seconda copia e finestra di migrazione al primo
avvio; non aggiornare contemporaneamente il server Milvus. Hybrid nativo
richiede Milvus >=2.5. Verificare `ENABLE_PLUGINS` master switch (anche MCP,
OpenAPI, terminal e direct connections), orjson default e arena: default off
per installazioni nuove, configurazione esistente preservata. Per servizi non usati registrare
`non applicabile` e motivazione, non una verifica fittizia.

Eseguire una prova restore su dati anonimizzati dopo le migrazioni e avviare
l'immagine precedente su quel restore. Non dichiarare rollback affidabile
basandosi solo sul cambio del tag container.

- [ ] **Step 5: Review finale di tutto il branch.**

Un reviewer nuovo riceve spec, piano, delta dal target upstream, matrice delle
217 decisioni e risultati esatti. Controlla autorizzazioni/privacy, merge
semantici puliti, pin, Alembic, i18n e perdite custom. Correggere le osservazioni
materiali e ripetere i test dei file interessati, senza ampliare il perimetro.

**Checkpoint:** nessuna release se ci sono regressioni, head accidentali,
audit generico su nuove mutazioni, build non verificata o backup/restore richiesto
ma non disponibile.

### Task 10: Rigenerare patch e documentare il candidato

**Files:**
- Modify: `patches/README.md`, `CHANGELOG.md`.
- Modify: `package.json`, `package-lock.json` soltanto se viene concordato
  il suffisso della release fork.
- Create: `patches/0001-chore-reconcile-fork-customizations-onto-v0.12.0-base.patch`.
- Modify: `patches/integration-v0.12.0-decisions.md`.

**Interfaces:**
- Consumes: candidato verificato dal task 9.
- Produces: delta finale replayable rispetto allo SHA upstream, note di
  riconciliazione, report verifiche e proposta release senza pubblicazione.

- [ ] **Step 1: Completare la matrice di decisioni.**

Per ogni path applicativo del delta fork originario, indicare il comportamento
preservato/adattato/equivalente upstream e il test che lo prova. Per archivi,
documenti e separatori di formato usare classificazione di provenienza.
Nessun `drop` senza equivalenza provata o decisione di scope esplicita.

- [ ] **Step 2: Aggiornare note e produrre patch non ricorsiva.**

```bash
rtk proxy git diff --binary 15818d88fd7bde1b73de33590f50d15d21e8d7c1 HEAD -- . ':(exclude)patches/**' ':(exclude)docs/**' ':(exclude).superpowers/**'
```

Salvare l'output non filtrato nella nuova patch, dopo aver committato
le modifiche applicative. Documentare le esclusioni: e una patch runtime,
non un backup completo della storia. Verificare `git apply --check` in un
worktree temporaneo pulito sullo SHA target; non applicarla al candidato
gia integrato. Conservare gli archivi precedenti senza riapplicarli.

- [ ] **Step 3: Documentare verifiche e limitazioni reali.**

Riportare per ogni comando eseguito esito e SHA, modello delle review,
revisioni Alembic finali, nuove azioni NIS2, configurazioni plugin/arena/orjson,
Redis/Milvus applicabili e backup/restore. Elencare in modo distinto verifiche
automatiche, manuali, non applicabili e bloccate.

- [ ] **Step 4: Committare solo gli artefatti della riconciliazione.**

Messaggio `docs: document v0.12.0 reconciliation`, trailer Copilot; status pulito
nel worktree candidato. Il worktree `main` mantiene le sue modifiche originali.
Non amendare altri commit o cancellare worktree di altri task.

- [ ] **Step 5: Consegnare il candidato, senza pubblicarlo.**

Il primo source tag della giornata ha formato `v0.12.0-YYMMDD`, con `b`, `c`
solo per iterazioni successive nello stesso giorno. La data e quella reale
della release, non necessariamente il 12 ottobre. L'immagine segue
`{source-tag}-build-YYYYMMDD.NN`. Concordare target PR, metadata e autorizzazione
di pubblicazione prima di crearli; rispettare il template PR esistente senza
spuntare dichiarazioni CLA o approvazioni non fornite dall'utente.

## Handoff

Il piano prepara una riconciliazione, non dichiara che v0.12.0 sia gia integrata.
La revisione di questo documento precede l'esecuzione. Il metodo previsto e
subagent-driven, con writer unico per il merge, task semantici sequenziali e
review indipendente; nessun push/deploy/release implicito.
