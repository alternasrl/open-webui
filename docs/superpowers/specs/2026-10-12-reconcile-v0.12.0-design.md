# Riconciliazione del fork GIADA con upstream v0.12.0

## Obiettivo e perimetro

Portare le funzionalita upstream `v0.12.0` nel fork conservando i comportamenti
custom effettivamente pubblicati su `main`. Questa richiesta produce il disegno
e il piano esecutivo; non autorizza l'esecuzione del merge, modifiche al database,
push, tag o release.

L'analisi e la progettazione usano subagent separati per backend e
frontend/dipendenze. L'esecuzione futura resta subordinata alla revisione del
piano. Non includere modifiche non committate o feature presenti soltanto in
altri branch/worktree.

## Riferimenti immutabili

| Ruolo | Ref informativo | SHA da utilizzare |
| --- | --- | --- |
| Fork pubblicato | `main`, `v0.11.4-260925` | `6d4a5ebd5fb3f1f0c4c3de210fe5da8395c37153` |
| Nuova base upstream | `upstream/v0.12.0` | `15818d88fd7bde1b73de33590f50d15d21e8d7c1` |
| Antenato comune upstream | `upstream/v0.11.4` | `8bd8b4fac5e059578ac0c74b3c18d11139f88b7d` |

Le ref possono muoversi; i confronti e gli artefatti devono registrare gli SHA.
Se `main` cambia prima dell'esecuzione, rigenerare inventario e simulazione,
spiegare il delta e non applicare automaticamente un piano per un altro commit.

## Evidenza e correzione dell'analisi iniziale

Il delta effettivo `base..fork` contiene **217 percorsi**; `base..upstream`
contiene **542 percorsi**. La loro intersezione e di **99 percorsi**, di cui
64 file di traduzione e 35 altri file. La divergenza storica e di 151 commit
fork e 584 upstream.

I precedenti valori 150/38 descrivevano il seed storico della riconciliazione
v0.11.4, non le personalizzazioni attualmente pubblicate. Il seed resta
documentazione di provenienza, non l'input autorevole della nuova integrazione.
Il conteggio lordo include grandi patch archiviate; non misura le dimensioni
del cambiamento applicativo.

Una simulazione con `git merge-tree --write-tree` rileva **76 percorsi in
conflitto**: 64 traduzioni e i seguenti 12 file:

- `CHANGELOG.md`
- `backend/open_webui/events.py`
- `backend/open_webui/main.py`
- `backend/open_webui/retrieval/utils.py`
- `backend/open_webui/routers/automations.py`
- `backend/open_webui/routers/folders.py`
- `backend/open_webui/utils/middleware.py`
- `backend/open_webui/utils/oauth.py`
- `package-lock.json`
- `package.json`
- `src/lib/components/admin/Analytics.svelte`
- `src/lib/components/admin/Analytics/Dashboard.svelte`

Un merge automatico pulito non prova compatibilita semantica. Auth, audit,
chat_messages, migrazioni, retrieval e MCP richiedono verifiche anche quando
non hanno conflitti testuali.

## Decisione di integrazione

**Preferire un merge Git a tre vie in un worktree isolato**, su
`integration-v0.12.0` creato dallo SHA upstream, integrando lo SHA fork
con `--no-commit --no-ff`. L'antenato comune e verificato: Git puo conservare
la storia di entrambi e applicare il delta effettivo senza riprodurre seed
obsoleti o commit storici gia superati.

Risolvere e verificare tutti i conflitti prima di un unico commit di merge.
Migrazioni, MFA/sessioni, privacy audit e test custom essenziali sono gate prima
del commit atomico; soltanto ulteriori correzioni di regressione saranno commit
autonomi. Durante il merge pendente non promettere commit intermedi:
Git non consente commit parziali di un merge.

Alternative considerate:

| Strategia | Vantaggio | Limite |
| --- | --- | --- |
| Merge a tre vie, raccomandato | Storia preservata e delta attuale completo | I conflitti richiedono una risoluzione atomica; gli automerge vanno verificati |
| Replay del delta cumulativo attuale su upstream | Serie custom ricostruibile | Richiede esclusioni esplicite e controllo di completezza; non preserva da solo l'ancestry fork |
| Cherry-pick dei commit storici | Granularita originaria | Reintroduce patch superate e cambi gia upstream; 151 commit non equivalgono a 151 feature indipendenti |

Non usare `ours`/`theirs` sull'intero albero. Nel worktree raccomandato
`ours` e upstream e `theirs` e il fork: non affidarsi a queste etichette
per scegliere un comportamento.

## Invarianti funzionali

### Audit e autenticazione

Preservare classificazione NIS2, outcome, attore e identificatori sanificati,
ordine dei middleware, cache del contesto utente e invalidazione OAuth.
Non ripristinare log storici contenenti token, credenziali, recovery code,
payload o claim completi. Integrare MFA, session stamp e revoca upstream;
una sessione revocata deve perdere anche streaming e attivita derivate.

Ogni nuova route mutante ha un'azione semantica oppure un'esenzione esplicita
e testata. `WRITE_OTHER`/`DELETE_OTHER` non costituiscono copertura semantica.
Le route rimosse non devono lasciare aspettative o regole morte. L'inventario
runtime integra, ma non sostituisce, i test di outcome e autorizzazione.

### Analytics e Prompt Insights

Preservare TTFT, token/s, errori, requested/selected model, cross-filter e
comportamento della tabella model usage. Integrare le colonne input/output
token upstream senza duplicare righe o contare due volte i dati.

Prompt Insights conserva scrub PII, embedding/clustering, backfill iniziale,
claim esclusivo del job e transazioni, API/UI e dati gia memorizzati.
Per chat condivise distinguere autore del messaggio e proprietario della chat;
una scelta sbagliata altera analytics, audit e analisi dei prompt.

### Provider, retrieval e interfaccia

Preservare compatibilita MCP e routing custom nel nuovo ciclo tools/compaction,
comportamenti sicuri del web loader e connessioni salvate soltanto dopo
il completamento della persistenza. Il ramo separato user-context forwarding
non entra implicitamente nella release.

Unire le traduzioni per chiave, mantenendo testi upstream aggiornati e chiavi
custom ancora usate; evitare overwrite di interi cataloghi e doppioni JSON.
Conservare le correzioni upstream gia equivalenti ai fix del fork.

### Database, build e rollout

Non modificare identificativi o parent di revisioni Alembic gia pubblicate.
Grafo verificato sui blob tramite assegnazioni semplici e annotate: base 58
revisioni/head `d4c1a8e37b62`; fork 61/head `6c7d8e9f0a1b`; upstream 64/head
`b8f2c6d91a04`; unione 67 revisioni con le due head, nessun parent mancante,
ciclo o parent condiviso divergente. Aggiungere una nuova merge revision con
`down_revision = ('6c7d8e9f0a1b', 'b8f2c6d91a04')`, upgrade/downgrade vuoti.
Catena custom: `42e2978c7933 -> f8a9b0c1d2e3`; merge
`(d4c1a8e37b62, f8a9b0c1d2e3) -> 28f62ff35ad1 -> 6c7d8e9f0a1b`.
Catena nuova upstream: `d4c1a8e37b62 -> a7d3e9f2b641 -> b8e4f0a3c752 ->
d6a8c3f912ab -> e7b9d4a023bc -> f8c0e5b134cd -> b8f2c6d91a04`.
L'indice pending-files finale e PostgreSQL-only: head raggiunta non prova
l'esistenza dell'indice. Non riscrivere revisioni gia distribuite. Entrambi i pin
usano `upgrade(..., 'head')` in `config.py` (fork :75; upstream :76): non
presupporre che il vecchio fix storico `heads` sia ancora attivo. Preservare
validazione PostgreSQL schema e search_path upstream (`migrations/env.py:77-99`).
Verificare database vuoto e upgrade da una copia anonimizzata della release
fork; mai collegare test o comandi Alembic al database di produzione.

Mantenere i requisiti Python/Node dei manifest target e pin custom ancora
necessari senza retrocedere dipendenze upstream. Rigenerare il lockfile tramite
package manager. Non installare dipendenze per la sola stesura del piano.

Documentare switch plugin/arena/orjson, aggiornamento coordinato di istanze
Redis e backup Milvus se il deployment usa queste integrazioni.
Il rollback dopo migrazioni richiede restore coordinato del backup dei dati,
non soltanto il ritorno all'immagine precedente.

## Criteri di accettazione

- SHA fork e upstream entrambi antenati del commit di integrazione.
- Nessun conflitto, marker residuo o personalizzazione applicativa persa.
- Migrazioni custom e upstream applicabili con una head finale intenzionale;
  dati Prompt Insights, auth e cronologie preservati.
- Copertura semantica NIS2 e test di autorizzazione/outcome sui nuovi flussi.
- Test custom e upstream pertinenti superati; le anomalie baseline sono
  riprodotte sullo stesso SHA upstream e documentate, non ignorate.
- Frontend e build container utilizzabili; configurazione di deployment e
  rollback espliciti.
- Inventario delle decisioni `keep/adapt/drop-upstream-equivalent` e patch
  finale rigenerata dalla nuova base, senza includere ricorsivamente archivi.
- Nessun push, tag, release o deploy senza autorizzazione successiva.
