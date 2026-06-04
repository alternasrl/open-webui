# Copilot Instructions for Open WebUI

This document provides essential guidance for AI assistants working on the Open WebUI codebase.

## Quick Reference

### Build & Test Commands

#### Frontend (Svelte + TypeScript)
- **Local Development**: `npm run dev` - Starts dev server with hot reload on `http://localhost:5173`
  - Alternative port: `npm run dev:5050` for port 5050
- **Build**: `npm run build` - Produces optimized production build to `build/`
- **Build with Watch**: `npm run build:watch` - Continuous build as you edit
- **Test Frontend**: `npm run test:frontend` - Runs Vitest (supports `--passWithNoTests`)
- **Type Check**: `npm run check` - Svelte-check with TypeScript validation
- **Lint**: `npm run lint:frontend` - ESLint with auto-fix
- **Format**: `npm run format` - Prettier (TypeScript, Svelte, CSS, JSON, etc.)

#### Backend (FastAPI + Python)
- **Python Version**: Must use **Python 3.11** or **3.12** (see `pyproject.toml` `requires-python`)
- **Install**: `pip install -e .` or use `uv` for faster installs
- **Run Backend**: Backend starts via FastAPI app at `open_webui.main:app` (typically port 8000)
- **Lint Backend**: `npm run lint:backend` - Runs pylint on `backend/`
- **Format Backend**: `npm run format:backend` - Black formatter
- **Tests**: See `backend/open_webui/test/` for pytest tests (run via `pytest backend/`)

#### Full Stack Commands
- **Lint Everything**: `npm run lint` runs frontend → types → backend sequentially
- **Format Everything**: `npm run format` + `npm run format:backend`
- **Docker**: Use `Makefile` targets or `docker-compose` (multiple configs available for GPU, AMD, Ollama, etc.)

## Architecture Overview

**Open WebUI is a two-tier full-stack application:**

### Frontend (SvelteKit + Vite)
- **Framework**: SvelteKit 2.x with static adapter (`@sveltejs/adapter-static`)
- **Language**: TypeScript with strict mode
- **Styling**: Tailwind CSS 4.0 + PostCSS
- **Structure**: `src/routes/` contains page routes (filesystem routing); `src/lib/` contains reusable components
- **Build Output**: Static files → `build/` directory
- **Special**: Uses Pyodide for client-side Python execution; prepared via `npm run pyodide:fetch`
- **Version Management**: Git commit SHA or package.json version (for offline builds); polls every 60s for updates

### Backend (FastAPI + Python)
- **Framework**: FastAPI 0.135.1 with Uvicorn ASGI server
- **Database**: SQLAlchemy 2.0 (ORM) + Alembic (migrations); supports SQLite, PostgreSQL, MariaDB
- **Auth**: JWT tokens, bcrypt password hashing, OAuth support, LDAP/AD integration
- **Key Packages**: 
  - **LLM Integration**: OpenAI, Anthropic, Google GenAI, Ollama APIs
  - **RAG**: LangChain, ChromaDB (9 vector database options supported)
  - **Retrieval**: Multiple content extractors (Tika, Docling, etc.) and web search providers (SearXNG, Brave, Tavily, etc.)
  - **File Handling**: PyPDF, docx2txt, python-pptx, unstructured, pandas (Excel/CSV)
  - **Media**: FastWhisper (speech-to-text), PIL, OpenCV, RapidOCR, ONNX
  - **Storage**: Local filesystem, S3, Google Cloud Storage, Azure Blob Storage
  - **Observability**: OpenTelemetry tracing, metrics, logs
  - **Real-time**: Socket.IO for WebSocket communication

**Backend Structure:**
- `backend/open_webui/routers/` - FastAPI router modules (models, users, tools, functions, etc.)
- `backend/open_webui/models/` - SQLAlchemy models and Pydantic schemas
- `backend/open_webui/utils/` - Helper utilities (auth, access control, etc.)
- `backend/open_webui/socket/` - WebSocket handlers
- `backend/open_webui/retrieval/` - RAG and search integration
- `backend/open_webui/storage/` - Cloud storage providers
- `backend/open_webui/migrations/` - Alembic DB migrations

### Data Flow
1. **Frontend** (SvelteKit) sends HTTP/WebSocket requests to FastAPI backend
2. **Backend** processes requests, queries DB (SQLAlchemy), calls external APIs (Ollama, OpenAI, web search, etc.)
3. **Results** returned as JSON or streamed responses; WebSocket handles real-time updates
4. **Storage** can be local SQLite, PostgreSQL, or cloud backends (configurable)

## Key Conventions

### Frontend Code
- **Component Organization**: Svelte files in `src/lib/components/` follow single-file component pattern
- **State Management**: Context API for shared state; stores in `src/lib/stores/` for reactive globals
- **Routing**: SvelteKit filesystem routing; pages in `src/routes/+page.svelte`, layouts in `+layout.svelte`
- **Styling**: Tailwind classes + `<style>` blocks; avoid inline styles for themes
- **i18n**: Translations in `src/lib/i18n/` managed via i18next; use `$t('key')` in templates
- **Type Safety**: Use TypeScript interfaces/types; avoid `any`; leverage SvelteKit's type generation

### Backend Code
- **Router Pattern**: Use APIRouter with decorators (`@router.get()`, `@router.post()`, etc.)
- **Dependencies**: Leverage FastAPI's dependency injection (`Depends()`) for auth, DB sessions, permissions
- **Auth Checks**: Use `get_verified_user()` or `get_admin_user()` from `open_webui.utils.auth`
- **DB Queries**: Always use SQLAlchemy session context for transactions; Alembic for schema migrations
- **Error Handling**: Raise `HTTPException` with appropriate `status_code` (404, 403, 500, etc.)
- **Pydantic Models**: Define request/response schemas; use `response_model=` in route decorators
- **Async/Await**: Most routes are async; use `asyncio` and `aiohttp` for concurrent operations
- **Logging**: Use standard Python logging or Loguru; configured in `backend/open_webui/config.py`
- **Environment Config**: All settings in `backend/open_webui/env.py` or `config.py`; read via `os.getenv()`

### Database
- **ORM**: SQLAlchemy 2.0; models in `backend/open_webui/models/`
- **Migrations**: Use Alembic CLI (`alembic upgrade head` to apply); never modify schema directly
- **Sessions**: Always use `get_session()` dependency to obtain DB session; let FastAPI handle cleanup
- **Multi-DB**: SQLite default; postgres/mariadb via optional dependencies and environment config

### Testing
- **Frontend Tests**: Vitest in `test/` directory; async tests use Vitest's built-in async support
- **Backend Tests**: Pytest; test files in `backend/open_webui/test/` mirroring source structure
- **Test DB**: Use temporary SQLite in-memory or fixture-based setups; avoid production DB
- **Mocking**: Mock external APIs (Ollama, OpenAI, storage) to avoid real API calls
- **Coverage**: Aim for critical paths (auth, routers, data validation)

### Code Style & Formatting
- **Frontend**: ESLint + Prettier (auto-fix enabled); tabs (not spaces)
- **Backend**: Black formatter; 100-char line limit (see config)
- **Python**: Follow PEP 8; type hints required for functions
- **Commits**: Must include `Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>` trailer if AI-assisted
- **PR Checklist**: Target `dev` branch (NOT `main`); include changelog entry; test thoroughly; document user-facing changes

### Special Considerations
- **Node/NPM Version**: Node 18.13.0 ≤ version ≤ 22.x.x; npm ≥ 6.0.0
- **Pyodide Fetching**: Frontend build requires `npm run pyodide:fetch` before `npm run build`
- **Offline-First**: Targets PWA and offline capabilities; version polling every 60s for updates
- **Multi-Tenancy**: RBAC, user groups, and granular permissions built-in
- **Extensibility**: Plugin system via Pipelines framework; custom functions via Python in UI
- **Internationalization**: 30+ languages supported; translations in JSON; use `i18next-parser` to sync strings

## Development Workflow

1. **Setup**: Clone repo, `npm install` (frontend), `pip install -e .` (backend, requires Python 3.11+)
2. **Branch**: Create feature branch from `dev`, not `main`
3. **Local Dev**: `npm run dev` (frontend on 5173 or 5050) + run backend separately (e.g., `uvicorn open_webui:app --reload`)
4. **Test**: Run `npm run test:frontend` and pytest for backend; test edge cases
5. **Lint & Format**: `npm run lint` and `npm run format` before committing
6. **Commit**: Write clear messages; include `Co-authored-by` trailer if AI-assisted
7. **PR**: Target `dev` branch; add changelog; test thoroughly; include screenshots/demos for UI changes
8. **Docs**: Update docs repo for user-facing changes, API endpoints, environment variables

## External Service Integration

- **LLM Providers**: Ollama (local), OpenAI, Anthropic, Google GenAI
- **Vector Stores**: ChromaDB, PGVector, Qdrant, Milvus, Elasticsearch, OpenSearch, Pinecone, Weaviate, Oracle 23ai
- **Web Search**: SearXNG, Google PSE, Brave, Tavily, Perplexity, Kagi, DuckDuckGo, Bing, etc.
- **Cloud Storage**: S3, Google Cloud Storage, Azure Blob Storage, Google Drive, OneDrive/SharePoint
- **Auth Providers**: OAuth, LDAP/Active Directory, SAML, trusted headers
- **Observability**: OpenTelemetry (traces, metrics, logs)
- **Message Brokers**: Redis (sessions, caching), Socket.IO (WebSocket)

All integrations are optional and configurable via environment variables.

## Tag & Release Naming Convention

  Always apply these rules when creating git tags or GitHub releases.ENFORCED ### 

#### 1. Source release tags (git tags on `alternasrl/open-webui`)

**Format:** `v{MAJOR}.{MINOR}.{PATCH}-{YYMMDD}[{letter}]`

| Component | Format | Description |
|-----------|--------|-------------|
| `v{semver}` | `v0.9.6` | Upstream open-webui version |
 `260604` |
| `{letter}` | *(omit)*, `b`, ` | Same-day re-iterations only; first tag has NO suffix |c`

**Examples:**
```
v0.9.5- v0.9.5, May 12 2026 (first tag that day)260512    
v0.9.5- v0.9.5, May 20 2026260520    
v0.9.6- v0.9.6, June 4 2026 (CORRECT form)260604    
v0.9.6- v0.9.6, June 4 2026, second iteration260604b   
v0.9.6- v0.9.6, June 4 2026, third iteration260604c   
```

 **Known deviation:** Tags `v0.9.6-040626` and `v0.9.6-040626b` exist in the repo with the wrong DDMMYY order. They remain for backwards compat but MUST NOT be used as a model for new tags. Always use **YYMMDD**.> 

**Regex to validate:** `^v\d+\.\d+\.\d+(-[a-z0-9]+)?-\d{6}[b-z]?$`

#### 2. Docker image tags (produced by `giada/build_image.py`)

**Format:** `{source-release-tag}-build-{YYYYMMDD}.{NN}`

| Component | Format | Description |
|-----------|--------|-------------|
| `{source-release-tag}` | `v0.9.6-260604` | Full source release tag (YYMMDD) |
| `build` | literal | Separator |
| `{YYYYMMDD}` | `20260604` | ISO date with **4-digit year** |
| `{NN}` | `01`, ` | Zero-padded sequential build number for the day |02`

**Examples:**
```
v0.9.6-260604-build-20260604.01
v0.9.6-260604-build-20260604.02
v0.9.6-260604b-build-20260604.01
```

**ACR full reference:** `craltea.azurecr.io/open-webui:{docker-image-tag}`

#### 3. GitHub releases (`alternasrl/open-webui`)

- **Tag:** source release tag (e.g. `v0.9.6-260604`)
- **Title:** same as tag
- **Body:** changelog snippet for the version + custom patches list

#### 4. Branch naming

- Integration branches: `integration-v{MAJOR}.{MINOR}.{PATCH}`
- Feature branches: `feat/{short-description}` from `dev`
- Do NOT branch from `main` for  use `dev`features 

#### Quick cheat-sheet

```
 YYMMDD = 260604

New source tag:     v0.9.7-260604        (first this day)
Second iteration:   v0.9.7-260604b
Docker image tag:   v0.9.7-260604-build-20260604.01
ACR ref:            craltea.azurecr.io/open-webui:v0.9.7-260604-build-20260604.01
```
