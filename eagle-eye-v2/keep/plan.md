# Eagle Eye v2 — Project Plan

## Vision

A full-featured web application for exploring, managing, and operationalizing Splunk security detection content. Built on Bun + TypeScript with a proper server, database, and modern frontend — evolving from the v1 single-file prototype into a production-grade tool.

---

## Architecture

```
                        ┌──────────────────────────────────────┐
                        │            Bun Server                │
                        │                                      │
  YAML content ───────→ │  Ingestion engine (watch + rebuild)   │
                        │  SQLite (bun:sqlite)                 │
  Splunk REST API ←───→ │  /api/splunk/*                       │
  AI backends ←───────→ │  /api/ai/*  (server-side proxy)      │
                        │  /api/detections/*                   │
                        │  /api/stories/*                      │
                        │  /api/datasources/*                  │
                        │  /api/environments/*                 │
                        │  /api/audit/*                        │
                        │  Auth middleware                     │
                        └──────────────┬───────────────────────┘
                                       │
                        ┌──────────────▼───────────────────────┐
                        │        Frontend (Svelte/React)        │
                        │  Vite dev server / static build       │
                        │  Cytoscape.js graph                   │
                        │  Real-time status updates             │
                        └──────────────────────────────────────┘
```

### Tech Stack

| Layer | Choice | Rationale |
|-------|--------|-----------|
| Runtime | **Bun** | Native TypeScript, fast startup, built-in SQLite, single binary builds |
| Database | **SQLite (bun:sqlite)** | Embedded, zero-config, perfect for read-heavy workloads, portable |
| API | **Bun.serve() + Hono** | Lightweight router, middleware support, TypeScript-native |
| Frontend | **Svelte** (or React) | Decision needed — Svelte is smaller/faster, React has broader ecosystem |
| Graph | **Cytoscape.js** | Proven in v1, excellent API, performant with thousands of nodes |
| Build | **Vite** | Fast HMR, native ESM, works with Bun |

---

## Data Model

### SQLite Schema (Core Tables)

```sql
-- Content tables (populated from YAML ingestion)
CREATE TABLE detections (
    id TEXT PRIMARY KEY,           -- UUID from YAML
    name TEXT NOT NULL,
    type TEXT,                     -- TTP, Anomaly, Correlation, Hunting
    status TEXT,                   -- production, experimental, deprecated
    description TEXT,
    search TEXT,                   -- SPL query
    author TEXT,
    date TEXT,
    security_domain TEXT,
    asset_type TEXT,
    file_path TEXT,                -- source YAML path
    raw_yaml TEXT,                 -- original YAML for reference
    ingested_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE stories (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    narrative TEXT,
    author TEXT,
    status TEXT,
    date TEXT,
    file_path TEXT,
    raw_yaml TEXT,
    ingested_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE data_sources (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    source TEXT,
    sourcetype TEXT,
    file_path TEXT,
    raw_yaml TEXT,
    ingested_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE macros (
    name TEXT PRIMARY KEY,
    definition TEXT,
    description TEXT,
    file_path TEXT
);

-- Cross-reference tables
CREATE TABLE detection_stories (
    detection_id TEXT REFERENCES detections(id),
    story_name TEXT,
    PRIMARY KEY (detection_id, story_name)
);

CREATE TABLE detection_datasources (
    detection_id TEXT REFERENCES detections(id),
    datasource_name TEXT,
    PRIMARY KEY (detection_id, datasource_name)
);

CREATE TABLE detection_mitre (
    detection_id TEXT REFERENCES detections(id),
    technique_id TEXT,
    PRIMARY KEY (detection_id, technique_id)
);

CREATE TABLE detection_cves (
    detection_id TEXT REFERENCES detections(id),
    cve_id TEXT,
    PRIMARY KEY (detection_id, cve_id)
);

CREATE TABLE detection_macros (
    detection_id TEXT REFERENCES detections(id),
    macro_name TEXT,
    PRIMARY KEY (detection_id, macro_name)
);

-- MITRE ATT&CK reference data
CREATE TABLE mitre_techniques (
    id TEXT PRIMARY KEY,            -- T1197, T1059.001, etc.
    name TEXT,
    is_subtechnique BOOLEAN,
    tactics TEXT                     -- JSON array of tactic shortnames
);

CREATE TABLE mitre_tactics (
    shortname TEXT PRIMARY KEY,
    name TEXT,
    external_id TEXT,
    sort_order INTEGER
);

-- Environment & enablement tracking
CREATE TABLE environments (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    created_by TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE enablement_statuses (
    environment_id TEXT REFERENCES environments(id) ON DELETE CASCADE,
    detection_id TEXT REFERENCES detections(id),
    status TEXT CHECK(status IN ('backlog','later','blocked','now','done')),
    changed_by TEXT,
    changed_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (environment_id, detection_id)
);

-- Multi-tenancy
CREATE TABLE tenants (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE users (
    id TEXT PRIMARY KEY,
    email TEXT UNIQUE,
    display_name TEXT,
    tenant_id TEXT REFERENCES tenants(id),
    role TEXT CHECK(role IN ('viewer','editor','admin')),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_login DATETIME
);

-- Splunk connections (per-tenant)
CREATE TABLE splunk_connections (
    id TEXT PRIMARY KEY,
    tenant_id TEXT REFERENCES tenants(id),
    name TEXT NOT NULL,
    base_url TEXT NOT NULL,          -- https://splunk.example.com:8089
    auth_type TEXT,                   -- token, basic, saml
    encrypted_credentials TEXT,       -- encrypted at rest
    environment_id TEXT REFERENCES environments(id),
    created_by TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- AI configuration (per-tenant)
CREATE TABLE ai_configs (
    id TEXT PRIMARY KEY,
    tenant_id TEXT REFERENCES tenants(id),
    name TEXT NOT NULL,
    endpoint TEXT NOT NULL,
    model TEXT,
    encrypted_api_key TEXT,
    temperature REAL DEFAULT 0.3,
    streaming BOOLEAN DEFAULT TRUE,
    created_by TEXT
);

CREATE TABLE ai_prompts (
    tenant_id TEXT REFERENCES tenants(id),
    entity_type TEXT CHECK(entity_type IN ('detection','story','datasource','mitre')),
    template TEXT NOT NULL,
    updated_by TEXT,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, entity_type)
);

-- Audit log
CREATE TABLE audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    tenant_id TEXT,
    user_id TEXT,
    action TEXT NOT NULL,             -- e.g. 'enablement.change', 'ai.query', 'search.run'
    entity_type TEXT,
    entity_id TEXT,
    details TEXT,                      -- JSON blob with action-specific data
    ip_address TEXT
);

CREATE INDEX idx_audit_tenant_time ON audit_log(tenant_id, timestamp DESC);
CREATE INDEX idx_audit_action ON audit_log(action);
```

---

## API Routes

### Content (read-only, populated from YAML ingestion)

| Method | Route | Description |
|--------|-------|-------------|
| GET | `/api/detections` | List detections (paginated, filterable, searchable) |
| GET | `/api/detections/:id` | Detection detail with all cross-references |
| GET | `/api/stories` | List stories |
| GET | `/api/stories/:id` | Story detail with member detections |
| GET | `/api/datasources` | List data sources |
| GET | `/api/datasources/:id` | Data source detail |
| GET | `/api/macros` | List macros |
| GET | `/api/mitre/techniques` | All techniques |
| GET | `/api/mitre/matrix` | Matrix structure (tactics × techniques) |
| GET | `/api/graph/:entityType/:entityId` | Ego-centric graph data for an entity |
| POST | `/api/search` | Full-text search across all entity types |

### Environments & Enablement

| Method | Route | Description |
|--------|-------|-------------|
| GET | `/api/environments` | List environments for current tenant |
| POST | `/api/environments` | Create environment |
| PUT | `/api/environments/:id` | Update environment |
| DELETE | `/api/environments/:id` | Delete environment |
| GET | `/api/environments/:id/statuses` | All detection statuses for an environment |
| PUT | `/api/environments/:envId/detections/:detId` | Set enablement status |
| PATCH | `/api/environments/:envId/detections` | Bulk update statuses |
| GET | `/api/environments/:id/export` | Export as YAML sidecar |
| POST | `/api/environments/import` | Import YAML sidecar |

### Splunk Integration

| Method | Route | Description |
|--------|-------|-------------|
| GET | `/api/splunk/connections` | List Splunk connections |
| POST | `/api/splunk/connections` | Add Splunk connection |
| DELETE | `/api/splunk/connections/:id` | Remove connection |
| GET | `/api/splunk/connections/:id/test` | Test connectivity |
| GET | `/api/splunk/status/:detectionId` | Check if detection is enabled in Splunk |
| POST | `/api/splunk/search` | Run a test search against Splunk |
| GET | `/api/splunk/search/:sid/results` | Get search results |

### AI Enrichment (Server-Side Proxy)

| Method | Route | Description |
|--------|-------|-------------|
| POST | `/api/ai/chat` | Proxied chat completion (streaming via SSE) |
| GET | `/api/ai/configs` | List AI configurations |
| POST | `/api/ai/configs` | Add AI backend |
| GET | `/api/ai/prompts` | Get prompt templates |
| PUT | `/api/ai/prompts/:entityType` | Update prompt template |

### Auth & Admin

| Method | Route | Description |
|--------|-------|-------------|
| POST | `/api/auth/login` | Authentication |
| POST | `/api/auth/logout` | End session |
| GET | `/api/auth/me` | Current user info |
| GET | `/api/users` | List users (admin) |
| POST | `/api/users` | Create user (admin) |
| GET | `/api/audit` | Query audit log (paginated, filterable) |
| GET | `/api/audit/export` | Export audit log as CSV/JSON |

### Ingestion

| Method | Route | Description |
|--------|-------|-------------|
| POST | `/api/ingest/trigger` | Trigger re-ingestion of YAML content |
| GET | `/api/ingest/status` | Current ingestion status / last run |

---

## Phases

### Phase 1 — Foundation (Week 1-2)

**Goal**: Server running, content ingested, basic browsing works.

- [ ] Project scaffolding (Bun + Hono + Vite + Svelte)
- [ ] SQLite schema creation and migrations
- [ ] YAML ingestion engine (port from v1 build.py → TypeScript)
  - [ ] Recursive detection loading
  - [ ] Story, data source, macro loading
  - [ ] Cross-reference resolution (detection↔story, detection↔datasource, detection↔mitre)
  - [ ] MITRE ATT&CK STIX data fetch + cache
- [ ] Core API routes: detections, stories, datasources, macros, mitre
- [ ] Full-text search (SQLite FTS5)
- [ ] Frontend: detection list view with search and filters
- [ ] Frontend: detection detail panel
- [ ] Frontend: story list + detail
- [ ] Frontend: data source list + detail
- [ ] Frontend: MITRE technique list
- [ ] Verification: feature parity with v1 browse/search/filter

### Phase 2 — Environments & Enablement (Week 3)

**Goal**: Full enablement tracking with server-side persistence.

- [ ] Environment CRUD API
- [ ] Enablement status API (set, bulk update)
- [ ] YAML import/export endpoints
- [ ] Frontend: environment selector
- [ ] Frontend: enablement badges on detections
- [ ] Frontend: breakdown bars on stories and data sources
- [ ] Frontend: status picker (click badge → change status)
- [ ] Migration path from v1 localStorage/YAML data
- [ ] Verification: all v1 enablement features working with server persistence

### Phase 3 — Graph & Matrix (Week 4)

**Goal**: Interactive graph and MITRE matrix views.

- [ ] Graph data API (ego-centric subgraph extraction)
- [ ] Frontend: Cytoscape.js graph view with enablement rings
- [ ] Frontend: MITRE ATT&CK coverage matrix
- [ ] Frontend: graph search and focus
- [ ] Graph performance testing at full content scale

### Phase 4 — AI Enrichment (Week 4-5)

**Goal**: Server-side AI proxy, zero CORS issues, streaming works perfectly.

- [ ] AI config CRUD API (encrypted credential storage)
- [ ] Server-side chat proxy with SSE streaming
- [ ] Per-entity-type prompt templates (CRUD + defaults)
- [ ] Frontend: AI analysis panel on all entity detail views
- [ ] Frontend: follow-up conversation support
- [ ] Frontend: AI settings management
- [ ] Conversation history persistence (per-user, per-entity)

### Phase 5 — Splunk Integration (Week 5-6)

**Goal**: Live detection status from Splunk, test search execution.

- [ ] Splunk connection management (encrypted credentials)
- [ ] Connection test endpoint
- [ ] Detection status polling (check if saved search exists + is enabled)
- [ ] Status sync: Splunk enabled state → enablement status
- [ ] Test search execution (submit SPL, poll for results, stream back)
- [ ] Frontend: live status indicator on detections
- [ ] Frontend: "Run Test Search" button on detection detail
- [ ] Frontend: search results display
- [ ] Rate limiting and connection pooling for Splunk API calls

### Phase 6 — Auth, Multi-Tenancy & Audit (Week 6-7)

**Goal**: Production-ready security, isolation, and observability.

- [ ] Authentication system (session-based or JWT)
  - [ ] Local auth (email + password) for simple deployments
  - [ ] SSO/OIDC integration (optional, for enterprise)
- [ ] Tenant isolation middleware (all queries scoped to tenant)
- [ ] Role-based access control (viewer, editor, admin)
- [ ] Audit logging middleware (automatic for all write operations)
- [ ] Audit log query API + export
- [ ] Frontend: login page
- [ ] Frontend: user management (admin)
- [ ] Frontend: audit log viewer
- [ ] Credential encryption at rest (AI keys, Splunk tokens)

### Phase 7 — Polish & Deployment (Week 7-8)

**Goal**: Production-quality UX, deployment options, documentation.

- [ ] Error handling and validation across all APIs
- [ ] Loading states, error states, empty states in frontend
- [ ] Responsive layout (tablet-friendly at minimum)
- [ ] Dark/light theme support
- [ ] Keyboard navigation and accessibility
- [ ] Docker container build (Bun + SQLite + static frontend)
- [ ] `bun build --compile` single binary option
- [ ] Environment variable configuration (ports, DB path, secrets)
- [ ] README and deployment guide
- [ ] Content ingestion watch mode (auto-reload on YAML changes)
- [ ] Performance testing at scale (5K+ detections)

---

## Non-Functional Requirements

| Requirement | Target |
|-------------|--------|
| Cold start | < 2 seconds |
| Search latency | < 100ms for full-text across all entities |
| Graph render | < 1 second for 500-node ego graph |
| Concurrent users | 50+ (SQLite WAL mode) |
| Detection scale | 10,000+ detections without degradation |
| Data at rest | All credentials encrypted (API keys, Splunk tokens) |
| Audit retention | 90 days default, configurable |
| Deployment | Single Docker image or single compiled binary |
| Offline | Works without internet (MITRE data cached in SQLite) |

---

## Migration from v1

| v1 Feature | v2 Equivalent |
|------------|---------------|
| `%%DATA_JSON%%` template injection | SQLite ingestion + API |
| `localStorage` environment data | `enablement_statuses` table |
| `localStorage` AI config | `ai_configs` table (encrypted) |
| Client-side `fetch()` to AI | Server-side proxy `/api/ai/chat` |
| YAML sidecar env files | Import → `environments` + `enablement_statuses` tables |
| Cytoscape.js CDN load | Bundled via Vite (offline-capable) |
| `build.py` YAML parser | TypeScript ingestion engine with watch mode |
| Browser-only persistence | SQLite database file (backupable, portable) |

---

## Open Decisions

- [ ] **Frontend framework**: Svelte (lighter, faster) vs React (bigger ecosystem, more hiring pool)
- [ ] **Auth provider**: Built-in local auth vs OIDC-only vs both
- [ ] **Deployment target**: Docker-first vs binary-first vs both
- [ ] **Repository structure**: Monorepo with `packages/server` + `packages/frontend` vs flat
- [ ] **Content ingestion trigger**: File watcher (auto) vs API trigger (manual) vs both
- [ ] **Splunk auth**: Per-user Splunk tokens vs shared service account per connection
- [ ] **YAML field coverage**: Which additional detection fields to surface (see Appendix A)

---

## Appendix A: Detection Fields Not Yet Surfaced

Fields present in YAML source files that v1 does not display but v2 should consider:

| Field | Value |
|-------|-------|
| `how_to_implement` | Implementation guidance for analysts |
| `known_false_positives` | Tuning guidance |
| `references` | External links (MITRE, vendor docs, research) |
| `drilldown_searches` | Follow-up searches for investigation |
| `rba.message` | Risk-based alerting message template |
| `rba.risk_objects` | Entities and risk scores |
| `rba.threat_objects` | Threat indicators |
| `tests` | Test cases with attack data URLs |
| `data_source` (full detail) | Source, sourcetype, supported TAs, field mappings |
| `tags.product` | Splunk product compatibility |
| `version` | Content version number |
| `date` | Last update date |

## Appendix B: Splunk REST API Endpoints

| Endpoint | Purpose |
|----------|---------|
| `GET /services/saved/searches/{name}` | Check if detection exists as saved search |
| `GET /services/saved/searches/{name}?output_mode=json` | Get enabled/disabled status |
| `POST /services/search/jobs` | Submit a search job |
| `GET /services/search/jobs/{sid}` | Check search job status |
| `GET /services/search/jobs/{sid}/results` | Get search results |
| `GET /services/server/info` | Test connection / get Splunk version |
