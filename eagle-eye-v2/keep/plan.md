# Eagle Eye v2 — Project Plan

## Vision

A full-featured web application for exploring, managing, and operationalizing Splunk security detection content. Built on Bun + TypeScript with a proper server, database, and modern frontend — evolving from the v1 single-file prototype into a production-grade tool.

**Key design goals:**
- Surface **every useful field** from the security-content YAML schema — nothing left behind
- Support **multiple content roots** (upstream ESCU + custom/private detections) with provenance tracking
- Provide **first-class RBA, compliance, and threat group views** alongside the core browse/search/graph/matrix experience
- Eliminate all v1 limitations (no CORS issues, server-side persistence, real SPL highlighting, offline-capable)

---

## Architecture

```
                        ┌──────────────────────────────────────┐
                        │            Bun Server                │
                        │                                      │
  YAML content ───────→ │  Ingestion engine (watch + rebuild)   │
  (multiple roots)      │  SQLite (bun:sqlite)                 │
                        │                                      │
  Splunk REST API ←───→ │  /api/splunk/*                       │
  AI backends ←───────→ │  /api/ai/*  (server-side proxy)      │
                        │  /api/detections/*                   │
                        │  /api/stories/*                      │
                        │  /api/datasources/*                  │
                        │  /api/lookups/*                      │
                        │  /api/baselines/*                    │
                        │  /api/deployments/*                  │
                        │  /api/mitre/*                        │
                        │  /api/environments/*                 │
                        │  /api/audit/*                        │
                        │  Auth middleware                     │
                        └──────────────┬───────────────────────┘
                                       │
                        ┌──────────────▼───────────────────────┐
                        │        Frontend (Svelte 5)            │
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
| Frontend | **Svelte 5** | v1 is ~3300 lines of vanilla JS which maps naturally to Svelte components; runes handle reactive state cleanly; smaller bundle than React |
| Graph | **Cytoscape.js** | Proven in v1, excellent API, performant with thousands of nodes |
| Build | **Vite** | Fast HMR, native ESM, works with Bun |
| Migrations | **Manual SQL scripts** | Numbered migration files in `migrations/` — simple, no ORM overhead |
| SPL Highlighting | **Custom tokenizer** | Lightweight SPL lexer for keywords, functions, fields, macros, pipes, operators |
| Markdown | **marked.js** | For AI response rendering (replaces v1's custom renderer) |

---

## Multi-Root Content Architecture

Eagle Eye supports ingesting content from **multiple content roots** — directories that follow the security-content schema. This enables teams to combine upstream Splunk ESCU content with their own custom/private detections.

### Configuration

Content roots are declared in `eagle-eye.config.yml` (or via environment variables):

```yaml
content_roots:
  - name: "Splunk ESCU"
    path: "./security-content"        # main upstream repo
    type: primary                      # first root = primary
  - name: "Custom Detections"
    path: "../our-custom-content"      # separate repo or directory
    type: overlay
  - name: "IR Team Content"
    path: "/opt/ir-detections"         # any local directory
    type: overlay
```

Each root must follow the standard directory layout (`detections/`, `stories/`, `data_sources/`, `macros/`, `lookups/`, `baselines/`). Partial roots are fine — a custom root may only contain `detections/` and `stories/`.

### Content Merging Rules

| Scenario | Behavior |
|----------|----------|
| Same UUID across roots | Later root (overlay) overrides primary — logged as intentional override |
| Same name, different UUID | Treated as separate entities — both appear, badged with provenance |
| Custom detection references upstream story | Cross-root references resolve by name (all roots processed before resolution) |
| Custom macro overrides upstream macro | Override wins — original still visible in "overridden" state |
| Conflicting cross-references | Warnings surfaced in ingestion status UI |

### Ingestion Order

1. Process primary root first (full content set)
2. Process overlay roots in declared order
3. Resolve all cross-references across merged content
4. UUID conflicts: overlay wins, logged with diff summary
5. Name-based references resolve across all roots

### Provenance Tracking

Every record carries `content_root_id` linking to the `content_roots` table. The UI provides:
- **Global filter**: "All Content" / "Splunk ESCU" / "Custom Detections" / etc.
- **Provenance badges**: Small label on cards showing which root a detection came from
- **Custom-only view**: Quick filter to see only your team's content
- **Override indicators**: When a custom detection overrides an upstream UUID, both versions are accessible

### Git Awareness (Optional)

If a content root is a git repository, Eagle Eye captures:
- Current branch name
- HEAD commit hash
- Last commit date
- Dirty/clean working tree status

This is displayed in the ingestion status panel and on provenance badges.

---

## Data Model

### SQLite Schema

```sql
-- ============================================================
-- Content Roots (multi-root support)
-- ============================================================

CREATE TABLE content_roots (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    path TEXT NOT NULL,
    type TEXT CHECK(type IN ('primary','overlay')) NOT NULL,
    git_branch TEXT,
    git_commit TEXT,
    git_dirty BOOLEAN,
    last_ingested_at DATETIME,
    detection_count INTEGER DEFAULT 0,
    story_count INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================
-- Detections (complete field coverage)
-- ============================================================

CREATE TABLE detections (
    id TEXT PRIMARY KEY,                    -- UUID from YAML
    content_root_id TEXT REFERENCES content_roots(id),
    name TEXT NOT NULL,
    type TEXT NOT NULL,                     -- TTP, Anomaly, Correlation, Hunting
    status TEXT NOT NULL,                   -- production, experimental, deprecated
    description TEXT NOT NULL,
    search TEXT NOT NULL,                   -- SPL query
    how_to_implement TEXT,                  -- implementation guidance (required in YAML)
    known_false_positives TEXT,             -- tuning guidance (required in YAML)
    author TEXT NOT NULL,
    date TEXT NOT NULL,
    version INTEGER NOT NULL,
    enabled_by_default BOOLEAN DEFAULT FALSE,
    -- Tags (flattened from tags.*)
    security_domain TEXT,                   -- endpoint, network, threat, identity, access, audit
    asset_type TEXT,                        -- Endpoint, AWS Account, etc.
    product TEXT,                           -- JSON array: ["Splunk Enterprise", "Splunk Cloud"]
    event_schema TEXT DEFAULT 'ocsf',
    groups TEXT,                            -- JSON array of group tags
    -- RBA (flattened from rba.*)
    rba_message TEXT,                       -- risk message template with $field$ tokens
    risk_score INTEGER,                     -- computed: max of risk_objects scores (1-100)
    severity TEXT,                          -- computed: informational/low/medium/high/critical
    -- Computed fields (derived at ingest time)
    datamodel TEXT,                         -- JSON array: parsed from search SPL
    source_category TEXT,                   -- parent folder name (endpoint, cloud, network, etc.)
    providing_technologies TEXT,            -- JSON array: parsed from data_source names
    kill_chain_phases TEXT,                 -- JSON array: mapped from MITRE tactics
    cis20 TEXT,                             -- JSON array: CIS Controls mapping
    nist TEXT,                              -- JSON array: NIST CSF mapping
    -- Deployment info (from matched deployment config)
    cron_schedule TEXT,
    scheduling_earliest TEXT,
    scheduling_latest TEXT,
    -- Metadata
    references TEXT,                        -- JSON array of URLs
    file_path TEXT,                         -- source YAML path (relative to content root)
    raw_yaml TEXT,                          -- original YAML for reference
    ingested_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_detections_status ON detections(status);
CREATE INDEX idx_detections_type ON detections(type);
CREATE INDEX idx_detections_security_domain ON detections(security_domain);
CREATE INDEX idx_detections_content_root ON detections(content_root_id);
CREATE INDEX idx_detections_severity ON detections(severity);

-- RBA risk objects (one-to-many from detection)
CREATE TABLE detection_risk_objects (
    detection_id TEXT REFERENCES detections(id) ON DELETE CASCADE,
    field TEXT NOT NULL,                     -- SPL field name (e.g., dest, user)
    type TEXT NOT NULL,                      -- system, user, other
    score INTEGER NOT NULL,                  -- 1-100
    PRIMARY KEY (detection_id, field)
);

-- RBA threat objects (one-to-many from detection)
CREATE TABLE detection_threat_objects (
    detection_id TEXT REFERENCES detections(id) ON DELETE CASCADE,
    field TEXT NOT NULL,
    type TEXT NOT NULL,                      -- 29 types: ip_address, domain, file_hash, url, process, etc.
    PRIMARY KEY (detection_id, field)
);

-- Drilldown searches (one-to-many from detection)
CREATE TABLE detection_drilldowns (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    detection_id TEXT REFERENCES detections(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    search TEXT NOT NULL,                    -- SPL with %original_detection_search% substituted
    earliest_offset TEXT,
    latest_offset TEXT
);

-- Throttling config (one-to-one with detection, optional)
CREATE TABLE detection_throttling (
    detection_id TEXT PRIMARY KEY REFERENCES detections(id) ON DELETE CASCADE,
    fields TEXT NOT NULL,                    -- JSON array of field names
    period TEXT NOT NULL                     -- e.g., "60m", "24h"
);

-- Test definitions (one-to-many from detection)
CREATE TABLE detection_tests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    detection_id TEXT REFERENCES detections(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    test_type TEXT NOT NULL,                 -- unit, integration, manual
    earliest_time TEXT,
    latest_time TEXT
);

-- Test attack data (one-to-many from test)
CREATE TABLE test_attack_data (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    test_id INTEGER REFERENCES detection_tests(id) ON DELETE CASCADE,
    data_url TEXT NOT NULL,                  -- URL to attack data file
    source TEXT NOT NULL,                    -- Splunk source value
    sourcetype TEXT NOT NULL,               -- Splunk sourcetype
    custom_index TEXT,
    host TEXT
);

-- ============================================================
-- Stories
-- ============================================================

CREATE TABLE stories (
    id TEXT PRIMARY KEY,
    content_root_id TEXT REFERENCES content_roots(id),
    name TEXT NOT NULL,
    description TEXT NOT NULL,
    narrative TEXT NOT NULL,
    author TEXT NOT NULL,
    status TEXT NOT NULL,                    -- production, deprecated
    date TEXT NOT NULL,
    version INTEGER NOT NULL,
    references TEXT,                         -- JSON array of URLs
    -- Tags
    category TEXT,                           -- JSON array: Malware, Adversary Tactics, Cloud Security, etc.
    usecase TEXT,                            -- Advanced Threat Detection, Compliance, Fraud Detection, etc.
    product TEXT,                            -- JSON array of product names
    groups TEXT,                             -- JSON array of group tags
    cve TEXT,                               -- JSON array of CVE IDs
    -- Metadata
    file_path TEXT,
    raw_yaml TEXT,
    ingested_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_stories_status ON stories(status);
CREATE INDEX idx_stories_content_root ON stories(content_root_id);

-- ============================================================
-- Data Sources (complete field coverage)
-- ============================================================

CREATE TABLE data_sources (
    id TEXT PRIMARY KEY,
    content_root_id TEXT REFERENCES content_roots(id),
    name TEXT NOT NULL,
    description TEXT NOT NULL,
    author TEXT NOT NULL,
    date TEXT NOT NULL,
    version INTEGER NOT NULL,
    source TEXT NOT NULL,                    -- Splunk source value
    sourcetype TEXT NOT NULL,               -- Splunk sourcetype
    separator TEXT,                          -- event ID type (e.g., "EventID")
    separator_value TEXT,                    -- event ID value (e.g., "13")
    configuration TEXT,                     -- URL to setup guide
    fields TEXT,                            -- JSON array: all available fields
    field_mappings TEXT,                    -- JSON: CIM/OCSF data model field mappings
    example_log TEXT,                       -- raw sample event (XML, JSON, etc.)
    output_fields TEXT,                     -- JSON array: validated output fields
    mitre_components TEXT,                  -- JSON array: MITRE component mappings
    -- Metadata
    file_path TEXT,
    raw_yaml TEXT,
    ingested_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_datasources_content_root ON data_sources(content_root_id);

-- Supported Technology Add-ons (one-to-many from data_source)
CREATE TABLE datasource_supported_ta (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    datasource_id TEXT REFERENCES data_sources(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    url TEXT,
    version TEXT
);

-- ============================================================
-- Macros
-- ============================================================

CREATE TABLE macros (
    id TEXT PRIMARY KEY,                    -- UUID (auto-generated if not in YAML)
    content_root_id TEXT REFERENCES content_roots(id),
    name TEXT NOT NULL UNIQUE,
    definition TEXT NOT NULL,
    description TEXT,
    arguments TEXT,                          -- JSON array of argument names
    file_path TEXT
);

CREATE INDEX idx_macros_name ON macros(name);

-- ============================================================
-- Lookups (3 types: CSV, KVStore, MLModel)
-- ============================================================

CREATE TABLE lookups (
    id TEXT PRIMARY KEY,
    content_root_id TEXT REFERENCES content_roots(id),
    name TEXT NOT NULL,
    lookup_type TEXT NOT NULL,               -- csv, kvstore, mlmodel
    description TEXT,
    author TEXT,
    date TEXT,
    version INTEGER,
    status TEXT,
    -- CSV-specific
    filename TEXT,                            -- e.g., "attacker_tools.csv"
    csv_preview TEXT,                         -- first N rows of CSV for preview
    -- KVStore-specific
    kvstore_fields TEXT,                     -- JSON array: field definitions (starts with _key)
    collection_name TEXT,                    -- auto-derived collection name
    -- Matching config (all types)
    default_match TEXT,
    match_type TEXT,                         -- JSON array: WILDCARD/CIDR patterns
    min_matches INTEGER,
    max_matches INTEGER,
    case_sensitive_match BOOLEAN,
    -- Metadata
    file_path TEXT,
    raw_yaml TEXT,
    ingested_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_lookups_type ON lookups(lookup_type);

-- ============================================================
-- Baselines
-- ============================================================

CREATE TABLE baselines (
    id TEXT PRIMARY KEY,
    content_root_id TEXT REFERENCES content_roots(id),
    name TEXT NOT NULL,
    description TEXT NOT NULL,
    search TEXT NOT NULL,                    -- SPL query
    how_to_implement TEXT,
    known_false_positives TEXT,
    author TEXT NOT NULL,
    date TEXT NOT NULL,
    version INTEGER NOT NULL,
    status TEXT NOT NULL,
    security_domain TEXT,
    datamodel TEXT,                          -- JSON array: parsed from search
    -- Metadata
    file_path TEXT,
    raw_yaml TEXT,
    ingested_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================
-- Deployments (scheduling + alert actions)
-- ============================================================

CREATE TABLE deployments (
    id TEXT PRIMARY KEY,
    content_root_id TEXT REFERENCES content_roots(id),
    name TEXT NOT NULL,
    description TEXT,
    type TEXT NOT NULL,                      -- TTP, Anomaly, Hunting, Correlation, Baseline
    -- Scheduling
    cron_schedule TEXT,
    earliest_time TEXT,
    latest_time TEXT,
    schedule_window TEXT,
    -- Alert actions (JSON blobs for flexibility)
    alert_action_notable TEXT,              -- JSON: {rule_description, rule_title, nes_fields}
    alert_action_rba TEXT,                  -- JSON: {enabled}
    alert_action_email TEXT,                -- JSON: {message, subject, to}
    alert_action_slack TEXT,                -- JSON: {channel, message}
    alert_action_phantom TEXT,              -- JSON: {cam_workers, label, server, sensitivity, severity}
    -- Metadata
    file_path TEXT,
    raw_yaml TEXT,
    ingested_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================
-- Cross-Reference Tables (all use IDs, not names)
-- ============================================================

CREATE TABLE detection_stories (
    detection_id TEXT REFERENCES detections(id) ON DELETE CASCADE,
    story_id TEXT REFERENCES stories(id) ON DELETE CASCADE,
    PRIMARY KEY (detection_id, story_id)
);
CREATE INDEX idx_det_stories_story ON detection_stories(story_id);

CREATE TABLE detection_datasources (
    detection_id TEXT REFERENCES detections(id) ON DELETE CASCADE,
    datasource_id TEXT REFERENCES data_sources(id) ON DELETE CASCADE,
    PRIMARY KEY (detection_id, datasource_id)
);
CREATE INDEX idx_det_ds_datasource ON detection_datasources(datasource_id);

-- detection_datasource_names: for data_source strings that don't resolve to a data_source entity
CREATE TABLE detection_datasource_names (
    detection_id TEXT REFERENCES detections(id) ON DELETE CASCADE,
    datasource_name TEXT NOT NULL,
    PRIMARY KEY (detection_id, datasource_name)
);

CREATE TABLE detection_mitre (
    detection_id TEXT REFERENCES detections(id) ON DELETE CASCADE,
    technique_id TEXT REFERENCES mitre_techniques(id),
    PRIMARY KEY (detection_id, technique_id)
);
CREATE INDEX idx_det_mitre_technique ON detection_mitre(technique_id);

CREATE TABLE detection_cves (
    detection_id TEXT REFERENCES detections(id) ON DELETE CASCADE,
    cve_id TEXT NOT NULL,
    PRIMARY KEY (detection_id, cve_id)
);

CREATE TABLE detection_macros (
    detection_id TEXT REFERENCES detections(id) ON DELETE CASCADE,
    macro_id TEXT REFERENCES macros(id) ON DELETE CASCADE,
    PRIMARY KEY (detection_id, macro_id)
);

CREATE TABLE detection_lookups (
    detection_id TEXT REFERENCES detections(id) ON DELETE CASCADE,
    lookup_id TEXT REFERENCES lookups(id) ON DELETE CASCADE,
    PRIMARY KEY (detection_id, lookup_id)
);

CREATE TABLE detection_baselines (
    detection_id TEXT REFERENCES detections(id) ON DELETE CASCADE,
    baseline_id TEXT REFERENCES baselines(id) ON DELETE CASCADE,
    PRIMARY KEY (detection_id, baseline_id)
);

CREATE TABLE detection_atomic_guids (
    detection_id TEXT REFERENCES detections(id) ON DELETE CASCADE,
    guid TEXT NOT NULL,                      -- Atomic Red Team test GUID
    PRIMARY KEY (detection_id, guid)
);

CREATE TABLE story_baselines (
    story_id TEXT REFERENCES stories(id) ON DELETE CASCADE,
    baseline_id TEXT REFERENCES baselines(id) ON DELETE CASCADE,
    PRIMARY KEY (story_id, baseline_id)
);

-- ============================================================
-- MITRE ATT&CK Reference Data
-- ============================================================

CREATE TABLE mitre_techniques (
    id TEXT PRIMARY KEY,                    -- T1197, T1059.001, etc.
    name TEXT NOT NULL,
    description TEXT,
    is_subtechnique BOOLEAN DEFAULT FALSE,
    url TEXT,                               -- https://attack.mitre.org/techniques/T1059/001/
    tactics TEXT NOT NULL,                  -- JSON array of tactic shortnames
    platforms TEXT,                          -- JSON array: Windows, Linux, macOS, etc.
    data_sources_mitre TEXT                  -- JSON array: MITRE-defined data source names
);

CREATE TABLE mitre_tactics (
    shortname TEXT PRIMARY KEY,             -- execution, persistence, etc.
    name TEXT NOT NULL,                     -- Execution, Persistence, etc.
    external_id TEXT NOT NULL,              -- TA0002, TA0003, etc.
    description TEXT,
    sort_order INTEGER NOT NULL             -- kill chain order (0-13)
);

CREATE TABLE mitre_groups (
    id TEXT PRIMARY KEY,                    -- G0007, G0016, etc.
    name TEXT NOT NULL,                     -- APT28, APT29, etc.
    aliases TEXT,                           -- JSON array of known aliases
    description TEXT,
    url TEXT                                -- https://attack.mitre.org/groups/G0007/
);

CREATE TABLE mitre_group_techniques (
    group_id TEXT REFERENCES mitre_groups(id) ON DELETE CASCADE,
    technique_id TEXT REFERENCES mitre_techniques(id) ON DELETE CASCADE,
    PRIMARY KEY (group_id, technique_id)
);
CREATE INDEX idx_group_tech_technique ON mitre_group_techniques(technique_id);

-- ============================================================
-- Environment & Enablement Tracking
-- ============================================================

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
    detection_id TEXT REFERENCES detections(id) ON DELETE CASCADE,
    status TEXT CHECK(status IN ('backlog','later','blocked','now','done')) NOT NULL,
    changed_by TEXT,
    changed_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (environment_id, detection_id)
);
CREATE INDEX idx_enablement_detection ON enablement_statuses(detection_id);

-- ============================================================
-- Deprecation Tracking
-- ============================================================

CREATE TABLE deprecation_mappings (
    content_id TEXT PRIMARY KEY,             -- UUID of deprecated/removed content
    content_name TEXT NOT NULL,
    content_type TEXT NOT NULL,              -- detection, story, etc.
    reason TEXT,                             -- why it was deprecated
    replacement_id TEXT,                     -- UUID of replacement content (nullable)
    replacement_name TEXT,
    removed_in_version TEXT                  -- app version when fully removed
);

-- ============================================================
-- Multi-tenancy (deferred — schema-ready, not enforced initially)
-- ============================================================

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

-- ============================================================
-- Splunk Connections
-- ============================================================

CREATE TABLE splunk_connections (
    id TEXT PRIMARY KEY,
    tenant_id TEXT REFERENCES tenants(id),
    name TEXT NOT NULL,
    base_url TEXT NOT NULL,                  -- https://splunk.example.com:8089
    auth_type TEXT,                          -- token, basic, saml
    encrypted_credentials TEXT,             -- encrypted at rest
    environment_id TEXT REFERENCES environments(id),
    created_by TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================
-- AI Configuration
-- ============================================================

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
    entity_type TEXT CHECK(entity_type IN (
        'detection','story','datasource','mitre','threat_group','baseline','lookup'
    )) NOT NULL,
    template TEXT NOT NULL,
    updated_by TEXT,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, entity_type)
);

CREATE TABLE ai_conversations (
    id TEXT PRIMARY KEY,
    tenant_id TEXT,
    user_id TEXT,
    entity_type TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    messages TEXT NOT NULL,                  -- JSON array of {role, content} messages
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_ai_conv_entity ON ai_conversations(entity_type, entity_id);

-- ============================================================
-- Audit Log
-- ============================================================

CREATE TABLE audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    tenant_id TEXT,
    user_id TEXT,
    action TEXT NOT NULL,                    -- e.g., 'enablement.change', 'ai.query', 'search.run'
    entity_type TEXT,
    entity_id TEXT,
    details TEXT,                            -- JSON blob with action-specific data
    ip_address TEXT
);

CREATE INDEX idx_audit_tenant_time ON audit_log(tenant_id, timestamp DESC);
CREATE INDEX idx_audit_action ON audit_log(action);

-- ============================================================
-- Full-Text Search (FTS5)
-- ============================================================

CREATE VIRTUAL TABLE detections_fts USING fts5(
    name, description, search, how_to_implement, known_false_positives, author,
    content='detections', content_rowid='rowid'
);

CREATE VIRTUAL TABLE stories_fts USING fts5(
    name, description, narrative, author,
    content='stories', content_rowid='rowid'
);

CREATE VIRTUAL TABLE datasources_fts USING fts5(
    name, description, source, sourcetype,
    content='data_sources', content_rowid='rowid'
);
```

---

## API Routes

### Content (read-only, populated from YAML ingestion)

| Method | Route | Description |
|--------|-------|-------------|
| GET | `/api/detections` | List detections (paginated, filterable, searchable) |
| GET | `/api/detections/:id` | Detection detail with all cross-references, RBA, drilldowns, tests |
| GET | `/api/stories` | List stories (filterable by category, usecase, status) |
| GET | `/api/stories/:id` | Story detail with member detections, aggregated MITRE/data sources |
| GET | `/api/datasources` | List data sources |
| GET | `/api/datasources/:id` | Data source detail with field mappings, example log, supported TAs |
| GET | `/api/macros` | List macros |
| GET | `/api/macros/:id` | Macro detail with referencing detections |
| GET | `/api/lookups` | List lookups (filterable by type: csv/kvstore/mlmodel) |
| GET | `/api/lookups/:id` | Lookup detail with CSV preview, KVStore fields, referencing detections |
| GET | `/api/baselines` | List baselines |
| GET | `/api/baselines/:id` | Baseline detail with related stories and detections |
| GET | `/api/deployments` | List deployment configs |
| GET | `/api/deployments/:id` | Deployment detail with scheduling and alert actions |

### MITRE ATT&CK & Threat Groups

| Method | Route | Description |
|--------|-------|-------------|
| GET | `/api/mitre/techniques` | All techniques with detection counts |
| GET | `/api/mitre/techniques/:id` | Technique detail with detections, groups, data sources |
| GET | `/api/mitre/tactics` | All tactics in kill-chain order |
| GET | `/api/mitre/matrix` | Matrix structure (tactics × techniques) with coverage counts |
| GET | `/api/mitre/groups` | All threat groups with technique/detection counts |
| GET | `/api/mitre/groups/:id` | Group detail: profile, techniques, detection coverage |
| GET | `/api/mitre/groups/:id/coverage` | Coverage analysis: covered vs uncovered techniques for this group |

### Graph & Search

| Method | Route | Description |
|--------|-------|-------------|
| GET | `/api/graph/:entityType/:entityId` | Ego-centric graph data for an entity |
| POST | `/api/search` | Full-text search across all entity types |
| GET | `/api/search/filters` | Available filter values (types, statuses, domains, categories, etc.) |

### Content Roots

| Method | Route | Description |
|--------|-------|-------------|
| GET | `/api/content-roots` | List configured content roots with stats |
| GET | `/api/content-roots/:id` | Content root detail with git info, entity counts |
| POST | `/api/content-roots/:id/ingest` | Trigger re-ingestion of a specific root |

### Environments & Enablement

| Method | Route | Description |
|--------|-------|-------------|
| GET | `/api/environments` | List environments |
| POST | `/api/environments` | Create environment |
| PUT | `/api/environments/:id` | Update environment |
| DELETE | `/api/environments/:id` | Delete environment |
| GET | `/api/environments/:id/statuses` | All detection statuses for an environment |
| PUT | `/api/environments/:envId/detections/:detId` | Set enablement status |
| PATCH | `/api/environments/:envId/detections` | Bulk update statuses |
| GET | `/api/environments/:id/export` | Export as YAML sidecar |
| POST | `/api/environments/import` | Import YAML sidecar |
| GET | `/api/environments/compare/:id1/:id2` | Compare two environments (diff) |

### Compliance & Frameworks

| Method | Route | Description |
|--------|-------|-------------|
| GET | `/api/compliance/nist` | NIST CSF coverage summary (categories → detection counts) |
| GET | `/api/compliance/cis` | CIS Controls coverage summary |
| GET | `/api/compliance/killchain` | Kill chain phase coverage summary |
| GET | `/api/compliance/:framework/:category` | Detections mapped to a specific framework category |

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
| GET | `/api/ai/conversations/:entityType/:entityId` | Get conversation history for an entity |
| DELETE | `/api/ai/conversations/:id` | Delete a conversation |

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
| POST | `/api/ingest/trigger` | Trigger full re-ingestion of all content roots |
| GET | `/api/ingest/status` | Current ingestion status / last run per root |

### Export & Reporting

| Method | Route | Description |
|--------|-------|-------------|
| GET | `/api/export/detections` | Export filtered detection list as CSV/JSON |
| GET | `/api/export/matrix` | Export MITRE matrix coverage as CSV |
| GET | `/api/export/coverage/:groupId` | Export threat group coverage analysis |

---

## Phases

### Phase 1 — Foundation & Full Ingestion (Week 1-2)

**Goal**: Server running, ALL content types ingested from multiple roots, basic browsing works for every entity.

- [ ] Project scaffolding (Bun + Hono + Vite + Svelte 5)
- [ ] SQLite schema creation with numbered migration scripts
- [ ] Multi-root configuration loading from `eagle-eye.config.yaml`
- [ ] YAML ingestion engine (TypeScript, replacing v1 `build.py`)
  - [ ] Content root discovery and git metadata extraction
  - [ ] Recursive detection loading with ALL fields (RBA, drilldowns, throttling, tests, atomic_guid, compliance tags)
  - [ ] Story loading with all fields (category, usecase, order)
  - [ ] Data source loading with field mappings, example logs, supported TAs
  - [ ] Macro loading with argument extraction
  - [ ] Lookup loading (CSV, KVStore, MLModel) with data preview
  - [ ] Baseline loading with scheduling and related stories
  - [ ] Deployment loading with scheduling and alert actions
  - [ ] Cross-reference resolution (all `*_xref` tables via IDs)
  - [ ] Provenance tracking: every entity tagged with its `content_root_id`
  - [ ] Duplicate detection: flag same-name entities across different roots
- [ ] MITRE ATT&CK STIX data fetch + cache (techniques, tactics, groups, group→technique mappings)
- [ ] Core API routes: detections, stories, datasources, macros, lookups, baselines, deployments, mitre
- [ ] Full-text search (SQLite FTS5 across all entity types)
- [ ] Frontend: detection list view
  - [ ] Rich filter panel (status, type, severity, product, domain, data_source, content root)
  - [ ] Search with FTS5
  - [ ] Breakdown bars on list items (enablement status counts)
  - [ ] SPL preview with syntax highlighting (custom tokenizer)
- [ ] Frontend: detection detail panel
  - [ ] All metadata fields (how_to_implement, known_false_positives, references)
  - [ ] RBA section (risk objects, threat objects, message template)
  - [ ] Drilldown searches list
  - [ ] Tests section with attack data links
  - [ ] Compliance tags (NIST, CIS, kill chain)
  - [ ] Cross-entity links (stories, data sources, MITRE techniques)
  - [ ] Content root provenance badge
  - [ ] "Copy SPL" button
  - [ ] CVE references → NVD links, MITRE technique IDs → ATT&CK links
- [ ] Frontend: story list + detail (with member detection list, aggregated MITRE coverage)
- [ ] Frontend: data source list + detail (with field mappings table, example log, referencing detections)
- [ ] Frontend: macro list + detail (with referencing detections)
- [ ] Frontend: lookup list + detail (with CSV data preview, field schema)
- [ ] Frontend: baseline list + detail (with related stories)
- [ ] Frontend: deployment list + detail (with scheduling, alert actions)
- [ ] Verification: all content loaded, all fields surfaced, multi-root provenance visible

### Phase 2 — Environments & Enablement (Week 3)

**Goal**: Full enablement tracking with server-side persistence, v1 feature parity for enablement.

- [ ] Environment CRUD API
- [ ] Enablement status API (set, bulk update)
- [ ] YAML sidecar import/export endpoints
- [ ] Environment comparison (diff) API
- [ ] Frontend: environment selector (top bar, persistent across views)
- [ ] Frontend: enablement badges on detections (color-coded status)
- [ ] Frontend: breakdown bars on stories and data sources (stacked status counts)
- [ ] Frontend: status picker (click badge → dropdown → change status)
- [ ] Frontend: bulk status update (select multiple → set status)
- [ ] Content root scoping in environments (enable/disable detections per-root)
- [ ] Migration utility: v1 localStorage/YAML data → v2 API import
- [ ] Verification: all v1 enablement features working with server persistence

### Phase 3 — Graph, Matrix & Threat Groups (Week 4)

**Goal**: Interactive graph, MITRE matrix, and threat group views with full interactivity.

- [ ] Graph data API (ego-centric subgraph extraction with depth control)
- [ ] Frontend: Cytoscape.js graph view
  - [ ] Node types: detection, story, datasource, mitre_technique (4 colors)
  - [ ] Enablement status rings on detection nodes
  - [ ] Graph scope mode (toggle full graph vs ego-centric)
  - [ ] Tap → select/highlight, double-tap → navigate to entity detail
  - [ ] Expand/collapse neighbors on interaction
  - [ ] Graph search and focus-on-node
  - [ ] Performance: cose layout, virtualization for large graphs
- [ ] Frontend: MITRE ATT&CK coverage matrix
  - [ ] Tactics as columns, techniques as rows
  - [ ] Cell color intensity by detection count
  - [ ] Sub-technique expansion (click to drill into sub-techniques)
  - [ ] Filter by environment enablement status
  - [ ] Click cell → show detections for that technique
- [ ] Frontend: Threat Groups view (NEW — dedicated tab)
  - [ ] Group list with search (by name, aliases, associated software)
  - [ ] Group detail: description, external references, known aliases
  - [ ] Technique heatmap per group (which techniques does this group use?)
  - [ ] Detection coverage analysis: covered vs uncovered techniques
  - [ ] "Gaps" view: techniques used by group with zero detection coverage
  - [ ] Cross-link to detection and technique detail views
- [ ] Frontend: Compliance/frameworks view
  - [ ] NIST CSF coverage summary (categories → detection counts)
  - [ ] CIS Controls coverage summary
  - [ ] Kill chain phase coverage summary
  - [ ] Drill into any category to see mapped detections
- [ ] Graph performance testing at full content scale (3000+ detections, 600+ techniques)

### Phase 4 — AI Enrichment (Week 5)

**Goal**: Server-side AI proxy with conversation persistence. Zero CORS issues, streaming works perfectly.

- [ ] AI config CRUD API (encrypted credential storage)
- [ ] Server-side chat proxy with SSE streaming
  - [ ] Support: Ollama, Docker Model Runner, OpenRouter (v1 parity)
  - [ ] AbortController support (cancel in-flight requests)
  - [ ] Error handling with user-friendly messages
- [ ] Per-entity-type prompt templates (CRUD + defaults)
  - [ ] Variable chip insertion: `{{detection.search}}`, `{{detection.description}}`, etc.
  - [ ] Templates for all entity types (detection, story, datasource, technique, group)
- [ ] Conversation history persistence (per-user, per-entity → `ai_conversations` table)
- [ ] Frontend: AI analysis panel on all entity detail views
  - [ ] Streaming response display with markdown rendering (marked.js)
  - [ ] Follow-up conversation support
  - [ ] "New Conversation" / "Clear History" buttons
  - [ ] Auto-scroll during streaming
  - [ ] Cancel button during streaming
- [ ] Frontend: AI settings management (providers, models, prompt templates)

### Phase 5 — Splunk Integration (Week 6)

**Goal**: Live detection status from Splunk, test search execution.

- [ ] Splunk connection management (encrypted credentials)
- [ ] Connection test endpoint
- [ ] Detection status polling (check if saved search exists + is enabled)
- [ ] Status sync: Splunk enabled state → enablement status
- [ ] Test search execution (submit SPL, poll for results, stream back)
- [ ] Frontend: live status indicator on detections
- [ ] Frontend: "Run Test Search" button on detection detail
- [ ] Frontend: search results display (tabular, scrollable)
- [ ] Rate limiting and connection pooling for Splunk API calls

### Phase 6 — Auth, Audit & Administration (Week 7)

**Goal**: Production-ready security, audit trail, and user management.

> **Note**: Multi-tenancy is schema-ready (tenant_id columns exist) but NOT enforced in Phase 6.
> Tenant isolation will be added in a future release when the use case is validated.

- [ ] Authentication system (session-based)
  - [ ] Local auth (email + password) for simple deployments
  - [ ] SSO/OIDC integration (optional, for enterprise)
- [ ] Role-based access control (viewer, editor, admin)
- [ ] Audit logging middleware (automatic for all write operations)
- [ ] Audit log query API + export (CSV, JSON)
- [ ] Content root access control (restrict which roots a user can see)
- [ ] Frontend: login page
- [ ] Frontend: user management (admin)
- [ ] Frontend: audit log viewer
- [ ] Credential encryption at rest (AI keys, Splunk tokens)

### Phase 7 — Polish, UX & Deployment (Week 8)

**Goal**: Production-quality UX, deployment options, documentation. Full v1 feature parity verified.

- [ ] Error handling and validation across all APIs
- [ ] Loading states, error states, empty states in frontend
- [ ] Toast notification system (success/error/info, auto-dismiss)
- [ ] Responsive layout (tablet-friendly at minimum)
- [ ] Dark theme (default, matching v1) + light theme toggle
- [ ] Keyboard navigation and accessibility
  - [ ] Escape → close panels/modals
  - [ ] Enter → confirm actions
  - [ ] Tab navigation through interactive elements
  - [ ] ARIA labels on all interactive elements
- [ ] Cross-entity navigation
  - [ ] Pivot banners: "View in Stories" / "View in Graph" / "View detections for this technique"
  - [ ] Back/forward navigation stack
  - [ ] Breadcrumb trail
- [ ] Deprecation awareness
  - [ ] Visual indicator on deprecated detections
  - [ ] "Deprecated by" link to replacement detection
  - [ ] Filter to hide/show deprecated content
- [ ] Content root management UI
  - [ ] Add/remove/edit content roots
  - [ ] Per-root ingestion trigger and status display
  - [ ] Root health indicators (last ingested, entity counts, errors)
- [ ] Export/reporting
  - [ ] Export filtered detection list as CSV/JSON
  - [ ] Export MITRE matrix coverage as CSV
  - [ ] Export threat group coverage analysis
- [ ] Docker container build (Bun + SQLite + static frontend)
- [ ] `bun build --compile` single binary option
- [ ] Environment variable configuration (ports, DB path, secrets)
- [ ] README and deployment guide
- [ ] Content ingestion watch mode (auto-reload on YAML changes via `fs.watch`)
- [ ] Performance testing at scale (5K+ detections across multiple content roots)
- [ ] v1 Feature Parity Checklist sign-off (see Appendix A)

---

## Non-Functional Requirements

| Requirement | Target |
|-------------|--------|
| Cold start | < 2 seconds (server ready to serve requests) |
| Ingestion (single root) | < 30 seconds for ~3000 detections |
| Ingestion (multi-root) | Parallelized per root; < 60 seconds for 3 roots |
| Search latency | < 100ms for FTS5 across all entity types |
| API response | < 200ms for list endpoints, < 50ms for detail endpoints |
| Graph render | < 1 second for 500-node ego graph |
| Matrix render | < 500ms for full MITRE matrix (600+ techniques) |
| Concurrent users | 50+ (SQLite WAL mode) |
| Detection scale | 10,000+ detections across all content roots without degradation |
| Content roots | Up to 10 roots simultaneously |
| Data at rest | All credentials encrypted (API keys, Splunk tokens) |
| Audit retention | 90 days default, configurable |
| Deployment | Single Docker image or single compiled binary |
| Offline | Works without internet (MITRE data cached in SQLite) |
| Backup | SQLite `.backup()` API, documented backup/restore procedure |
| Schema migration | Forward-only numbered SQL scripts, applied on startup |

---

## Migration from v1

| v1 Feature | v2 Equivalent | Migration Path |
|------------|---------------|----------------|
| `%%DATA_JSON%%` template injection | SQLite ingestion + REST API | Automatic — v2 reads same YAML source |
| `localStorage` environment data | `environments` + `enablement_statuses` tables | One-time import: export v1 localStorage JSON → `POST /api/environments/import` |
| `localStorage` AI config | `ai_configs` table (encrypted) | Manual re-entry (secrets should not be exported) |
| Client-side `fetch()` to AI providers | Server-side proxy `/api/ai/chat` | Reconfigure same providers in v2 settings UI |
| YAML sidecar env files | Import → `environments` + `enablement_statuses` tables | `POST /api/environments/import` accepts v1 YAML format |
| Cytoscape.js CDN load | Bundled via Vite (offline-capable) | Automatic |
| `build.py` YAML parser | TypeScript ingestion engine with watch mode | v2 reads same YAML files from same directory |
| Browser-only persistence | SQLite database file (backupable, portable) | Data persists server-side; no user action needed |
| Single content directory | Multi-root content architecture | Configure additional roots in `eagle-eye.config.yaml` |
| No conversation history | `ai_conversations` table | New feature — no migration needed |
| No threat group data | MITRE STIX group ingestion | New feature — automatic on first ingestion |
| No RBA/drilldown display | Full RBA, drilldown, test sections | New feature — data already in YAML, now surfaced |

### Migration Utility

A CLI helper (`bun run migrate-v1`) will:
1. Read v1 `build.py` output JSON (if available) for verification
2. Accept v1 localStorage export JSON and convert to v2 environment import format
3. Accept v1 YAML sidecar files and import via API
4. Produce a migration report showing what was imported

---

## Open Decisions

### Resolved

- [x] **Frontend framework**: Svelte 5 — v1's ~3300 lines of vanilla JS maps naturally to Svelte components; runes handle reactive state elegantly; smaller bundle than React for this use case
- [x] **YAML field coverage**: ALL fields surfaced — complete schema in Data Model section
- [x] **Multi-tenancy timing**: Schema-ready (tenant_id columns) but NOT enforced until validated
- [x] **SPL display**: Custom tokenizer for syntax highlighting (command, pipe, keyword, string, field coloring)

### Open

- [ ] **Auth provider**: Built-in local auth vs OIDC-only vs both (leaning: both, local as default)
- [ ] **Deployment target**: Docker-first vs binary-first vs both (leaning: both, Docker as primary)
- [ ] **Repository structure**: Monorepo with `packages/server` + `packages/frontend` vs flat (leaning: monorepo for clean separation)
- [ ] **Content ingestion trigger**: File watcher (auto) vs API trigger (manual) vs both (leaning: both, watcher default in dev)
- [ ] **Splunk auth**: Per-user Splunk tokens vs shared service account per connection (leaning: shared service account, simpler for teams)
- [ ] **Content conflict resolution**: When same detection ID exists in multiple roots — last-wins vs primary-root-wins vs flag-for-user (leaning: primary-root-wins with override flag)
- [ ] **Graph layout algorithm**: cose (v1 default) vs cola vs dagre for different graph types
- [ ] **Offline MITRE updates**: How to update STIX data when running offline (leaning: CLI command `bun run update-mitre` with bundled fallback)

---

## Appendix A: v1 Feature Parity Checklist

Every feature from v1 (`template.html`) that must exist in v2 before launch.

### Views
- [ ] Detection list with search, filter, breakdown bars
- [ ] Detection detail with all metadata
- [ ] Story list with search, filter, breakdown bars
- [ ] Story detail with member detections
- [ ] Data Source list with search, referencing detection count
- [ ] Data Source detail with referencing detections
- [ ] MITRE Technique list with detection counts
- [ ] MITRE ATT&CK Matrix (tactics × techniques, color-coded)
- [ ] Graph view (Cytoscape.js, 4 node types, enablement rings)

### Interactions
- [ ] Environment selector (top bar, persists across views)
- [ ] Enablement badge click → status picker
- [ ] Breakdown bars on list items (stacked status counts)
- [ ] Copy SPL button
- [ ] Cross-entity pivot links (detection → story, story → detections, etc.)
- [ ] Pivot banners ("View in Graph", "View in Stories", etc.)
- [ ] Graph: tap → select, double-tap → navigate
- [ ] Graph: expand/collapse neighbors
- [ ] Graph: scope mode toggle (full vs ego-centric)
- [ ] Matrix: sub-technique expansion/collapse
- [ ] Matrix: click cell → see detections
- [ ] External links: MITRE IDs → ATT&CK website, CVEs → NVD
- [ ] Search across all entity types

### AI Features
- [ ] AI analysis panel on entity detail views
- [ ] Support for Ollama, Docker Model Runner, OpenRouter
- [ ] Streaming responses (SSE)
- [ ] Abort/cancel in-flight request
- [ ] Follow-up conversations
- [ ] Per-entity-type prompt templates
- [ ] Variable chip insertion in prompt editor
- [ ] Markdown rendering in AI responses
- [ ] Auto-scroll during streaming

### UX
- [ ] Dark theme (default)
- [ ] Toast notifications (success, error, info)
- [ ] Loading states on all async operations
- [ ] Escape key closes panels/modals
- [ ] Error states with actionable messages

## Appendix B: Splunk REST API Endpoints

| Endpoint | Purpose |
|----------|---------|
| `GET /services/saved/searches/{name}` | Check if detection exists as saved search |
| `GET /services/saved/searches/{name}?output_mode=json` | Get enabled/disabled status |
| `POST /services/search/jobs` | Submit a search job |
| `GET /services/search/jobs/{sid}` | Check search job status |
| `GET /services/search/jobs/{sid}/results` | Get search results |
| `GET /services/server/info` | Test connection / get Splunk version |

## Appendix C: Content Type Coverage Matrix

Summary of which content types are fully surfaced, partially surfaced, or excluded.

| Content Type | v1 Status | v2 Status | Notes |
|--------------|-----------|-----------|-------|
| Detections | Partial (missing RBA, drilldowns, tests, compliance) | **Full** | All fields surfaced |
| Stories | Partial (missing category, usecase, order) | **Full** | All fields surfaced |
| Data Sources | Partial (missing field mappings, example log) | **Full** | All fields surfaced |
| Macros | Reference only (extracted from SPL) | **Full** | Loaded from YAML with args, proper IDs |
| Lookups (CSV) | Not surfaced | **Full** | Data preview, referencing detections |
| Lookups (KVStore) | Not surfaced | **Full** | Field schema display |
| Lookups (MLModel) | Not surfaced | **Full** | Model metadata |
| Baselines | Not surfaced | **Full** | Related stories, scheduling |
| Deployments | Not surfaced | **Full** | Scheduling, alert actions |
| MITRE Techniques | Partial (no sub-technique hierarchy) | **Full** | Sub-techniques, data sources |
| MITRE Tactics | List only | **Full** | Kill chain ordering |
| MITRE Groups | Not surfaced | **Full** | First-class view with coverage analysis |
| Workbooks | Not surfaced | **Excluded** | JSON format, low analyst value in Eagle Eye |
| Response Templates | Not surfaced | **Excluded** | Phantom/SOAR-specific |
| Notebooks | Not surfaced | **Excluded** | Jupyter format, specialized tooling |
| Investigations | Not surfaced | **Excluded** | Legacy type, deprecated in contentctl |
| Playbooks | Not surfaced | **Excluded** | Phantom/SOAR-specific |
| Dashboards | Not surfaced | **Excluded** | SimpleXML, better viewed in Splunk |

## Appendix D: Enum Reference

Key enums used in the data model, matching contentctl definitions.

| Enum | Values |
|------|--------|
| `AnalyticsType` | Anomaly, Correlation, Hunting, TTP |
| `DetectionStatus` | Production, Validation, Experimental, Deprecated |
| `SecurityDomain` | Access, Endpoint, Network, Threat, Identity, Audit |
| `AssetType` | Endpoint, IP Address, AWS Account, URL, User, Email Address, Process Name, System, Other |
| `RiskSeverity` | Critical, High, Medium, Low, Informational |
| `DataModel` | Authentication, Change, Email, Endpoint, Network_Resolution, Network_Sessions, Network_Traffic, Risk, Splunk_Audit, UEBA, Updates, Vulnerabilities, Web |
| `NistCategory` | DE.AE, DE.CM, ID.AM, ID.RA, PR.AC, PR.DS, PR.IP, PR.PT, RS.CO, RS.MI, RS.AN |
| `CISControl` | CIS 1 through CIS 20 |
| `KillChainPhase` | Reconnaissance, Weaponization, Delivery, Exploitation, Installation, Command And Control, Actions On Objectives |
| `EnablementStatus` | Enabled, Disabled, Under Review, Planned (user-defined per environment) |
