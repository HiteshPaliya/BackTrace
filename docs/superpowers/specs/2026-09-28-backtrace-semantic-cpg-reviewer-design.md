# System Architecture & Design Specification: BackTrace Semantic CPG Security Reviewer

## 1. Executive Summary & Core Philosophy

This specification defines the architecture, data models, semantic matrices, graph schema, and operational boundaries for **BackTrace**, an offensive-minded polyglot source code security review system.

BackTrace is engineered to discover high-impact vulnerabilities (e.g., Remote Code Execution, SQL Injection, Authentication/Authorization Bypasses, BOLA/IDOR, SSRF, Path Traversal, XXE, NoSQL Injection, Insecure Deserialization, and Hardcoded Secrets) through automated semantic analysis, deterministic repository-level code property graphs (CPG), and evidence-gated agentic verification.

### Core Architectural Principles

1. **Persistent CPG as Primary Semantic Spine:**  
   The persistent Code Property Graph (CPG) constructed from Tree-sitter ASTs, symbol tables, and deterministic framework resolvers is the authoritative primary analysis layer. External scanners (OWASP Noir, Semgrep, TruffleHog) act as **evidence producers and corroborators**, enriching graph nodes rather than defining graph architecture.
2. **Dual-Track Analysis Pipeline:**  
   Vulnerabilities are divided into two parallel, non-conflated analysis tracks:
   - **Track A (Semantic Data Flow):** `Source → Propagation → Transform / Sanitizer / Validator → Propagation → Sink`.
   - **Track B (Authorization Relationships):** `Principal ↔ Object ID ↔ Authorization Boundary` (BOLA/IDOR and access control).
3. **Detection vs. Verification Separation:**  
   Built-in static detectors and external adapters emit typed candidate objects (`CANDIDATE_FLOW`, `CANDIDATE_AUTHZ_GAP`) with heuristic resolution confidence. Only the downstream evidence sufficiency gate and agentic verification can assign canonical verdicts (`EXPLOITABLE`, `LIKELY_EXPLOITABLE_PARTIAL_SANITIZATION`, `SAFE_PROVEN`, `INSUFFICIENT_CONTEXT`).
4. **Universal Provenance on All Relationships:**  
   Every edge in the CPG retains explicit provenance, resolution method, evidence, and calibrated confidence. Inferred or agentic edges can never masquerade as deterministic compiler facts.
5. **Decoupled Reachability vs. Exploitability Confidence:**  
   Path reachability confidence (certainty that code can execute from source to sink) is strictly separated from exploitability confidence (certainty that input violates the sink's security contract).
6. **Non-Weaponized Reproduction Templates:**  
   The system generates assertion-oriented, non-weaponized reproduction blueprints using inert markers (`<controlled-test-value>`, `BT_FLOW_MARKER_001`), demonstrating parameter reachability without generating active exploits or shellcode.
7. **Resilient Durable State & Strict Version Gating:**  
   Durable SQLite storage (`.audit/audit.db`) with an append-only, thread-safe event log (`.audit/events.jsonl`). An unaffected finding is only reusable across incremental scans if the comprehensive `engine_fingerprint` matches the current run.

### 1.1 Core Architectural Invariants & Soundness Guarantees

BackTrace strictly enforces eight operational invariants to prevent false-positive explosions, syntax collisions, and ungrounded exploit assertions:

1. **Semantic Sink Detection with Argument Analysis:**  
   Candidate sinks must evaluate argument semantics, not raw identifier text. Hardcoded string literals (e.g. `fetch("https://fixed.example")`, `fs.readFileSync('./swagger.yml')`) and test harness assertions (`request(app)`) are rejected from candidate sink generation. Sinks require variable, dynamic, or user-influenced arguments.
2. **Mandatory Language/Artifact Constraints:**  
   Detectors must declare language and artifact boundaries. Template unescape patterns (`!=`) are restricted strictly to template extensions (`.pug`, `.jade`, `.ejs`) and are never evaluated in JavaScript/TypeScript where `!=` and `!==` represent equality comparisons.
3. **Scope-Gated Detector Eligibility:**  
   Scope classification precedes candidate generation. Files classified as `TEST_MOCK`, `VENDOR_DEPENDENCY`, or `BUILD_OUTPUT_GENERATED` are evaluated by an eligibility filter (`eligible_for_detector(file, detector)`) and denied from emitting web runtime candidate sinks.
4. **Zero Endpoint Fallback Binding:**  
   A finding is bound to an HTTP endpoint only if an unbroken reachability path exists from that route in the CPG. Sinks without a graph-proven route are assigned `reproduction_type = NONE` or `NON_HTTP_TEMPLATE` and marked `INTERNAL_SINK` or `INSUFFICIENT_CONTEXT`. BackTrace forbids fallback assignment to arbitrary endpoints (`endpoints[0]`).
5. **Direct Import & Alias Resolution:**  
   Sink classification operates on resolved symbols rather than receiver text. Direct function imports (e.g. `import { parseXmlString } from '../lib/xml'`) resolve to the underlying implementation in the CPG.
6. **Operation Semantics over Naming Conventions:**  
   Detectors evaluate operation semantics and argument structure rather than lexical naming conventions (e.g. any receiver `.find(...)` with dynamic query objects or operators, regardless of uppercase or lowercase model names).
7. **Authoritative Evidence Gate (Zero Manufactured Proofs):**  
   The Evidence Sufficiency Gate evaluates only real evidence derived from CPG path traversal and contract analysis. The orchestrator is strictly forbidden from supplying synthetic `source_control="CONFIRMED"` or `transform_status="FAILED"` assertions.
8. **Evidence-Derived Confidence:**  
   Confidence is calculated strictly from edge resolution quality, path completeness, and contract verification; it must never be assigned a flat or static default.

---

## 2. Strict Non-Goals (Boundaries & Constraints)

1. **No Active / Dynamic Attack Execution:**  
   BackTrace will never launch live HTTP requests, dynamic probes, or active fuzzing payloads against running servers.
2. **No Weaponized Exploit Generation:**  
   The system produces research dossiers with reproduction blueprints and theoretical bypass reasoning, but will never generate weaponized exploit binaries, memory-corruption payloads, or destructive commands.
3. **No Compliance / Style Linting Bloat:**  
   No generic code smells, formatting checks, or compliance linters. Analysis is restricted to exploitable security weaknesses.
4. **No Monolithic Single-File Context Dumps:**  
   BackTrace decomposes code into targeted reachability slices; it never feeds entire repositories into monolithic LLM prompts.
5. **No Deep Recursive Vendor AST Traversal:**  
   Third-party packages (`node_modules/`, `vendor/`, `site-packages/`) receive shallow export signature harvesting only.
6. **No Uncurated Chain-of-Thought / Raw Scratchpad Persistence:**  
   Internal model monologues, private deliberation tokens, and raw scratchpads are strictly ephemeral. Only curated, structured security evidence is persisted.

---

## 3. High-Level Architecture & Component Topology

```text
                                Repository Source
                                        │
           ┌────────────────────────────┴────────────────────────────┐
           ▼                                                         ▼
 [Tree-sitter AST & SCIP]                                [External Tool Adapters]
(Symbols, Imports, Callsites)                             (Noir, Semgrep, TruffleHog)
           │                                                         │
           ▼                                                         ▼
[Framework Semantic Resolvers]                               [Evidence Ingestion]
(Routes, Middleware, ORMs, DI)                           (Corroborating Sinks/Endpoints)
           │                                                         │
           └────────────────────────────┬────────────────────────────┘
                                        │
                                        ▼
                         [Persistent Repository CPG]
                    (SQLite .audit/audit.db + Memory Cache)
                                        │
                    ┌───────────────────┴───────────────────┐
                    ▼                                       ▼
        [Track A: Data-Flow Engine]             [Track B: AuthZ Analyzer]
   (Source→Transform/Sanitizer→Sink)           (Principal ↔ Object Boundary)
                    │                                       │
                    ▼                                       ▼
             [CANDIDATE_FLOW]                      [CANDIDATE_AUTHZ_GAP]
                    │                                       │
                    └───────────────────┬───────────────────┘
                                        │
                                        ▼
                            [Composite Triage Queue]
                          (Risk, Scope, Exposure, Hops)
                                        │
                                        ▼
                          [Evidence & Verification Gate]
                        ┌───────────────┴───────────────┐
                        ▼                               ▼
               [Contract Analysis]            [Agentic Resolution]
             (Transform vs Sink Precon)     (Linker & Debate Engines)
                        │                               │
                        └───────────────┬───────────────┘
                                        │
                                        ▼
                            [Canonical Final Verdict]
                                        │
                                        ▼
                          [Verified Security Dossiers]
                        (With Reproduction Templates)
                                        │
                 ┌──────────────────────┼──────────────────────┐
                 ▼                      ▼                      ▼
          [SARIF 2.1.0]          [Graph JSON]             [Markdown]
```

---

## 4. Multidimensional Scope Classification

Every discovered repository file is classified across four orthogonal dimensions stored in the SQLite `files` table, accompanied by classification confidence and provenance evidence:

```sql
ALTER TABLE files ADD COLUMN execution_domain TEXT NOT NULL;
ALTER TABLE files ADD COLUMN runtime_role TEXT NOT NULL;
ALTER TABLE files ADD COLUMN environment TEXT NOT NULL;
ALTER TABLE files ADD COLUMN artifact_type TEXT NOT NULL;
ALTER TABLE files ADD COLUMN classification_confidence REAL NOT NULL;
ALTER TABLE files ADD COLUMN classification_evidence TEXT;
```

### 4.1 Dimension Values

1. **`execution_domain`:**
   - `APPLICATION_RUNTIME`: Production backend services, APIs, controllers, handlers, models, workers.
   - `CLIENT_SPA`: Frontend browser client code (Angular, React, Vue, Svelte, client bundles).
   - `CI_CD_PIPELINE`: GitHub Actions workflows, GitLab CI, CircleCI configs, build scripts.
   - `INFRASTRUCTURE_IAC`: Terraform (`*.tf`), CloudFormation, Dockerfile, Kubernetes manifests.
   - `TEST_MOCK`: `*.spec.ts`, `*.test.js`, `tests/`, test doubles, test fixtures.
   - `DATA_SEED_TUTORIAL`: Static challenge definitions, database seeds, interactive tutorial snippets.
   - `VENDOR_DEPENDENCY`: `node_modules/`, `vendor/`, `site-packages/`.
   - `BUILD_OUTPUT_GENERATED`: Minified bundles, generated proto code.

2. **`runtime_role`:**
   - `ENTRYPOINT_ROUTE_HANDLER`: HTTP routes, GraphQL resolvers, RPC handlers.
   - `MIDDLEWARE`: Auth guards, request interceptors, CORS handlers.
   - `SERVICE_BUSINESS_LOGIC`: Domain logic, core business services.
   - `DATA_ACCESS_ORM`: Repositories, models, active record classes.
   - `UTILITY_HELPER`: Generic formatting, string manipulation.
   - `CONFIGURATION`: Environment files, configuration binders.

3. **`environment`:**
   - `PRODUCTION`, `TEST`, `DEVELOPMENT`, `BUILD_TIME`.

4. **`artifact_type`:**
   - Language/syntax: `TYPESCRIPT`, `JAVASCRIPT`, `PYTHON`, `GO`, `JAVA`, `RUBY`, `PHP`, `YAML`, `TERRAFORM`, `DOCKERFILE`.

### 4.2 Scope Rules & Context-Aware Prioritization

- **No Blind Suppression:** Classifying a file as `CI_CD_PIPELINE` does not discard it; instead, findings in that file are evaluated under the **Supply-Chain Threat Model** (`SUPPLY_CHAIN_CI`), never as a web-facing `CRITICAL_RCE`.
- **Test / Mock Scope Handling:** Files with `TEST_MOCK` or `DATA_SEED_TUTORIAL` are excluded from default production security dossiers **unless**:
  1. A production file directly imports the test/mock file.
  2. A production runtime configuration or build manifest registers the file into the production bundle.
- **Classification Evidence:** Every classification carries `confidence` and `evidence` (e.g. `evidence="directory: .github/workflows, parser: yaml, confidence: 0.98"`).

---

## 5. Framework Semantic Resolvers

Framework resolvers translate high-level framework patterns into authoritative CPG elements before reachability analysis.

### 5.1 Evidence-Based Framework Identity
Resolvers detect frameworks using manifest and lockfile evidence:
- Node.js: `package.json`, `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock` (Express, Fastify, NestJS, Koa).
- Python: `pyproject.toml`, `requirements.txt`, `poetry.lock` (FastAPI, Django, Flask).
- Java: `pom.xml`, `build.gradle` (Spring Boot, Jakarta).
- Go: `go.mod`, `go.sum` (Gin, Chi, Echo).

### 5.2 Deterministic Route & Middleware Composition
The resolver handles hierarchical route prefixes and mounting:
1. **Route Prefix Composition:**
   - `app.use("/api/v1", userRouter)` mounted with `router.post("/login", handler)` resolves deterministically to `POST /api/v1/login`.
2. **Inherited & Global Middleware Resolution:**
   - Middleware applied via `app.use(authGuard)` is inherited by all mounted sub-routers and endpoints.
3. **Tri-State Authentication State (`auth_state`):**
   Endpoints do not assume binary True/False auth:
   - `REQUIRED`: Explicit authentication middleware detected (`passport.authenticate`, `jwt.verify`, `@login_required`).
   - `NOT_REQUIRED`: Explicit public route annotation or public bypass configured.
   - `UNKNOWN`: Unrecognized or custom middleware detected; receives conservative triage weighting.
4. **Semantic Data-Layer Classification:**
   - Raw queries (`sequelize.query()`, `db.raw()`, `cursor.execute()`) are tagged as `RAW_SQL_SINK`.
   - ORM operations (`UserModel.findOne(...)`, `Basket.findByPk(...)`) are tagged as `ORM_DATA_ACCESS` (a semantic operation category, not an assertion of safety).

---

## 6. Dual-Track Analysis Matrices

### 6.1 Track A: Semantic Data-Flow Matrix

#### Sources (Untrusted Entrypoints)
- **HTTP Request Context:** `req.body`, `req.query`, `req.params`, `req.headers`, `req.cookies`, FastAPI parameter bindings, Django `request.GET/POST`, Spring `@RequestParam`/`@RequestBody`.
- **External Message Streams:** Webhooks, message queues (`amqp`, `kafka`), uploaded files (`req.file`).
- **Second-Order Persistence Sources:** Reads of untrusted user fields retrieved from the database.

#### Propagation & Transforms
Transforms specify their semantic nature and security contract:

| Category | Operations | Semantic Effect | Contract Note |
|---|---|---|---|
| **Type Constraint** | `parseInt()`, `Number()`, `int()`, `zod.parse()` | Constrains value domain | Sinks must still be evaluated; does not universally eliminate injection |
| **Path Construction** | `os.path.join()`, `path.join()`, `path.resolve()` | Assembles path segments | Structural transform; filesystem access sink occurs at `open()` / `sendFile()` |
| **Encoding / Decoding** | `decodeURIComponent`, `base64decode`, `unquote` | Alters byte representation | Propagates taint; may unmask bypass payloads |
| **Sanitizers** | `.replace()`, `DOMPurify.sanitize()`, `escapeHtml()` | Modifies/strips tokens | Contract verified against sink syntax requirements |
| **Validation Guards** | `if (!isValid(x)) return`, allowlist lookups | Directs control flow | Branch condition audited for bypasses |

#### Sinks (Categorized by Vulnerability Class)
- **`SQL_EXECUTION`:** Raw query escapes (`sequelize.query`, `db.raw`, `cursor.execute`).
- **`HTTP_REQUEST` (SSRF):** Outbound client calls (`fetch`, `axios.get/post`, `needle`, `request`, `urllib.request`).
- **`FILESYSTEM_ACCESS` (Path Traversal):** File primitives (`res.sendFile`, `fs.readFile`, `open()`, `fs.writeFile`).
- **`COMMAND_EXECUTION` (RCE):** Shell invocation (`child_process.exec`, `os.system`, `subprocess.Popen`).
- **`CODE_EVALUATION` (Code Injection):** Dynamic evaluation (`eval()`, `new Function()`, `vm.runInContext`).
- **`XML_PARSING` (XXE):** XML parsers evaluated against configuration (external entities enabled, DTD enabled).
- **`DESERIALIZATION`:** Unsafe loaders (`yaml.load()`, `pickle.loads()`, `unserialize()`).
- **`NOSQL_QUERY`:** MongoDB/Mongoose query operations with user-controlled query structure, operators (`$where`, `$regex`), or uncast JSON objects.
- **`TEMPLATE_HTML_OUTPUT` (XSS):** Context-aware sinks (HTML body, attribute, JS context, CSS, URL, DOM manipulation).

---

### 6.2 Track B: Authorization Relationship Analyzer (BOLA / IDOR)

Track B reasons about authorization relationships rather than taint flows.

```text
                  Incoming Request: GET /rest/basket/:id
                                    │
       ┌────────────────────────────┴────────────────────────────┐
       ▼                                                         ▼
[Authenticated Principal]                               [Target Resource Key]
 - Identity: req.user.id                                 - Key: req.params.id
 - Roles: req.user.roles                                 - Type: Basket Primary Key
 - Tenant: req.user.tenantId                             - Scope: User Data
       │                                                         │
       └────────────────────────────┬────────────────────────────┘
                                    │
                                    ▼
                      [ORM / Data Access Operation]
                      Basket.findByPk(req.params.id)
                                    │
                                    ▼
                      [Authorization Predicate Audit]
   Is there a relationship binding: OWNER, TENANT, ROLE, PERMISSION?
                  ├── YES (Predicate Bound) ──> Emits: AUTHZ_CONSTRAINT_PRESENT
                  └── NO  (Predicate Absent) ──> Emits: CANDIDATE_AUTHZ_GAP
```

#### Principal & Relationship Model
1. **Principal Entities Extracted:** User ID, Tenant ID, Role array, Permission/scope set, Service identity, API key claims.
2. **Target Resource Key Extracted:** Object IDs from path parameters, query tokens, or payload bodies.
3. **Explicit Relationship Types:** `OWNER`, `TENANT`, `ROLE`, `PERMISSION`, `MEMBERSHIP`, `RESOURCE_SCOPE`.
4. **Predicate Auditing:**
   - **Scoped Query:** Query includes owner/tenant binding (`Basket.findOne({ where: { id, userId } })`). Emits `AUTHZ_CONSTRAINT_PRESENT`. *(Note: Final `SAFE_PROVEN` verdict is only established after verifying full contract across middleware and service layers).*
   - **Unscoped Query:** Query fetches strictly by primary key without owner binding (`Basket.findByPk(id)`). If enclosing service and middleware lack explicit ownership assertions, emits `CANDIDATE_AUTHZ_GAP`.

---

## 7. Persistent CPG, Edge Provenance & Reachability

### 7.1 SQLite Relational Schema (`.audit/audit.db`)

```sql
PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;

-- ============================================================================
-- 1. PERSISTENT REPOSITORY GRAPH LAYER
-- ============================================================================

CREATE TABLE IF NOT EXISTS files (
    file_id INTEGER PRIMARY KEY AUTOINCREMENT,
    rel_path TEXT NOT NULL UNIQUE,
    language TEXT NOT NULL,
    is_vendor BOOLEAN DEFAULT 0,
    file_hash TEXT NOT NULL,
    loc INTEGER NOT NULL,
    execution_domain TEXT NOT NULL,
    runtime_role TEXT NOT NULL,
    environment TEXT NOT NULL,
    artifact_type TEXT NOT NULL,
    classification_confidence REAL NOT NULL,
    classification_evidence TEXT,
    last_indexed_commit TEXT,
    last_indexed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_files_path ON files(rel_path);
CREATE INDEX IF NOT EXISTS idx_files_domain ON files(execution_domain, runtime_role);

CREATE TABLE IF NOT EXISTS symbols (
    symbol_id INTEGER PRIMARY KEY AUTOINCREMENT,
    file_id INTEGER NOT NULL REFERENCES files(file_id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    kind TEXT CHECK(kind IN ('FUNCTION', 'METHOD', 'CLASS', 'INTERFACE', 'VARIABLE')) NOT NULL,
    start_line INTEGER NOT NULL,
    start_col INTEGER NOT NULL,
    end_line INTEGER NOT NULL,
    end_col INTEGER NOT NULL,
    signature TEXT,
    scope TEXT,
    UNIQUE(file_id, name, kind, start_line, start_col)
);
CREATE INDEX IF NOT EXISTS idx_symbols_file ON symbols(file_id, name);
CREATE INDEX IF NOT EXISTS idx_symbols_name ON symbols(name);

CREATE TABLE IF NOT EXISTS endpoints (
    endpoint_id INTEGER PRIMARY KEY AUTOINCREMENT,
    file_id INTEGER NOT NULL REFERENCES files(file_id) ON DELETE CASCADE,
    http_method TEXT NOT NULL,
    route_pattern TEXT NOT NULL,
    handler_symbol_id INTEGER REFERENCES symbols(symbol_id) ON DELETE SET NULL,
    line_number INTEGER NOT NULL,
    auth_state TEXT CHECK(auth_state IN ('REQUIRED', 'NOT_REQUIRED', 'UNKNOWN')) NOT NULL,
    parameters_json TEXT, -- JSON array of {name, in, type, required}
    tool_provenance TEXT NOT NULL,
    UNIQUE(file_id, http_method, route_pattern, line_number)
);

CREATE TABLE IF NOT EXISTS candidate_sinks (
    sink_id INTEGER PRIMARY KEY AUTOINCREMENT,
    file_id INTEGER NOT NULL REFERENCES files(file_id) ON DELETE CASCADE,
    symbol_id INTEGER REFERENCES symbols(symbol_id) ON DELETE SET NULL,
    vuln_class TEXT NOT NULL,
    triage_severity TEXT CHECK(triage_severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO')) NOT NULL,
    line_number INTEGER NOT NULL,
    cwe_id TEXT,
    sink_expression TEXT NOT NULL,
    raw_rule_id TEXT NOT NULL,
    tool_provenance TEXT NOT NULL,
    UNIQUE(file_id, line_number, raw_rule_id)
);

-- Logical graph edges
CREATE TABLE IF NOT EXISTS graph_edges (
    edge_id INTEGER PRIMARY KEY AUTOINCREMENT,
    caller_symbol_id INTEGER NOT NULL REFERENCES symbols(symbol_id) ON DELETE CASCADE,
    callee_symbol_id INTEGER NOT NULL REFERENCES symbols(symbol_id) ON DELETE CASCADE,
    edge_type TEXT NOT NULL, -- 'CALL', 'IMPORT', 'INHERITS', 'DYNAMIC_DISPATCH', 'EVENT_EMIT', 'HANDLED_BY', 'GUARDED_BY'
    UNIQUE(caller_symbol_id, callee_symbol_id, edge_type)
);

-- Edge evidence records (Allows multiple independent corroborations per logical edge)
CREATE TABLE IF NOT EXISTS graph_edge_evidence (
    evidence_id INTEGER PRIMARY KEY AUTOINCREMENT,
    edge_id INTEGER NOT NULL REFERENCES graph_edges(edge_id) ON DELETE CASCADE,
    resolution_method TEXT NOT NULL, -- 'FRAMEWORK_RESOLVER', 'DETERMINISTIC_AST', 'SCIP_LSIF', 'HEURISTIC_CALL', 'LINKER_AGENT'
    confidence REAL CHECK(confidence >= 0.0 AND confidence <= 1.0) NOT NULL,
    evidence_json TEXT,
    indexed_commit TEXT,              -- Tracks commit SHA when evidence was harvested
    is_active BOOLEAN DEFAULT 1,       -- Invalidation flag when file/symbol changes
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_edge_evidence_edge ON graph_edge_evidence(edge_id);
CREATE INDEX IF NOT EXISTS idx_edge_evidence_active ON graph_edge_evidence(is_active);

-- ============================================================================
-- 2. SCAN SESSIONS & VERIFIED FINDINGS LAYER
-- ============================================================================

CREATE TABLE IF NOT EXISTS scans (
    scan_id TEXT PRIMARY KEY,
    target_path TEXT NOT NULL,
    scan_mode TEXT CHECK(scan_mode IN ('FULL', 'DIFF')) NOT NULL,
    base_commit TEXT,
    target_commit TEXT,
    engine_fingerprint TEXT NOT NULL,
    status TEXT CHECK(status IN ('INITIALIZING', 'INDEXING', 'TRIAGING', 'VERIFYING', 'COMPLETED', 'FAILED', 'ABORTED')) NOT NULL,
    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP,
    config_json TEXT NOT NULL,
    stats_json TEXT
);

CREATE TABLE IF NOT EXISTS scan_candidate_paths (
    path_id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
    endpoint_id INTEGER REFERENCES endpoints(endpoint_id) ON DELETE CASCADE,
    sink_id INTEGER NOT NULL REFERENCES candidate_sinks(sink_id) ON DELETE CASCADE,
    hop_count INTEGER NOT NULL,
    call_sequence_json TEXT NOT NULL,
    priority_score REAL NOT NULL,
    reachability_confidence REAL NOT NULL,
    state TEXT CHECK(state IN (
        'QUEUED', 'RUNNING', 'RESOLVED', 'UNRESOLVED',
        'PATH_PRUNED_DEPTH_LIMIT', 'PATH_PRUNED_BUDGET',
        'PATH_FAILED_TIMEOUT', 'PATH_FAILED_API', 'PATH_FAILED_AGENT',
        'REUSED_FROM_CACHE'
    )) NOT NULL DEFAULT 'QUEUED',
    retry_count INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS scan_dossiers (
    dossier_id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
    fingerprint_schema_version INTEGER NOT NULL DEFAULT 1,
    finding_fingerprint TEXT NOT NULL, -- Stable across scans: SHA256(version + vuln_class + norm_endpoint + norm_source + norm_sink + norm_path)
    path_id TEXT REFERENCES scan_candidate_paths(path_id) ON DELETE SET NULL,
    engine_fingerprint TEXT NOT NULL,
    title TEXT NOT NULL,
    vuln_class TEXT NOT NULL,
    severity TEXT CHECK(severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO')) NOT NULL, -- Verified/normalized severity
    cwe_id TEXT,                      -- Nullable: does not force artificial CWE mappings
    verdict TEXT CHECK(verdict IN (
        'EXPLOITABLE', 
        'LIKELY_EXPLOITABLE_PARTIAL_SANITIZATION', 
        'SAFE_PROVEN', 
        'INSUFFICIENT_CONTEXT'
    )) NOT NULL,
    reachability_confidence REAL NOT NULL,
    exploitability_confidence REAL NOT NULL,
    source_trace_json TEXT NOT NULL,
    evidence_bundle_json TEXT NOT NULL, -- Curated structured evidence bundle (no private CoT)
    repro_template_json TEXT,           -- Structured reproduction blueprint
    mitigation_notes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_dossiers_finding_fp ON scan_dossiers(finding_fingerprint);
CREATE INDEX IF NOT EXISTS idx_dossiers_verdict ON scan_dossiers(scan_id, verdict, severity);
CREATE INDEX IF NOT EXISTS idx_dossiers_fingerprint ON scan_dossiers(engine_fingerprint, path_id);
```

---

### 7.2 Resolution Confidence & Path Aggregation

Edge resolution confidence is a calibrated score reflecting:
$$\text{Confidence}_{\text{Edge}} = \text{BaseScore}(\text{Method}) + \text{CorroborationBonus} - \text{AmbiguityPenalty}$$

#### Bounded Path Confidence Aggregation:
Rather than penalizing long deterministic paths with multiplicative decay, path confidence is aggregated via bounded weakest-link bottleneck with corroboration adjustment:
$$\text{Confidence}_{\text{Path}} = \min_{e \in \text{Edges}} (\text{Confidence}_e) \times \text{CompletenessFactor}$$
*Invariant:* A path containing an ambiguous edge (e.g. 0.60) cannot exceed 0.60, ensuring weak links are never obscured by surrounding deterministic hops.

### 7.3 State-Aware Traversal & Cycle Detection
Traversal through the in-memory graph cache uses a composite state key:
$$\text{TraversalKey} = (\text{node\_id}, \text{edge\_type}, \text{analysis\_state})$$
where `analysis_state` tracks `(taint_state, auth_context, role_scope)`. This allows legitimate revisiting of utility functions under different taint or principal states while terminating true infinite loops. Hard depth cutoff: **20 hops**.

### 7.4 CPG Invalidation & Incremental Mutation Semantics
When source files change across incremental scans (`diff` mode), the persistent CPG is mutated rather than rebuilt from zero:
1. **Modified File (Content/Hash Delta):**
   - The file's existing `symbols`, `endpoints`, and `candidate_sinks` are marked for replacement or purged (`ON DELETE CASCADE`).
   - Connected `graph_edge_evidence` records where `caller_symbol_id` or `callee_symbol_id` lived in this file are marked `is_active = 0`.
   - Dependent `scan_candidate_paths` in active scans traversing invalidated edges are set to state `UNRESOLVED`.
   - The file is re-indexed by Tree-sitter and Framework Resolvers, creating new symbols and fresh active edge evidence.
   - Dependent reachability paths are recomputed incrementally.
2. **Deleted File:**
   - Deleting the `files` record activates SQLite `ON DELETE CASCADE`, immediately removing its symbols, endpoints, candidate sinks, and connected graph edges.
   - Any historical `scan_dossiers` referencing affected candidate paths are marked as non-reusable.
3. **Normalized Finding Fingerprint Formulation:**
   To guarantee stable vulnerability lifecycle tracking across incremental runs without duplicate alerts:
   $$\text{finding\_fingerprint} = \text{SHA256}(\text{schema\_version} + \text{vuln\_class} + \text{norm\_endpoint} + \text{norm\_source} + \text{norm\_sink} + \text{norm\_path})$$
   - `schema_version`: Global integer (currently `1`).
   - `norm_endpoint`: Standardized HTTP method + normalized path (e.g. `POST /rest/user/login`).
   - `norm_source`: Qualified parameter token (e.g. `BODY.email`).
   - `norm_sink`: Canonical sink identifier (e.g. `SQL.models.sequelize.query`).
   - `norm_path`: Canonical POSIX sequence of qualified symbol identifiers.

---

## 8. Evidence-Gated Agentic Verification Pipeline

```text
                        Queued Candidate Path
                                  │
                  ┌───────────────┴───────────────┐
                  ▼                               ▼
       [Broken / Dynamic Edge?]        [Unbroken Candidate Path]
                  │                               │
                  ▼                               ▼
          [Linker Agent]               [Contract-Flow Agent]
       (Max 2 turns per edge)      (Evaluate Transform Contracts)
                  │                               │
                  ▼                               │
       Inferred Edge Persisted                    │
         to Persistent CPG                        │
                  │                               │
                  └───────────────┬───────────────┘
                                  │
                                  ▼
                   Is Candidate Critical or Contested?
                  ├── YES ──> [Adversarial Debate Engine]
                  │           (Prosecutor vs. Defender → Judge)
                  │           (Ephemeral CoT; Curated Evidence Only)
                  └── NO  ──> Direct Contract Evaluation
                                  │
                                  ▼
                   [Evidence Sufficiency Gate]
                     Meets all required proofs?
                  ├── YES ──> EXPLOITABLE / LIKELY_EXPLOITABLE_PARTIAL_SANITIZATION
                  └── NO  ──> SAFE_PROVEN / INSUFFICIENT_CONTEXT
```

### 8.1 Canonical Verdict Definitions
BackTrace enforces strict semantic boundaries on its four canonical verdicts:

- **`EXPLOITABLE`:**  
  Attacker control over source input is established, continuous reachability to the sink is proven, the sink's precondition requirements are verified, and intermediate transforms fail to neutralize the payload (a concrete bypass rationale is recorded). Meets all criteria of the Evidence Sufficiency Gate.
- **`LIKELY_EXPLOITABLE_PARTIAL_SANITIZATION`:**  
  Reachability and attacker control are established, but a sanitizer, validator, or transform provides incomplete, flawed, or context-dependent protection (e.g. unanchored regex, unquoted parameter, partial blacklist). The available evidence indicates substantial risk but does not justify the stronger deterministic `EXPLOITABLE` verdict.
- **`SAFE_PROVEN`:**  
  The analyzed security contract has been demonstrated to hold for the identified source, propagation path, sink, and relevant authorization/context assumptions within the analyzed code/configuration (e.g. strict type coercion, parameterized ORM predicate, verified contextual escaping).  
  *Operational Boundary:* `SAFE_PROVEN` certifies only that the analyzed flow satisfies its security contract; it **does not** imply the repository is globally vulnerability-free.
- **`INSUFFICIENT_CONTEXT`:**  
  The available code slice, dynamic dispatches, unresolvable vendor signatures, or sanitization logic leaves the flow ambiguous or untestable without external assumptions. Prevents hallucinating vulnerabilities when evidence is missing.

### 8.2 Evidence Sufficiency Gate
A finding receives `EXPLOITABLE` **only** when all required proofs are established:
1. **Source Control Established:** Attacker role can supply arbitrary or dangerous tokens.
2. **Reachability Established:** Continuous path exists from entrypoint to sink without broken hops.
3. **Sink Semantics Established:** Exact sink requirements and character boundaries confirmed.
4. **Security Contract Violated:** Transforms fail to neutralize the payload; explicit bypass reasoning provided.
5. **No Material Ambiguity:** If unresolved callsites or missing source lines leave the flow ambiguous, the gate assigns `INSUFFICIENT_CONTEXT`.

---

## 9. Endpoint-Aware Reproduction Templates

Reproduction templates are generated as structured, assertion-oriented blueprints.

```json
{
  "reproduction_type": "HTTP_TEMPLATE",
  "method": "POST",
  "route": "/rest/user/login",
  "auth_context": {
    "auth_state": "REQUIRED",
    "header_placeholder": "Authorization: Bearer ${AUTH_TOKEN}"
  },
  "parameters": [
    {
      "location": "BODY",
      "name": "email",
      "type": "string",
      "is_tainted_target": true,
      "marker_value": "BT_FLOW_MARKER_001"
    },
    {
      "location": "BODY",
      "name": "password",
      "type": "string",
      "is_tainted_target": false,
      "marker_value": "validDummyPassword123!"
    }
  ],
  "expected_assertion": {
    "assertion_type": "PARAMETER_REACHABILITY",
    "description": "Marker 'BT_FLOW_MARKER_001' propagates unescaped into server-side SQL query string."
  },
  "curl_command": "curl -X POST \"${TARGET_URL:-http://localhost:3000}/rest/user/login\" -H \"Content-Type: application/json\" -d '{\"email\": \"BT_FLOW_MARKER_001\", \"password\": \"validDummyPassword123!\"}'"
}
```

### Supported Reproduction Types:
- `HTTP_TEMPLATE`: Parameterized `curl` template with non-weaponized test markers.
- `NON_HTTP_TEMPLATE`: CLI invocation or message payload template (for background workers / CLI entrypoints).
- `PARTIAL_TEMPLATE`: Route and parameters known, but required sibling payloads require manual configuration.
- `NONE`: Internal unexposed sink or complex state-machine requirement.

---

## 10. Multi-Format Exporters & CLI

### 10.1 Export Formats
1. **OASIS SARIF v2.1.0:** Step-by-step `codeFlows` and `threadFlows` from entrypoint through transforms to sink, with CWE tags and remediation notes.
2. **Interactive Graph JSON:** Configurable export scope (`--graph-scope repository | finding | path | endpoint`).
3. **Research Markdown Report:** Summary tables, threat surface statistics, call diagrams, and reproduction blueprints.

### 10.2 Strengthened Engine Fingerprint
Cache validity requires exact match across the entire toolchain:
$$\text{Engine Fingerprint} = \text{SHA256}(\text{EngineVer} + \text{SchemaVer} + \text{ToolVers} + \text{RulesetHashes} + \text{ModelID} + \text{ConfigJSON} + \text{ResolverVers} + \text{LockfileHash})$$

---

## 11. Edge-Case Matrix & Operational Bounds

| Edge Case | Failure Mode Without Defense | BackTrace Defensive Guarantee |
|---|---|---|
| **Masked Tool Snippets** | Semgrep outputs `"requires login"` | Filesystem Fallback Hydration: Reads actual source lines from target path and line coordinates |
| **Recursive Call Loops** | Infinite traversal in DFS | State-aware traversal key `(node, edge_type, state)` terminates cycles immediately |
| **Deep Call Stacks** | Stack overflow / timeout | Max 20 hops depth cutoff; marks path `PATH_PRUNED_DEPTH_LIMIT` |
| **Ambiguous Dynamic Dispatch** | Disconnected reachability path | Linker Agent attempts resolution (max 2 turns); records confidence & evidence |
| **Private LLM Monologue** | Secret CoT persisted to database | Ephemeral prompt isolation; parser persists only curated evidence fields |
| **CI / Test Code False Alarms** | CI scripts flagged as Web RCE | Multidimensional scope routes workflows to `SUPPLY_CHAIN_CI` dossiers |
| **BOLA / IDOR Scenarios** | Taint engine ignores safe ORM calls | Track B audits principal-to-object ownership predicates |
