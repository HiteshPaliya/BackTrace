PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;

-- ============================================================================
-- 1. PERSISTENT REPOSITORY GRAPH LAYER (Survives across scans)
-- ============================================================================

-- Repository files indexed
CREATE TABLE IF NOT EXISTS files (
    file_id INTEGER PRIMARY KEY AUTOINCREMENT,
    rel_path TEXT NOT NULL UNIQUE,
    language TEXT NOT NULL,
    is_vendor BOOLEAN DEFAULT 0,
    file_hash TEXT NOT NULL,
    loc INTEGER NOT NULL,
    execution_domain TEXT DEFAULT 'APPLICATION_RUNTIME',
    runtime_role TEXT DEFAULT 'UNKNOWN',
    environment TEXT DEFAULT 'PRODUCTION',
    artifact_type TEXT DEFAULT 'UNKNOWN',
    classification_confidence REAL DEFAULT 0.8,
    classification_evidence TEXT,
    last_indexed_commit TEXT,
    last_indexed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_files_path ON files(rel_path);
CREATE INDEX IF NOT EXISTS idx_files_hash ON files(file_hash);
CREATE INDEX IF NOT EXISTS idx_files_domain ON files(execution_domain, runtime_role);

-- Symbols (functions, methods, classes, interfaces)
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

-- Discovered Endpoints (Framework Resolvers + OWASP Noir)
CREATE TABLE IF NOT EXISTS endpoints (
    endpoint_id INTEGER PRIMARY KEY AUTOINCREMENT,
    file_id INTEGER NOT NULL REFERENCES files(file_id) ON DELETE CASCADE,
    http_method TEXT NOT NULL,
    route_pattern TEXT NOT NULL,
    handler_symbol_id INTEGER REFERENCES symbols(symbol_id) ON DELETE SET NULL,
    line_number INTEGER NOT NULL,
    auth_state TEXT CHECK(auth_state IN ('REQUIRED', 'NOT_REQUIRED', 'UNKNOWN')) NOT NULL DEFAULT 'UNKNOWN',
    auth_required BOOLEAN DEFAULT 0,
    parameters_json TEXT, -- JSON array of {name, in, type, required}
    tool_provenance TEXT NOT NULL,
    UNIQUE(file_id, http_method, route_pattern, line_number)
);
CREATE INDEX IF NOT EXISTS idx_endpoints_route ON endpoints(http_method, route_pattern);

-- Discovered Candidate Sinks (Built-in Semantic AST + Semgrep)
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
CREATE INDEX IF NOT EXISTS idx_sinks_class ON candidate_sinks(vuln_class);

-- Cross-File Logical Graph Edges
CREATE TABLE IF NOT EXISTS graph_edges (
    edge_id INTEGER PRIMARY KEY AUTOINCREMENT,
    caller_symbol_id INTEGER NOT NULL REFERENCES symbols(symbol_id) ON DELETE CASCADE,
    callee_symbol_id INTEGER NOT NULL REFERENCES symbols(symbol_id) ON DELETE CASCADE,
    edge_type TEXT NOT NULL, -- 'CALL', 'IMPORT', 'INHERITS', 'DYNAMIC_DISPATCH', 'EVENT_EMIT', 'HANDLED_BY', 'GUARDED_BY', 'CONTAINS_SINK'
    UNIQUE(caller_symbol_id, callee_symbol_id, edge_type)
);
CREATE INDEX IF NOT EXISTS idx_edges_traversal ON graph_edges(caller_symbol_id, callee_symbol_id);

-- Edge Evidence Records (Allows multiple independent corroborations per logical edge)
CREATE TABLE IF NOT EXISTS graph_edge_evidence (
    evidence_id INTEGER PRIMARY KEY AUTOINCREMENT,
    edge_id INTEGER NOT NULL REFERENCES graph_edges(edge_id) ON DELETE CASCADE,
    resolution_method TEXT NOT NULL, -- 'FRAMEWORK_RESOLVER', 'DETERMINISTIC_AST', 'SCIP_LSIF', 'HEURISTIC_CALL', 'LINKER_AGENT'
    confidence REAL CHECK(confidence >= 0.0 AND confidence <= 1.0) NOT NULL,
    evidence_json TEXT,
    indexed_commit TEXT,
    is_active BOOLEAN DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_edge_evidence_edge ON graph_edge_evidence(edge_id);
CREATE INDEX IF NOT EXISTS idx_edge_evidence_active ON graph_edge_evidence(is_active);

-- Vendor Signatures (Shallow 3rd-party library sink mappings)
CREATE TABLE IF NOT EXISTS vendor_signatures (
    sig_id INTEGER PRIMARY KEY AUTOINCREMENT,
    package_name TEXT NOT NULL,
    api_name TEXT NOT NULL,
    potential_sink_class TEXT NOT NULL,
    signature_pattern TEXT,
    UNIQUE(package_name, api_name)
);

-- ============================================================================
-- 2. SCAN SESSIONS & FINDINGS LAYER (Scoped to individual scan executions)
-- ============================================================================

-- Metadata tracking individual scan executions (FULL or DIFF)
CREATE TABLE IF NOT EXISTS scans (
    scan_id TEXT PRIMARY KEY,
    target_path TEXT NOT NULL,
    scan_mode TEXT CHECK(scan_mode IN ('FULL', 'DIFF')) NOT NULL,
    base_commit TEXT,
    target_commit TEXT,
    engine_fingerprint TEXT NOT NULL, -- SHA256(tools + rules + model + config)
    status TEXT CHECK(status IN ('INITIALIZING', 'INDEXING', 'TRIAGING', 'VERIFYING', 'COMPLETED', 'FAILED', 'ABORTED')) NOT NULL,
    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP,
    config_json TEXT NOT NULL,
    stats_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);

-- Candidate Reachability Paths evaluated in a specific scan
CREATE TABLE IF NOT EXISTS scan_candidate_paths (
    path_id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
    endpoint_id INTEGER REFERENCES endpoints(endpoint_id) ON DELETE CASCADE,
    sink_id INTEGER NOT NULL REFERENCES candidate_sinks(sink_id) ON DELETE CASCADE,
    hop_count INTEGER NOT NULL,
    call_sequence_json TEXT NOT NULL, -- Array of symbol_ids and edge_ids
    priority_score REAL NOT NULL,
    reachability_confidence REAL DEFAULT 1.0,
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
CREATE INDEX IF NOT EXISTS idx_paths_triage ON scan_candidate_paths(scan_id, state, priority_score DESC);

-- Verified Vulnerability Dossiers produced in a scan
CREATE TABLE IF NOT EXISTS scan_dossiers (
    dossier_id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
    fingerprint_schema_version INTEGER NOT NULL DEFAULT 1,
    finding_fingerprint TEXT,
    path_id TEXT REFERENCES scan_candidate_paths(path_id) ON DELETE SET NULL,
    engine_fingerprint TEXT NOT NULL,
    title TEXT NOT NULL,
    vuln_class TEXT NOT NULL,
    severity TEXT CHECK(severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO')) NOT NULL,
    cwe_id TEXT,
    verdict TEXT CHECK(verdict IN (
        'EXPLOITABLE', 
        'LIKELY_EXPLOITABLE_PARTIAL_SANITIZATION', 
        'SAFE_PROVEN', 
        'INSUFFICIENT_CONTEXT'
    )) NOT NULL,
    reachability_confidence REAL DEFAULT 1.0,
    exploitability_confidence REAL DEFAULT 0.85,
    confidence REAL DEFAULT 0.85,
    source_trace_json TEXT NOT NULL,
    sanitizer_analysis_json TEXT,
    evidence_bundle_json TEXT,
    repro_curl_template TEXT,
    repro_template_json TEXT,
    mitigation_notes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_dossiers_finding_fp ON scan_dossiers(finding_fingerprint);
CREATE INDEX IF NOT EXISTS idx_dossiers_verdict ON scan_dossiers(scan_id, verdict, severity);
CREATE INDEX IF NOT EXISTS idx_dossiers_fingerprint ON scan_dossiers(engine_fingerprint, path_id);
