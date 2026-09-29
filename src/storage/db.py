"""SQLite DatabaseManager implementing decoupled repository graph and scan state store."""

import hashlib
import json
import sqlite3
import uuid
from contextlib import contextmanager
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Generator, List, Optional


class VerdictStatus(str, Enum):
    """Canonical taint analysis verdict outcomes."""

    EXPLOITABLE = "EXPLOITABLE"
    LIKELY_EXPLOITABLE_PARTIAL_SANITIZATION = "LIKELY_EXPLOITABLE_PARTIAL_SANITIZATION"
    SAFE_PROVEN = "SAFE_PROVEN"
    INSUFFICIENT_CONTEXT = "INSUFFICIENT_CONTEXT"


class DatabaseManager:
    """Manages SQLite connection pooling, transactions, repository graph, and scan state."""

    def __init__(self, db_path: Path | str) -> None:
        self.db_path = Path(db_path).resolve()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=5.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.execute("PRAGMA busy_timeout = 5000;")
        return conn

    @contextmanager
    def transaction(self) -> Generator[sqlite3.Connection, None, None]:
        """Scoped atomic transaction context manager."""
        conn = self._get_connection()
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def init_schema(self) -> None:
        """Initialize or migrate database tables and indexes from schema.sql."""
        schema_path = Path(__file__).parent / "schema.sql"
        schema_sql = schema_path.read_text(encoding="utf-8")
        with self._get_connection() as conn:
            # Check if files table exists and needs column migrations
            cursor = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='files';"
            )
            if cursor.fetchone():
                cols = [row[1] for row in conn.execute("PRAGMA table_info(files);").fetchall()]
                if "execution_domain" not in cols:
                    conn.execute(
                        "ALTER TABLE files ADD COLUMN execution_domain TEXT "
                        "DEFAULT 'APPLICATION_RUNTIME';"
                    )
                if "runtime_role" not in cols:
                    conn.execute(
                        "ALTER TABLE files ADD COLUMN runtime_role TEXT DEFAULT 'UNKNOWN';"
                    )
                if "environment" not in cols:
                    conn.execute(
                        "ALTER TABLE files ADD COLUMN environment TEXT DEFAULT 'PRODUCTION';"
                    )
                if "artifact_type" not in cols:
                    conn.execute(
                        "ALTER TABLE files ADD COLUMN artifact_type TEXT DEFAULT 'UNKNOWN';"
                    )
                if "classification_confidence" not in cols:
                    conn.execute(
                        "ALTER TABLE files ADD COLUMN classification_confidence REAL "
                        "DEFAULT 0.8;"
                    )
                if "classification_evidence" not in cols:
                    conn.execute(
                        "ALTER TABLE files ADD COLUMN classification_evidence TEXT;"
                    )

            # Check candidate_sinks for triage_severity
            cursor = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='candidate_sinks';"
            )
            if cursor.fetchone():
                cols = [
                    row[1]
                    for row in conn.execute("PRAGMA table_info(candidate_sinks);").fetchall()
                ]
                if "triage_severity" not in cols:
                    conn.execute(
                        "ALTER TABLE candidate_sinks ADD COLUMN triage_severity TEXT "
                        "DEFAULT 'MEDIUM';"
                    )

            # Check scan_candidate_paths for reachability_confidence
            cursor = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND "
                "name='scan_candidate_paths';"
            )
            if cursor.fetchone():
                cols = [
                    row[1]
                    for row in conn.execute(
                        "PRAGMA table_info(scan_candidate_paths);"
                    ).fetchall()
                ]
                if "reachability_confidence" not in cols:
                    conn.execute(
                        "ALTER TABLE scan_candidate_paths ADD COLUMN "
                        "reachability_confidence REAL DEFAULT 1.0;"
                    )

            # Check scan_dossiers for new columns
            cursor = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='scan_dossiers';"
            )
            if cursor.fetchone():
                cols = [
                    row[1]
                    for row in conn.execute("PRAGMA table_info(scan_dossiers);").fetchall()
                ]
                if "fingerprint_schema_version" not in cols:
                    conn.execute(
                        "ALTER TABLE scan_dossiers ADD COLUMN fingerprint_schema_version "
                        "INTEGER DEFAULT 1;"
                    )
                if "finding_fingerprint" not in cols:
                    conn.execute(
                        "ALTER TABLE scan_dossiers ADD COLUMN finding_fingerprint TEXT;"
                    )
                if "reachability_confidence" not in cols:
                    conn.execute(
                        "ALTER TABLE scan_dossiers ADD COLUMN reachability_confidence REAL "
                        "DEFAULT 1.0;"
                    )
                if "exploitability_confidence" not in cols:
                    conn.execute(
                        "ALTER TABLE scan_dossiers ADD COLUMN exploitability_confidence REAL "
                        "DEFAULT 0.85;"
                    )
                if "evidence_bundle_json" not in cols:
                    conn.execute(
                        "ALTER TABLE scan_dossiers ADD COLUMN evidence_bundle_json TEXT;"
                    )
                if "repro_template_json" not in cols:
                    conn.execute(
                        "ALTER TABLE scan_dossiers ADD COLUMN repro_template_json TEXT;"
                    )

            conn.executescript(schema_sql)

    # =========================================================================
    # Persistent Repository Graph CRUD (Decoupled from scans)
    # =========================================================================

    def upsert_file(
        self,
        rel_path: str,
        language: str,
        is_vendor: bool,
        file_hash: str,
        loc: int,
        last_indexed_commit: Optional[str] = None,
        execution_domain: str = "APPLICATION_RUNTIME",
        runtime_role: str = "UNKNOWN",
        environment: str = "PRODUCTION",
        artifact_type: str = "UNKNOWN",
        classification_confidence: float = 0.8,
        classification_evidence: Optional[str] = None,
    ) -> int:
        """Insert or update a repository file record with scope metadata."""
        with self.transaction() as conn:
            cursor = conn.execute(
                """
                INSERT INTO files (
                    rel_path, language, is_vendor, file_hash, loc, last_indexed_commit,
                    execution_domain, runtime_role, environment, artifact_type,
                    classification_confidence, classification_evidence
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(rel_path) DO UPDATE SET
                    language = excluded.language,
                    is_vendor = excluded.is_vendor,
                    file_hash = excluded.file_hash,
                    loc = excluded.loc,
                    last_indexed_commit = excluded.last_indexed_commit,
                    execution_domain = excluded.execution_domain,
                    runtime_role = excluded.runtime_role,
                    environment = excluded.environment,
                    artifact_type = excluded.artifact_type,
                    classification_confidence = excluded.classification_confidence,
                    classification_evidence = excluded.classification_evidence,
                    last_indexed_at = CURRENT_TIMESTAMP
                RETURNING file_id;
                """,
                (
                    rel_path,
                    language,
                    int(is_vendor),
                    file_hash,
                    loc,
                    last_indexed_commit,
                    execution_domain,
                    runtime_role,
                    environment,
                    artifact_type,
                    classification_confidence,
                    classification_evidence,
                ),
            )
            row = cursor.fetchone()
            return int(row["file_id"])

    def get_all_files(self) -> List[Dict[str, Any]]:
        """Retrieve all indexed repository files."""
        with self._get_connection() as conn:
            rows = conn.execute("SELECT * FROM files ORDER BY file_id ASC;").fetchall()
            return [dict(r) for r in rows]

    def insert_symbol(
        self,
        file_id: int,
        name: str,
        kind: str,
        start_line: int,
        start_col: int,
        end_line: int,
        end_col: int,
        signature: Optional[str] = None,
        scope: Optional[str] = None,
    ) -> int:
        """Insert a symbol record for a file."""
        with self.transaction() as conn:
            cursor = conn.execute(
                """
                INSERT INTO symbols (
                    file_id, name, kind, start_line, start_col, end_line, end_col, signature, scope
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(file_id, name, kind, start_line, start_col) DO UPDATE SET
                    end_line = excluded.end_line,
                    end_col = excluded.end_col,
                    signature = excluded.signature,
                    scope = excluded.scope
                RETURNING symbol_id;
                """,
                (
                    file_id,
                    name,
                    kind,
                    start_line,
                    start_col,
                    end_line,
                    end_col,
                    signature,
                    scope,
                ),
            )
            row = cursor.fetchone()
            return int(row["symbol_id"])

    def insert_endpoint(
        self,
        file_id: int,
        http_method: str,
        route_pattern: str,
        line_number: int,
        tool_provenance: str,
        handler_symbol_id: Optional[int] = None,
        auth_required: bool = False,
        parameters: Optional[List[Dict[str, Any]]] = None,
    ) -> int:
        """Insert a discovered HTTP endpoint."""
        params_json = json.dumps(parameters or [])
        with self.transaction() as conn:
            cursor = conn.execute(
                """
                INSERT INTO endpoints (
                    file_id, http_method, route_pattern, handler_symbol_id,
                    line_number, auth_required, parameters_json, tool_provenance
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(file_id, http_method, route_pattern, line_number) DO UPDATE SET
                    handler_symbol_id = excluded.handler_symbol_id,
                    auth_required = excluded.auth_required,
                    parameters_json = excluded.parameters_json,
                    tool_provenance = excluded.tool_provenance
                RETURNING endpoint_id;
                """,
                (
                    file_id,
                    http_method.upper(),
                    route_pattern,
                    handler_symbol_id,
                    line_number,
                    int(auth_required),
                    params_json,
                    tool_provenance,
                ),
            )
            row = cursor.fetchone()
            return int(row["endpoint_id"])

    def insert_candidate_sink(
        self,
        file_id: int,
        vuln_class: str,
        triage_severity: Optional[str] = None,
        line_number: int = 1,
        sink_expression: str = "",
        raw_rule_id: str = "",
        tool_provenance: str = "",
        severity: Optional[str] = None,
        symbol_id: Optional[int] = None,
        cwe_id: Optional[str] = None,
    ) -> int:
        """Insert a discovered candidate vulnerability sink with triage severity."""
        eff_severity = (triage_severity or severity or "MEDIUM").upper()
        with self.transaction() as conn:
            cursor = conn.execute(
                """
                INSERT INTO candidate_sinks (
                    file_id, symbol_id, vuln_class, triage_severity, line_number,
                    cwe_id, sink_expression, raw_rule_id, tool_provenance
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(file_id, line_number, raw_rule_id) DO UPDATE SET
                    vuln_class = excluded.vuln_class,
                    triage_severity = excluded.triage_severity,
                    sink_expression = excluded.sink_expression,
                    tool_provenance = excluded.tool_provenance
                RETURNING sink_id;
                """,
                (
                    file_id,
                    symbol_id,
                    vuln_class,
                    eff_severity,
                    line_number,
                    cwe_id,
                    sink_expression,
                    raw_rule_id,
                    tool_provenance,
                ),
            )
            row = cursor.fetchone()
            return int(row["sink_id"])

    def insert_graph_edge(
        self,
        caller_symbol_id: int,
        callee_symbol_id: int,
        edge_type: str,
        provenance: Optional[str] = None,
        confidence: float = 1.0,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> int:
        """Insert or retrieve logical cross-symbol graph edge."""
        with self.transaction() as conn:
            cursor = conn.execute(
                """
                INSERT INTO graph_edges (
                    caller_symbol_id, callee_symbol_id, edge_type
                ) VALUES (?, ?, ?)
                ON CONFLICT(caller_symbol_id, callee_symbol_id, edge_type) DO UPDATE SET
                    edge_type = excluded.edge_type
                RETURNING edge_id;
                """,
                (
                    caller_symbol_id,
                    callee_symbol_id,
                    edge_type,
                ),
            )
            row = cursor.fetchone()
            edge_id = int(row["edge_id"])

            # Also record default evidence if provenance is provided
            if provenance:
                conn.execute(
                    """
                    INSERT INTO graph_edge_evidence (
                        edge_id, resolution_method, confidence, evidence_json, is_active
                    ) VALUES (?, ?, ?, ?, 1);
                    """,
                    (
                        edge_id,
                        provenance,
                        confidence,
                        json.dumps(metadata or {}),
                    ),
                )
            return edge_id

    def insert_edge_evidence(
        self,
        edge_id: int,
        resolution_method: str,
        confidence: float,
        evidence: Optional[Dict[str, Any]] = None,
        commit_sha: Optional[str] = None,
    ) -> int:
        """Insert an independent evidence record for a logical graph edge."""
        evidence_str = json.dumps(evidence or {})
        with self.transaction() as conn:
            cursor = conn.execute(
                """
                INSERT INTO graph_edge_evidence (
                    edge_id, resolution_method, confidence, evidence_json, indexed_commit, is_active
                ) VALUES (?, ?, ?, ?, ?, 1)
                RETURNING evidence_id;
                """,
                (edge_id, resolution_method, confidence, evidence_str, commit_sha),
            )
            row = cursor.fetchone()
            return int(row["evidence_id"])

    def get_active_edge_evidence(self, edge_id: int) -> List[Dict[str, Any]]:
        """Retrieve all active evidence records for an edge."""
        with self._get_connection() as conn:
            rows = conn.execute(
                "SELECT * FROM graph_edge_evidence WHERE edge_id = ? AND is_active = 1;",
                (edge_id,),
            ).fetchall()
            return [dict(r) for r in rows]

    def invalidate_file_symbols(self, file_id: int) -> None:
        """Invalidate edge evidence and dependent candidate paths for symbols in file."""
        with self.transaction() as conn:
            conn.execute(
                """
                UPDATE graph_edge_evidence
                SET is_active = 0
                WHERE edge_id IN (
                    SELECT edge_id FROM graph_edges
                    WHERE caller_symbol_id IN (SELECT symbol_id FROM symbols WHERE file_id = ?)
                       OR callee_symbol_id IN (SELECT symbol_id FROM symbols WHERE file_id = ?)
                );
                """,
                (file_id, file_id),
            )
            conn.execute(
                """
                UPDATE scan_candidate_paths
                SET state = 'UNRESOLVED'
                WHERE sink_id IN (SELECT sink_id FROM candidate_sinks WHERE file_id = ?);
                """,
                (file_id,),
            )

    def invalidate_deleted_file(self, rel_path: str) -> None:
        """Purge deleted file and cascade invalidation through symbols and edges."""
        with self.transaction() as conn:
            conn.execute("DELETE FROM files WHERE rel_path = ?;", (rel_path,))

    @staticmethod
    def compute_finding_fingerprint(
        schema_version: int,
        vuln_class: str,
        norm_endpoint: str,
        norm_source: str,
        norm_sink: str,
        norm_path: str,
    ) -> str:
        """Compute versioned, normalized SHA256 finding fingerprint (line-churn immune)."""
        clean_path = (
            norm_path.split(":")[0].strip()
            if ":" in norm_path and not norm_path.startswith("http")
            else norm_path.strip()
        )
        raw = (
            f"v{schema_version}|{vuln_class.strip().upper()}|{norm_endpoint.strip()}|"
            f"{norm_source.strip()}|{norm_sink.strip()}|{clean_path}"
        )
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def get_edges_for_caller(self, caller_symbol_id: int) -> List[Dict[str, Any]]:
        """Retrieve all outgoing graph edges for a given caller symbol with active evidence."""
        with self._get_connection() as conn:
            rows = conn.execute(
                """
                SELECT e.*,
                       COALESCE(ev.resolution_method, 'DETERMINISTIC') as provenance,
                       COALESCE(ev.confidence, 1.0) as confidence
                FROM graph_edges e
                LEFT JOIN graph_edge_evidence ev ON e.edge_id = ev.edge_id AND ev.is_active = 1
                WHERE e.caller_symbol_id = ?;
                """,
                (caller_symbol_id,),
            ).fetchall()
            return [dict(r) for r in rows]

    def get_symbol_by_name(self, name: str) -> Optional[Dict[str, Any]]:
        """Retrieve a symbol by exact name."""
        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT * FROM symbols WHERE name = ? LIMIT 1;",
                (name,),
            ).fetchone()
            return dict(row) if row else None

    def upsert_vendor_signature(
        self,
        package_name: str,
        api_name: str,
        potential_sink_class: str,
        signature_pattern: Optional[str] = None,
    ) -> int:
        """Upsert a vendor library signature."""
        with self.transaction() as conn:
            cursor = conn.execute(
                """
                INSERT INTO vendor_signatures (
                    package_name, api_name, potential_sink_class, signature_pattern
                ) VALUES (?, ?, ?, ?)
                ON CONFLICT(package_name, api_name) DO UPDATE SET
                    potential_sink_class = excluded.potential_sink_class,
                    signature_pattern = excluded.signature_pattern
                RETURNING sig_id;
                """,
                (package_name, api_name, potential_sink_class, signature_pattern),
            )
            row = cursor.fetchone()
            return int(row["sig_id"])

    # =========================================================================
    # Scan Sessions CRUD (Scoped to individual scan executions)
    # =========================================================================

    def create_scan(
        self,
        target_path: str,
        scan_mode: str,
        engine_fingerprint: str,
        config: Optional[Dict[str, Any]] = None,
        base_commit: Optional[str] = None,
        target_commit: Optional[str] = None,
        scan_id: Optional[str] = None,
    ) -> str:
        """Create and track a new scan session."""
        scan_uuid = scan_id or f"scan_{uuid.uuid4().hex[:12]}"
        cfg_json = json.dumps(config or {})
        with self.transaction() as conn:
            conn.execute(
                """
                INSERT INTO scans (
                    scan_id, target_path, scan_mode, base_commit, target_commit,
                    engine_fingerprint, status, config_json
                ) VALUES (?, ?, ?, ?, ?, ?, 'INITIALIZING', ?);
                """,
                (
                    scan_uuid,
                    target_path,
                    scan_mode,
                    base_commit,
                    target_commit,
                    engine_fingerprint,
                    cfg_json,
                ),
            )
        return scan_uuid

    def update_scan_status(
        self,
        scan_id: str,
        status: str,
        stats: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Update status and stats of a scan session."""
        stats_json = json.dumps(stats) if stats else None
        with self.transaction() as conn:
            conn.execute(
                """
                UPDATE scans
                SET status = ?,
                    stats_json = COALESCE(?, stats_json),
                    completed_at = CASE WHEN ? IN ('COMPLETED', 'FAILED', 'ABORTED')
                                        THEN CURRENT_TIMESTAMP ELSE completed_at END
                WHERE scan_id = ?;
                """,
                (status, stats_json, status, scan_id),
            )

    def record_candidate_path(
        self,
        path_id: str,
        scan_id: str,
        sink_id: int,
        hop_count: int,
        call_sequence: List[Any],
        priority_score: float,
        endpoint_id: Optional[int] = None,
        state: str = "QUEUED",
        reachability_confidence: float = 1.0,
    ) -> None:
        """Record candidate reachability path for a scan."""
        seq_json = json.dumps(call_sequence)
        with self.transaction() as conn:
            conn.execute(
                """
                INSERT INTO scan_candidate_paths (
                    path_id, scan_id, endpoint_id, sink_id, hop_count,
                    call_sequence_json, priority_score, reachability_confidence, state
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(path_id) DO UPDATE SET
                    state = excluded.state,
                    priority_score = excluded.priority_score,
                    reachability_confidence = excluded.reachability_confidence,
                    updated_at = CURRENT_TIMESTAMP;
                """,
                (
                    path_id,
                    scan_id,
                    endpoint_id,
                    sink_id,
                    hop_count,
                    seq_json,
                    priority_score,
                    reachability_confidence,
                    state,
                ),
            )

    def record_dossier(
        self,
        dossier_id: str,
        scan_id: str,
        path_id: Optional[str],
        engine_fingerprint: str,
        title: str,
        vuln_class: str,
        severity: str,
        cwe_id: Optional[str],
        verdict: str,
        confidence: Optional[float] = None,
        reachability_confidence: float = 1.0,
        exploitability_confidence: float = 0.85,
        source_trace: Optional[Dict[str, Any] | List[Any]] = None,
        sanitizer_analysis: Optional[Dict[str, Any]] = None,
        evidence_bundle: Optional[Dict[str, Any]] = None,
        finding_fingerprint: Optional[str] = None,
        fingerprint_schema_version: int = 1,
        repro_curl_template: Optional[str] = None,
        repro_template: Optional[Dict[str, Any]] = None,
        mitigation_notes: Optional[str] = None,
    ) -> None:
        """Record verified vulnerability dossier for a scan."""
        trace_json = json.dumps(source_trace or [])
        analysis_json = json.dumps(sanitizer_analysis or {})
        bundle_json = json.dumps(evidence_bundle or {})
        repro_json = json.dumps(repro_template) if repro_template else None
        eff_conf = confidence if confidence is not None else exploitability_confidence
        with self.transaction() as conn:
            conn.execute(
                """
                INSERT INTO scan_dossiers (
                    dossier_id, scan_id, fingerprint_schema_version, finding_fingerprint,
                    path_id, engine_fingerprint, title, vuln_class, severity, cwe_id,
                    verdict, reachability_confidence, exploitability_confidence, confidence,
                    source_trace_json, sanitizer_analysis_json, evidence_bundle_json,
                    repro_curl_template, repro_template_json, mitigation_notes
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(dossier_id) DO UPDATE SET
                    verdict = excluded.verdict,
                    reachability_confidence = excluded.reachability_confidence,
                    exploitability_confidence = excluded.exploitability_confidence,
                    confidence = excluded.confidence,
                    source_trace_json = excluded.source_trace_json,
                    sanitizer_analysis_json = excluded.sanitizer_analysis_json,
                    evidence_bundle_json = excluded.evidence_bundle_json,
                    repro_curl_template = excluded.repro_curl_template,
                    repro_template_json = excluded.repro_template_json,
                    mitigation_notes = excluded.mitigation_notes;
                """,
                (
                    dossier_id,
                    scan_id,
                    fingerprint_schema_version,
                    finding_fingerprint,
                    path_id,
                    engine_fingerprint,
                    title,
                    vuln_class,
                    severity,
                    cwe_id,
                    verdict,
                    reachability_confidence,
                    exploitability_confidence,
                    eff_conf,
                    trace_json,
                    analysis_json,
                    bundle_json,
                    repro_curl_template,
                    repro_json,
                    mitigation_notes,
                ),
            )

    def get_reusable_dossier(
        self,
        path_id: str,
        engine_fingerprint: str,
    ) -> Optional[Dict[str, Any]]:
        """Retrieve cached dossier if engine_fingerprint matches exactly (Version Gating)."""
        with self._get_connection() as conn:
            row = conn.execute(
                """
                SELECT * FROM scan_dossiers
                WHERE path_id = ? AND engine_fingerprint = ?
                ORDER BY created_at DESC
                LIMIT 1;
                """,
                (path_id, engine_fingerprint),
            ).fetchone()
            if not row:
                return None
            res = dict(row)
            res["source_trace"] = json.loads(res["source_trace_json"])
            res["sanitizer_analysis"] = json.loads(res["sanitizer_analysis_json"])
            return res

    def get_scan_dossiers(self, scan_id: str) -> List[Dict[str, Any]]:
        """Retrieve all dossiers produced during a scan session."""
        with self._get_connection() as conn:
            rows = conn.execute(
                "SELECT * FROM scan_dossiers WHERE scan_id = ? ORDER BY severity ASC;",
                (scan_id,),
            ).fetchall()
            dossiers = []
            for r in rows:
                d = dict(r)
                d["source_trace"] = json.loads(d["source_trace_json"])
                d["sanitizer_analysis"] = json.loads(d["sanitizer_analysis_json"])
                dossiers.append(d)
            return dossiers
