# BackTrace Semantic CPG Security Reviewer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build BackTrace into an authoritative, polyglot Semantic Code Property Graph (CPG) security reviewer featuring dual-track analysis (Data-Flow & Authorization/BOLA), multidimensional scope classification, framework route resolution, evidence-gated agentic verification, and non-weaponized endpoint-aware reproduction templates.

**Architecture:** The persistent SQLite CPG (`.audit/audit.db`) is the central semantic spine constructed from Tree-sitter ASTs, symbol tables, and framework resolvers. External scanners (Noir, Semgrep, TruffleHog) act as secondary evidence producers. Analysis splits into Track A (Semantic Data Flow: `Source → Transform/Sanitizer → Sink`) and Track B (Authorization Relationships: `Principal ↔ Object ID ↔ AuthZ Boundary`), which emit candidates to a prioritized queue. An Evidence Sufficiency Gate evaluates security contracts and invokes bounded agents (Linker, Contract-Flow, Dialectic Debate) to produce verified research dossiers, SARIF 2.1.0, and Graph JSON.

**Tech Stack:** Python 3.11+, SQLite3 (WAL mode), NetworkX, Tree-sitter (`tree-sitter<0.22`, `tree-sitter-languages`), Click/Rich (CLI), Pydantic, pytest.

**Spec:** `docs/superpowers/specs/2026-09-28-backtrace-semantic-cpg-reviewer-design.md`

## Global Constraints

- **Language Floor:** Python 3.11+
- **Persistence Target:** `.audit/audit.db` (SQLite) and `.audit/events.jsonl` (JSON Lines).
- **CPG Centrality:** The persistent SQLite CPG is the authoritative truth; external tools only corroborate findings.
- **Circuit Breakers:** Max call depth: 20 hops; Max Linker turns per broken edge: 2; Max debate rounds: 3; Request timeout: 45s; Max file size: 2MB.
- **Strict Non-Goals:** No live network requests to target hosts; no weaponized exploit generation; no monolithic full-repo context dumps; no recursive vendor AST traversal; no uncurated chain-of-thought scratchpad persistence.
- **Canonical Verdicts:** Must strictly use `EXPLOITABLE`, `LIKELY_EXPLOITABLE_PARTIAL_SANITIZATION`, `SAFE_PROVEN`, `INSUFFICIENT_CONTEXT`.

## Review Focus

1. **Information Redaction Resilience:** When external tools omit or redact source lines (e.g. Semgrep `requires login`), the filesystem source hydrator must read the exact lines from disk without falling back to blank or redacted strings.
2. **Dual-Track Non-Conflation:** Track B (BOLA/IDOR) must never be coerced into Track A taint-flow; it must evaluate principal-to-object ownership bindings.
3. **Decoupled Confidence:** Edge and path reachability confidence must not be conflated with vulnerability exploitability confidence. Inferred edges must never masquerade as deterministic compiler facts.
4. **Scope-Severity Independence:** Classifying a file as `CI_CD_PIPELINE` or `INFRASTRUCTURE_IAC` must not automatically force severity to low/medium; it must route findings to domain-appropriate threat models.
5. **Non-Weaponized Reproduction:** Generated reproduction templates must strictly use inert markers (e.g., `BT_FLOW_MARKER_001`, `<controlled-test-value>`) and never output exploit payloads like `' OR 1=1--`.

---

## Tasks

### Task 1: Multidimensional Scope Classifier & Filesystem Source Hydration

**Files:**
- Create: `src/core/scope.py`
- Modify: `src/core/workspace.py`
- Modify: `src/adapters/semgrep.py`
- Test: `tests/test_scope.py`

**Interfaces:**
- Consumes: `FileInfo` from `WorkspaceManager`
- Produces: `ScopeClassifier.classify(file_info: FileInfo) -> ScopeMetadata` containing `execution_domain`, `runtime_role`, `environment`, `artifact_type`, `confidence`, `evidence`.
- Produces: `ScopeClassifier.eligible_for_detector(file_info: FileInfo, detector_type: str) -> bool`.
- Produces: `SourceHydrator.hydrate_snippet(root_path: Path, rel_path: str, line_no: int, snippet: str) -> str`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_scope.py
from pathlib import Path
from src.core.scope import ScopeClassifier, ExecutionDomain, RuntimeRole
from src.core.workspace import FileInfo, SourceHydrator

def test_scope_classifier_dimensions_and_eligibility():
    ci_file = FileInfo(".github/workflows/ci.yml", "/repo/.github/workflows/ci.yml", "yaml", False, "h1", 100)
    spec_file = FileInfo("test/auth.test.ts", "/repo/test/auth.test.ts", "typescript", False, "h2", 50)
    vendor_file = FileInfo("assets/three.js", "/repo/assets/three.js", "javascript", False, "h3", 5000)
    route_file = FileInfo("routes/login.ts", "/repo/routes/login.ts", "typescript", False, "h4", 80)
    
    classifier = ScopeClassifier()
    assert classifier.classify(ci_file).execution_domain == ExecutionDomain.CI_CD_PIPELINE
    assert classifier.classify(spec_file).execution_domain == ExecutionDomain.TEST_MOCK
    assert classifier.classify(vendor_file).execution_domain == ExecutionDomain.VENDOR_DEPENDENCY
    assert classifier.classify(route_file).execution_domain == ExecutionDomain.APPLICATION_RUNTIME
    assert classifier.classify(route_file).runtime_role == RuntimeRole.ROUTE_HANDLER
    
    # Invariant 3: Scope-gated eligibility
    assert classifier.eligible_for_detector(spec_file, "SSRF") is False
    assert classifier.eligible_for_detector(vendor_file, "XSS") is False
    assert classifier.eligible_for_detector(route_file, "SQLI") is True

def test_source_hydrator_resolves_redacted_lines(tmp_path: Path):
    target = tmp_path / "routes" / "search.ts"
    target.parent.mkdir(parents=True)
    target.write_text("line 1\nmodels.sequelize.query(criteria)\nline 3\n", encoding="utf-8")
    
    hydrator = SourceHydrator(tmp_path)
    snippet = hydrator.hydrate_snippet("routes/search.ts", 2, "requires login")
    assert "models.sequelize.query(criteria)" in snippet
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_scope.py -v`
Expected: FAIL with "No module named 'src.core.scope'"

- [ ] **Step 3: Implement `ScopeClassifier` and `SourceHydrator`**

Implement 4D classification (`execution_domain`, `runtime_role`, `environment`, `artifact_type`) with calibrated confidence and evidence extraction in `src/core/scope.py`. Implement filesystem fallback line hydration in `src/core/workspace.py` and integrate with `SemgrepAdapter` to replace redacted `requires login` snippets.

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_scope.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/core/scope.py src/core/workspace.py src/adapters/semgrep.py tests/test_scope.py
git commit -m "feat(core): implement multidimensional scope classifier and filesystem source hydrator"
```

---

### Task 2: Persistent CPG Schema Evolution & Multi-Evidence Lifecycle

**Files:**
- Modify: `src/storage/schema.sql`
- Modify: `src/storage/db.py`
- Test: `tests/test_cpg_schema.py`

**Interfaces:**
- Consumes: Multidimensional file metadata, logical graph edges, and edge evidence records.
- Produces: `DatabaseManager` with `graph_edge_evidence` lifecycle tracking, `triage_severity` on candidate sinks, versioned `finding_fingerprint` on dossiers, automated SQLite table migrations, and symbol/file invalidation semantics.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_cpg_schema.py
from pathlib import Path
from src.storage.db import DatabaseManager

def test_schema_supports_multi_evidence_and_lifecycle(tmp_path: Path):
    db = DatabaseManager(tmp_path / "cpg.db")
    db.init_schema()
    
    f1 = db.upsert_file("app.py", "python", False, "h1", 100, execution_domain="APPLICATION_RUNTIME")
    s1 = db.insert_symbol(f1, "main", "FUNCTION", 1, 0, 5, 0)
    s2 = db.insert_symbol(f1, "helper", "FUNCTION", 6, 0, 10, 0)
    
    # Insert logical edge
    edge_id = db.insert_graph_edge(s1, s2, "CALL")
    
    # Insert multiple independent evidence records for the same logical edge
    db.insert_edge_evidence(edge_id, "FRAMEWORK_RESOLVER", 0.98, {"route": "/api"}, commit_sha="abc1")
    db.insert_edge_evidence(edge_id, "LINKER_AGENT", 0.75, {"reason": "DI binding"}, commit_sha="abc1")
    
    evidence = db.get_active_edge_evidence(edge_id)
    assert len(evidence) == 2
    
    # Invalidate evidence on commit change / symbol mutation
    db.invalidate_file_symbols(f1)
    active_evidence = db.get_active_edge_evidence(edge_id)
    assert len(active_evidence) == 0
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_cpg_schema.py -v`
Expected: FAIL with missing methods or schema mismatch

- [ ] **Step 3: Update `src/storage/schema.sql` and `src/storage/db.py`**

Evolve schema with `execution_domain`/`runtime_role` in `files`, `triage_severity` in `candidate_sinks`, `graph_edge_evidence` table with `is_active` and `indexed_commit`, and versioned `finding_fingerprint` in `scan_dossiers`. Implement atomic invalidation methods and automatic SQLite table migrations in `init_schema()`.

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_cpg_schema.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/storage/schema.sql src/storage/db.py tests/test_cpg_schema.py
git commit -m "feat(storage): implement multi-evidence graph edge lifecycle and CPG mutation semantics"
```

---

### Task 3: Framework Semantic Identity & Express Route/Middleware Resolver

**Files:**
- Create: `src/frameworks/__init__.py`
- Create: `src/frameworks/detector.py`
- Create: `src/frameworks/base.py`
- Create: `src/frameworks/express.py`
- Test: `tests/test_framework_express.py`

**Interfaces:**
- Consumes: Target repository path, package manifests (`package.json`, lockfiles), and AST symbol graph.
- Produces: `FrameworkResolver.resolve_endpoints() -> List[FrameworkEndpoint]` with hierarchical route prefix composition, inherited global middleware, and tri-state `auth_state` (`REQUIRED`, `NOT_REQUIRED`, `UNKNOWN`).

- [ ] **Step 1: Write the failing test**

```python
# tests/test_framework_express.py
from pathlib import Path
from src.frameworks.detector import FrameworkDetector
from src.frameworks.express import ExpressResolver

def test_express_route_composition_and_middleware_inheritance(tmp_path: Path):
    app_js = tmp_path / "app.js"
    app_js.write_text("""
        const express = require('express');
        const app = express();
        const userRouter = require('./routes/users');
        app.use(authMiddleware);
        app.use('/api/v1', userRouter);
    """, encoding="utf-8")
    
    users_js = tmp_path / "routes" / "users.js"
    users_js.parent.mkdir(parents=True)
    users_js.write_text("""
        const express = require('express');
        const router = express.Router();
        router.post('/login', loginController);
        module.exports = router;
    """, encoding="utf-8")
    
    detector = FrameworkDetector(tmp_path)
    assert detector.identify() == "express"
    
    resolver = ExpressResolver(tmp_path)
    endpoints = resolver.resolve_endpoints()
    
    login_ep = next((e for e in endpoints if e.route_pattern == "/api/v1/login"), None)
    assert login_ep is not None
    assert login_ep.http_method == "POST"
    assert login_ep.auth_state == "REQUIRED"  # Inherited from app.use(authMiddleware)
    assert login_ep.handler_symbol == "loginController"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_framework_express.py -v`
Expected: FAIL with "No module named 'src.frameworks'"

- [ ] **Step 3: Implement `FrameworkDetector` and `ExpressResolver`**

Implement evidence-based framework identity in `src/frameworks/detector.py`. Implement Express AST route resolver supporting `app.use()` router mounting, path composition, global middleware propagation, and tri-state authentication classification in `src/frameworks/express.py`.

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_framework_express.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/frameworks/ tests/test_framework_express.py
git commit -m "feat(frameworks): implement Express route composition and inherited middleware resolver"
```

---

### Task 4: Track A: Semantic Source, Transform, and Sink Detectors

**Files:**
- Create: `src/semantic/__init__.py`
- Create: `src/semantic/sources.py`
- Create: `src/semantic/transforms.py`
- Create: `src/semantic/sinks.py`
- Create: `src/semantic/detector.py`
- Test: `tests/test_semantic_matrix.py`

**Interfaces:**
- Consumes: AST CST nodes from `TreeSitterIndexer`
- Produces: `SemanticDetector.scan_source(file_path: Path, code: str, language: str) -> SemanticFileFindings` emitting `CANDIDATE_FLOW` elements across SSRF, SQLi, XXE, NoSQLi, Deserialization, Path Traversal, Command Injection, and Context-Aware Template XSS.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_semantic_matrix.py
from src.semantic.detector import SemanticDetector

def test_semantic_detectors_capture_ssrf_xxe_nosqli():
    js_code = """
        const needle = require('needle');
        const libxmljs = require('libxmljs');
        const User = require('./models/user');
        
        function handleSsrf(req, res) {
            const targetUrl = req.query.url;
            needle.get(targetUrl); // SSRF Sink
        }
        
        function handleXxe(req, res) {
            const xml = req.body.xml;
            parseXmlString(xml); // Direct import XXE Sink
        }
        
        function handleNoSql(req, res) {
            db.ordersCollection.find({ $where: req.body.selector }); // NoSQL Injection Sink
        }
    """
    detector = SemanticDetector()
    findings = detector.scan_source("routes/test.js", js_code, "javascript")
    
    sink_types = {s.vuln_class for s in findings.sinks}
    assert "SSRF" in sink_types
    assert "XXE" in sink_types
    assert "NOSQLI" in sink_types

def test_semantic_invariants_reject_literals_and_supertest():
    js_code = """
        const request = require('supertest');
        request(app).get('/api/users');
        fetch("https://pastebin.com/static_hash");
        fs.readFileSync('./swagger.yml', 'utf8');
        if (value !== undefined) { doSomething(); }
    """
    detector = SemanticDetector()
    findings = detector.scan_source("app.js", js_code, "javascript")
    assert len(findings.sinks) == 0
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_semantic_matrix.py -v`
Expected: FAIL with "No module named 'src.semantic'"

- [ ] **Step 3: Implement Semantic Source, Transform, and Sink Matrix**

Implement AST detectors in `src/semantic/`: sources (`req.body`, `req.query`, etc.), transforms (`path.join` as path construction, `parseInt` as domain constraint, sanitizers), and configuration-aware sinks (SSRF, XXE, NoSQLi, Deserialization, SQLi, Path Traversal, RCE, context-aware template output). Enforce Invariants 1, 2, 5, and 6.

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_semantic_matrix.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/semantic/ tests/test_semantic_matrix.py
git commit -m "feat(semantic): implement Track A source, transform, and sink matrix with configuration awareness"
```

---

### Task 5: Track B: Authorization Relationship Analyzer (BOLA / IDOR)

**Files:**
- Create: `src/semantic/authz.py`
- Test: `tests/test_authz_analyzer.py`

**Interfaces:**
- Consumes: Endpoint definitions, Principal extraction logic, and Data Access AST operations.
- Produces: `AuthorizationAnalyzer.analyze_handler(method, route, code, language) -> AuthzAnalysisResult` emitting `AUTHZ_CONSTRAINT_PRESENT` for owner/tenant-scoped queries or `CANDIDATE_AUTHZ_GAP` for unscoped lookups.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_authz_analyzer.py
from src.semantic.authz import AuthorizationAnalyzer

def test_authz_analyzer_detects_bola_and_scoped_queries():
    analyzer = AuthorizationAnalyzer()
    
    # Unscoped lookup without ownership check (Juice Shop Basket scenario)
    vulnerable_route = """
        function getBasket(req, res) {
            const basketId = req.params.id;
            BasketModel.findOne({ where: { id: basketId } }).then(basket => {
                res.json(basket);
            });
        }
    """
    vuln_result = analyzer.analyze_handler("GET", "/rest/basket/:id", vulnerable_route, "javascript")
    assert vuln_result.has_gap is True
    assert vuln_result.gap_type == "CANDIDATE_AUTHZ_GAP"
    assert vuln_result.object_key == "req.params.id"
    
    # Scoped lookup binding principal ownership
    safe_route = """
        function getBasket(req, res) {
            const basketId = req.params.id;
            BasketModel.findOne({ where: { id: basketId, UserId: req.user.id } }).then(basket => {
                res.json(basket);
            });
        }
    """
    safe_result = analyzer.analyze_handler("GET", "/rest/basket/:id", safe_route, "javascript")
    assert safe_result.has_gap is False
    assert safe_result.status == "AUTHZ_CONSTRAINT_PRESENT"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_authz_analyzer.py -v`
Expected: FAIL with "No module named 'src.semantic.authz'"

- [ ] **Step 3: Implement `AuthorizationAnalyzer` in `src/semantic/authz.py`**

Implement Track B authorization analyzer auditing principal extraction (User, Tenant, Role), target resource keys, and data access query predicates (`where: { userId }`), emitting `AUTHZ_CONSTRAINT_PRESENT` or `CANDIDATE_AUTHZ_GAP`.

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_authz_analyzer.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/semantic/authz.py tests/test_authz_analyzer.py
git commit -m "feat(semantic): implement Track B Authorization Relationship Analyzer for BOLA/IDOR detection"
```

---

### Task 6: State-Aware Graph Reachability & Bounded Confidence Aggregation

**Files:**
- Modify: `src/graph/cpg.py`
- Modify: `src/graph/reachability.py`
- Modify: `src/triage/scorer.py`
- Test: `tests/test_state_reachability.py`

**Interfaces:**
- Consumes: CPG with multi-evidence edges and candidate flow nodes.
- Produces: `ReachabilityAnalyzer.find_paths(...) -> List[CandidatePath]` with state-aware traversal keys `(node_id, edge_type, analysis_state)`, 20-hop depth cutoff, and weakest-link path confidence aggregation.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_state_reachability.py
from src.graph.cpg import CodePropertyGraph
from src.graph.reachability import ReachabilityAnalyzer

def test_state_aware_traversal_and_bounded_confidence():
    cpg = CodePropertyGraph()
    cpg.add_node("ep_1", kind="ENDPOINT")
    cpg.add_node("ctrl_1", kind="SYMBOL")
    cpg.add_node("srv_1", kind="SYMBOL")
    cpg.add_node("sink_1", kind="SINK")
    
    cpg.add_edge_with_evidence("ep_1", "ctrl_1", "HANDLED_BY", "FRAMEWORK_RESOLVER", 0.98)
    cpg.add_edge_with_evidence("ctrl_1", "srv_1", "CALL", "DETERMINISTIC_AST", 0.95)
    cpg.add_edge_with_evidence("srv_1", "sink_1", "CALL", "LINKER_AGENT", 0.70)
    
    analyzer = ReachabilityAnalyzer(cpg)
    paths = analyzer.find_paths("ep_1", "sink_1", max_hops=20)
    
    assert len(paths) == 1
    # Bounded weakest-link confidence aggregation: min(0.98, 0.95, 0.70) = 0.70
    assert paths[0].reachability_confidence == 0.70
    assert paths[0].hop_count == 3
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_state_reachability.py -v`
Expected: FAIL with attribute/method error

- [ ] **Step 3: Implement State-Aware Reachability & Bounded Confidence**

Update `CodePropertyGraph` and `ReachabilityAnalyzer` in `src/graph/` to implement composite state keys `(node_id, edge_type, analysis_state)`, bounded weakest-link path confidence $\min(\text{edge\_confidence}) \times \text{completeness}$, and update triage queue priority scoring incorporating scope factor and tri-state exposure.

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_state_reachability.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/graph/ src/triage/ tests/test_state_reachability.py
git commit -m "feat(graph): implement state-aware reachability and bounded weakest-link confidence aggregation"
```

---

### Task 7: Evidence-Gated Agentic Verification & Canonical Verdicts

**Files:**
- Modify: `src/agents/linker.py`
- Modify: `src/agents/contract_flow.py`
- Modify: `src/agents/debate.py`
- Create: `src/agents/verifier.py`
- Test: `tests/test_evidence_gate.py`

**Interfaces:**
- Consumes: Prioritized candidate paths (`CandidatePath`), AST slices, and database state.
- Produces: `EvidenceGateVerifier.evaluate_contract(evidence_bundle: EvidenceBundle) -> VerificationResult` assigning strictly one of `EXPLOITABLE`, `LIKELY_EXPLOITABLE_PARTIAL_SANITIZATION`, `SAFE_PROVEN`, or `INSUFFICIENT_CONTEXT` backed by a structured evidence bundle.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_evidence_gate.py
from src.agents.verifier import EvidenceBundle, EvidenceGateVerifier
from src.storage.db import VerdictStatus

def test_evidence_sufficiency_gate_strict_verdicts():
    verifier = EvidenceGateVerifier()
    
    # Case 1: Incomplete evidence (no path) -> INSUFFICIENT_CONTEXT
    bundle_unproven = EvidenceBundle(
        source_node=None,
        path_trace=None,
        sink_node={"vuln_class": "SQLI"},
        reachability_confidence=0.0,
        bypass_reasoning="Manufactured claim",
    )
    res_unproven = verifier.evaluate_contract(evidence_bundle=bundle_unproven)
    assert res_unproven.verdict == VerdictStatus.INSUFFICIENT_CONTEXT
    assert res_unproven.verdict != VerdictStatus.EXPLOITABLE

    # Case 2: Full proof -> EXPLOITABLE
    bundle_proven = EvidenceBundle(
        source_node={"route": "/api"},
        path_trace=[{"node": "ep"}, {"node": "sink"}],
        sink_node={"vuln_class": "SQLI"},
        reachability_confidence=0.85,
        bypass_reasoning="Direct string concatenation into query",
    )
    res_proven = verifier.evaluate_contract(evidence_bundle=bundle_proven)
    assert res_proven.verdict == VerdictStatus.EXPLOITABLE
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_evidence_gate.py -v`
Expected: FAIL with "No module named 'src.agents.verifier'"

- [ ] **Step 3: Implement `EvidenceGateVerifier` and Dialectic Verification**

Implement `EvidenceGateVerifier` in `src/agents/verifier.py` enforcing the formal definitions of all four canonical verdicts. Maintain zero private CoT in persisted evidence bundles. Enforce Linker agent only updates reachability confidence and never asserts exploitability verdicts. Enforce Invariants 7 and 8.

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_evidence_gate.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/agents/ tests/test_evidence_gate.py
git commit -m "feat(agents): implement EvidenceGateVerifier enforcing canonical 4-state contract verdicts"
```

---

### Task 8: Endpoint-Aware Non-Weaponized Reproduction Templates & Exporters

**Files:**
- Modify: `src/reporting/synthesizer.py`
- Modify: `src/reporting/sarif.py`
- Modify: `src/reporting/graph_json.py`
- Modify: `src/reporting/markdown.py`
- Test: `tests/test_repro_synthesizer.py`

**Interfaces:**
- Consumes: Verified dossiers, origin `EndpointNode`, and candidate path trace.
- Produces: Non-weaponized, structured reproduction blueprints (`reproduction_type`: `HTTP_TEMPLATE`, `NON_HTTP_TEMPLATE`, `PARTIAL_TEMPLATE`, `NONE`) with inert test markers (`BT_FLOW_MARKER_001`), exported via SARIF 2.1.0, scoped Graph JSON, and Markdown.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_repro_synthesizer.py
from src.reporting.synthesizer import DossierSynthesizer

def test_reproduction_synthesizer_emits_assertion_blueprint():
    synthesizer = DossierSynthesizer()
    blueprint = synthesizer.generate_reproduction_template(
        endpoint_method="POST",
        route_pattern="/rest/user/login",
        auth_state="REQUIRED",
        tainted_param={"location": "BODY", "name": "email"},
        sibling_params=[{"location": "BODY", "name": "password", "dummy": "dummyPass123!"}],
        sink_target="models.sequelize.query"
    )
    
    assert blueprint["reproduction_type"] == "HTTP_TEMPLATE"
    # Must use inert marker, NEVER weaponized payload
    assert "BT_FLOW_MARKER_001" in blueprint["curl_command"]
    assert "' OR 1=1--" not in blueprint["curl_command"]
    assert "Authorization: Bearer ${AUTH_TOKEN}" in blueprint["curl_command"]
    assert blueprint["expected_assertion"]["assertion_type"] == "PARAMETER_REACHABILITY"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_repro_synthesizer.py -v`
Expected: FAIL with missing method

- [ ] **Step 3: Update `DossierSynthesizer` and Exporters**

Update `src/reporting/synthesizer.py` to generate structured, non-weaponized reproduction blueprints. Update `src/reporting/sarif.py` to embed `codeFlows`, `src/reporting/graph_json.py` to support `--graph-scope` (`repository`, `symbol`, `finding`), and `src/reporting/markdown.py` to display assertion blueprints.

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_repro_synthesizer.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/reporting/ tests/test_repro_synthesizer.py
git commit -m "feat(reporting): implement endpoint-aware non-weaponized reproduction templates and scoped exporters"
```

---

### Task 9: Incremental CPG Invalidation, Version Gating & Full CLI Pipeline Integration

**Files:**
- Modify: `src/diff/git_scanner.py`
- Modify: `src/cli.py`
- Test: `tests/test_pipeline_e2e.py`
- Test: `tests/test_invariants_verification.py`

**Interfaces:**
- Consumes: CLI commands (`scan`, `diff`, `report`, `resume`) against real repositories.
- Produces: Fully integrated BackTrace pipeline executing Scope Classifier → Framework Resolver → Persistent CPG → Dual-Track Detectors → State-Aware Reachability → Evidence Gate → Verified Dossiers.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_pipeline_e2e.py
from pathlib import Path
from click.testing import CliRunner
from src.cli import cli
from src.storage.db import DatabaseManager

def test_full_backtrace_pipeline_on_synthetic_repo(tmp_path: Path):
    app_file = tmp_path / "app.js"
    app_file.write_text("""
        const express = require('express');
        const needle = require('needle');
        const app = express();
        app.get('/api/fetch', (req, res) => {
            const url = req.query.url;
            needle.get(url);
        });
    """, encoding="utf-8")
    
    runner = CliRunner()
    res = runner.invoke(cli, ["scan", str(tmp_path)])
    assert res.exit_code == 0
    
    db = DatabaseManager(tmp_path / ".audit" / "audit.db")
    with db._get_connection() as conn:
        scans = conn.execute("SELECT scan_id FROM scans ORDER BY started_at DESC LIMIT 1;").fetchone()
        scan_id = scans["scan_id"]
    
    dossiers = db.get_scan_dossiers(scan_id)
    assert len(dossiers) >= 1
    ssrf_dossier = next((d for d in dossiers if d["vuln_class"] == "SSRF"), None)
    assert ssrf_dossier is not None
    assert ssrf_dossier["verdict"] in ("EXPLOITABLE", "LIKELY_EXPLOITABLE_PARTIAL_SANITIZATION")
    assert "BT_FLOW_MARKER_001" in ssrf_dossier["repro_curl_template"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_pipeline_e2e.py -v`
Expected: FAIL with missing dossier or unintegrated pipeline

- [ ] **Step 3: Integrate End-to-End Pipeline in `src/cli.py` and `src/diff/git_scanner.py`**

Wire the complete pipeline in `src/cli.py`: run Scope Classification → Framework Resolvers → Semantic Detectors → Graph Edges with Evidence → Reachability → Evidence Sufficiency Gate → Dossier Synthesis. Enforce Invariant 4 (zero endpoint fallback). Update `GitDiffEngine` with the versioned `finding_fingerprint` and strengthened `engine_fingerprint`.

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_pipeline_e2e.py tests/test_invariants_verification.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/cli.py src/diff/git_scanner.py tests/test_pipeline_e2e.py tests/test_invariants_verification.py
git commit -m "feat(cli): wire authoritative semantic CPG pipeline with versioned incremental diff scanner"
```

---

## Plan Self-Review Checklist

1. **Spec Coverage:**
   - Multidimensional Scope (Section 4) → Task 1.
   - Filesystem Source Hydration (Section 11) → Task 1.
   - CPG Schema & Invalidation (Section 7) → Task 2.
   - Framework Semantic Resolvers (Section 5) → Task 3.
   - Track A Data-Flow Matrix (Section 6.1) → Task 4.
   - Track B Authorization Analyzer (Section 6.2) → Task 5.
   - State-Aware Reachability & Bounded Confidence (Section 7.2, 7.3) → Task 6.
   - Evidence-Gated Verification & Canonical Verdicts (Section 8) → Task 7.
   - Reproduction Blueprints & Exporters (Section 9, 10) → Task 8.
   - Incremental Scanner & CLI (Section 7.4, 10.2) → Task 9.
2. **Review Focus Pinning:**
   - Information Redaction Resilience pinned in Task 1.
   - Dual-Track Non-Conflation pinned in Tasks 4 & 5.
   - Decoupled Confidence pinned in Tasks 2, 6 & 7.
   - Scope-Severity Independence pinned in Task 1.
   - Non-Weaponized Reproduction pinned in Task 8.
3. **Type Consistency:**
   - Canonical 4-state verdict enum strictly adhered to across all tasks.
   - Logical edges `(caller, callee, edge_type)` decoupled from `graph_edge_evidence`.
   - `finding_fingerprint` versioned with schema version 1.
4. **Bite-Sized Testability:**
   - Every task has a designated failing test with concrete names and assertions.
   - Every task ends with an independent verification command and commit.
