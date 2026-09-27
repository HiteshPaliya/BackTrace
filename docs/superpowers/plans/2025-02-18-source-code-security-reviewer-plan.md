# Polyglot Source Code Security Reviewer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a robust, polyglot, cross-file source code security review system orchestrating external scanners (Noir, Semgrep, TruffleHog), a persistent repository-level Tree-sitter Code Property Graph, scan-session state management in SQLite (`.audit/audit.db`), and Strands LLM agents (Gemini 3.8 Flash default / local fallback) to generate actionable vulnerability research dossiers with curl repro templates.

**Architecture:** A tiered hybrid pipeline: 
1. Workspace canonicalization and tool adapters normalize endpoints, sinks, and secrets.
2. Persistent Repository Graph: `files`, `symbols`, `endpoints`, `candidate_sinks`, `graph_edges`, and `vendor_signatures` survive scan sessions in SQLite (`.audit/audit.db`).
3. Scan Sessions & Execution: Ephemeral scan runs (`scans`, `scan_candidate_paths`, `scan_dossiers`) evaluate reachability and agent verdicts, fully supporting incremental Git-diff scans with working-tree evaluation, graph impact propagation, and strict engine fingerprint version gating.
4. Strands Agent SDK orchestrates Linker agents (resolving and persisting dynamic dispatch edges), Contract-Flow agents (verifying sanitizers), and an Adversarial Debate engine (prosecuting high-severity bypasses without storing private CoT scratchpads).
5. Dossier synthesizer produces interactive CLI views, research Markdown reports, standard SARIF 2.1.0, and Graph JSON output.

**Tech Stack:** Python 3.11+, SQLite3 (WAL mode), NetworkX, Tree-sitter (`tree-sitter-languages`), Strands Agent SDK (`strands-agents` / Google GenAI SDK), Rich/Click (CLI), SARIF SDK.

**Spec:** `SPEC.md` / `docs/superpowers/specs/2025-02-18-source-code-security-reviewer-design.md`

## Global Constraints

- **Language Floor:** Python 3.11+
- **Persistence Target:** `.audit/audit.db` (SQLite) and `.audit/events.jsonl` (JSON Lines)
- **Graph Decoupling:** Persistent repository graph (`files`, `symbols`, `graph_edges`, etc.) MUST NOT have a `scan_id` foreign key; they belong to the repository. Only `scans`, `scan_candidate_paths`, and `scan_dossiers` are scan-scoped.
- **Circuit Breakers:** Max call depth: 20 hops; Max Linker agents per broken edge: 2; Max agent turns per path: 8; Request timeout: 45s; Max file size: 2MB.
- **Strict Non-Goals:** No live network requests to target hosts; no weaponized binary exploit generation; no monolithic full-repo context dumping; no recursive vendor AST traversal; no uncurated chain-of-thought scratchpad persistence.
- **Taint Verdicts:** Must strictly use `EXPLOITABLE`, `LIKELY_EXPLOITABLE_PARTIAL_SANITIZATION`, `SAFE_PROVEN`, `INSUFFICIENT_CONTEXT`.

## Review Focus

1. **Working-Tree Diff & Untracked Files:** `GitDiffEngine` must capture unstaged, staged, and untracked additions against `base_ref` (e.g. `git diff --name-only <base_ref>` plus `git ls-files --others --exclude-standard`), rather than assuming a committed commit-to-commit diff.
2. **Version Gating for Incremental Cache:** Cached findings must be invalidated if `engine_fingerprint` (tool versions, Semgrep rulesets, model ID, or scanner config) changes, even if the source code did not change.
3. **Linker Edge Persistence & Provenance:** Linker agents must persist resolved edges into `graph_edges` with `provenance='AGENT_INFERRED'` and its confidence score, verified via SQLite queries.
4. **No Private Chain-of-Thought Persistence:** Adversarial debate dialectic must synthesize curated structured evidence (`source_control_evidence`, `transform_sanitizer_evidence`, `sink_requirements`, `bypass_reasoning`) into `scan_dossiers`; raw model monologues must never be stored.
5. **Thread-Safe & Flushed Event Log:** Concurrent workers logging to `.audit/events.jsonl` must acquire a process-level lock, and critical transitions must flush immediately without line corruption.

---

## Tasks

### Task 1: Project Scaffolding & Workspace Manager

**Files:**
- Create: `pyproject.toml`
- Create: `src/__init__.py`
- Create: `src/core/__init__.py`
- Create: `src/core/workspace.py`
- Test: `tests/test_workspace.py`

**Interfaces:**
- Consumes: Filesystem path (root string/Path)
- Produces: `WorkspaceManager.discover_files(root: Path) -> List[FileInfo]` where `FileInfo` has `rel_path`, `abs_path`, `language`, `is_vendor`, `file_hash`, `loc`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_workspace.py
from pathlib import Path
import pytest
from src.core.workspace import WorkspaceManager, FileInfo

def test_workspace_canonicalization_and_filtering(tmp_path: Path):
    # Setup test directory with valid code, vendor code, and minified file
    src_file = tmp_path / "app.py"
    src_file.write_text("print('hello world')", encoding="utf-8")
    
    vendor_dir = tmp_path / "node_modules" / "pkg"
    vendor_dir.mkdir(parents=True)
    vendor_file = vendor_dir / "index.js"
    vendor_file.write_text("module.exports = {}", encoding="utf-8")
    
    min_file = tmp_path / "bundle.min.js"
    min_file.write_text("a" * 2000, encoding="utf-8")
    
    wm = WorkspaceManager(root_path=tmp_path)
    files = wm.discover_files()
    
    rel_paths = {f.rel_path for f in files}
    assert "app.py" in rel_paths
    assert "bundle.min.js" not in rel_paths  # Minified files skipped
    
    vendor_f = next(f for f in files if f.rel_path == "node_modules/pkg/index.js")
    assert vendor_f.is_vendor is True
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_workspace.py -v`
Expected: FAIL with "ModuleNotFoundError: No module named 'src'"

- [ ] **Step 3: Implement `pyproject.toml` and `WorkspaceManager` in `src/core/workspace.py`**

Configure `pyproject.toml` dependencies (`networkx`, `tree-sitter`, `rich`, `click`, `pydantic`). Implement `WorkspaceManager` with safe path canonicalization, max file size cutoff (2MB), average line length check (>1000 chars skipped as minified), and vendor path tagging.

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_workspace.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add pyproject.toml src/core/workspace.py tests/test_workspace.py
git commit -m "feat(core): implement WorkspaceManager with path canonicalization and vendor tagging"
```

---

### Task 2: SQLite Decoupled Repository & Scan State Store

**Files:**
- Create: `src/storage/__init__.py`
- Create: `src/storage/schema.sql`
- Create: `src/storage/db.py`
- Test: `tests/test_db.py`

**Interfaces:**
- Consumes: SQLite DB path (`.audit/audit.db`)
- Produces: `DatabaseManager` providing connection pooling, WAL mode, transaction context managers, persistent repository CRUD (files, symbols, endpoints, sinks, edges), and scan-scoped execution CRUD (scans, candidate paths, dossiers) with `engine_fingerprint` tracking.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_db.py
from pathlib import Path
import pytest
from src.storage.db import DatabaseManager

def test_database_initialization_and_scan_decoupling(tmp_path: Path):
    db_file = tmp_path / ".audit" / "audit.db"
    db = DatabaseManager(db_file)
    db.init_schema()
    
    # 1. Insert into persistent repo graph (independent of scan_id)
    file_id = db.upsert_file("app.py", "python", is_vendor=False, file_hash="hash_1", loc=50)
    sym_id = db.insert_symbol(file_id, "main", "FUNCTION", 1, 0, 10, 0, "def main():", "global")
    assert file_id > 0
    assert sym_id > 0
    
    # 2. Start Scan 1 (FULL) with engine fingerprint
    scan_1 = db.create_scan(
        target_path=str(tmp_path), 
        scan_mode="FULL", 
        engine_fingerprint="fp_v1",
        config={"workers": 4}
    )
    db.update_scan_status(scan_1, "COMPLETED")
    
    # 3. Start Scan 2 (DIFF) - verify persistent graph still exists
    scan_2 = db.create_scan(
        target_path=str(tmp_path), 
        scan_mode="DIFF", 
        engine_fingerprint="fp_v1",
        config={"workers": 4}
    )
    files = db.get_all_files()
    assert len(files) == 1
    assert files[0]["rel_path"] == "app.py"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_db.py -v`
Expected: FAIL with "No module named 'src.storage'"

- [ ] **Step 3: Implement `src/storage/schema.sql` and `DatabaseManager` in `src/storage/db.py`**

Embed the decoupled schema from SPEC.md Section 4.1. Set `PRAGMA journal_mode = WAL;` and `PRAGMA busy_timeout = 5000;`. Provide atomic scoped transaction contexts.

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_db.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/storage/schema.sql src/storage/db.py tests/test_db.py
git commit -m "feat(storage): initialize decoupled repository graph and scan state store in SQLite"
```

---

### Task 3: Thread-Safe Durable Append-Only Event Log (`.audit/events.jsonl`)

**Files:**
- Create: `src/storage/events.py`
- Test: `tests/test_events.py`

**Interfaces:**
- Consumes: Event metadata (component, event_type, payload dict)
- Produces: `EventLogger.log(component: str, event_type: str, payload: dict) -> EventRecord` with process-level locking and immediate flushing for critical state events.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_events.py
import json
import threading
from pathlib import Path
from src.storage.events import EventLogger

def test_event_logger_concurrent_thread_safety(tmp_path: Path):
    log_file = tmp_path / ".audit" / "events.jsonl"
    logger = EventLogger(log_file, scan_id="test-scan-123")
    
    # Dispatch concurrent writes from multiple threads
    def log_worker(worker_id):
        for i in range(25):
            logger.log("STRANDS_AGENT", "AGENT_STEP", {"worker": worker_id, "step": i})
            
    threads = [threading.Thread(target=log_worker, args=(t,)) for t in range(4)]
    for t in threads: t.start()
    for t in threads: t.join()
    
    lines = log_file.read_text().strip().split("\n")
    assert len(lines) == 100
    for line in lines:
        record = json.loads(line)
        assert record["scan_id"] == "test-scan-123"
        assert record["component"] == "STRANDS_AGENT"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_events.py -v`
Expected: FAIL with "No module named 'src.storage.events'"

- [ ] **Step 3: Implement `EventLogger` in `src/storage/events.py`**

Implement thread-safe writer with `threading.Lock()`. Call `flush()` and `os.fdatasync()` on critical events (`PATH_TRANSITION`, `DOSSIER_SYNTHESIZED`, `CIRCUIT_BREAKER_TRIGGERED`).

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_events.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/storage/events.py tests/test_events.py
git commit -m "feat(storage): implement thread-safe durable event logger with immediate flush"
```

---

### Task 4: Pluggable `ToolAdapter` Framework & Adapters (Noir, Semgrep, TruffleHog)

**Files:**
- Create: `src/adapters/__init__.py`
- Create: `src/adapters/base.py`
- Create: `src/adapters/noir.py`
- Create: `src/adapters/semgrep.py`
- Create: `src/adapters/trufflehog.py`
- Create: `src/adapters/manager.py`
- Test: `tests/test_adapters.py`

**Interfaces:**
- Consumes: `ToolAdapter.run(repo_path: Path) -> ToolExecutionResult`
- Produces: `ToolManager.run_all(repo_path: Path) -> Dict[str, ToolExecutionResult]` with soft degradation when tools are missing from `$PATH`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_adapters.py
from pathlib import Path
from src.adapters.base import ToolAdapter, ToolExecutionResult
from src.adapters.manager import ToolManager

class MockMissingTool(ToolAdapter):
    @property
    def name(self) -> str: return "missing_tool"
    def is_installed(self) -> bool: return False
    def run(self, repo_path: Path, options: dict) -> ToolExecutionResult:
        raise FileNotFoundError("Binary not found")
    def normalize(self, raw_output: str) -> list: return []

def test_tool_manager_handles_missing_tool_softly(tmp_path: Path):
    manager = ToolManager(adapters=[MockMissingTool()])
    results = manager.run_all(tmp_path)
    
    assert "missing_tool" in results
    assert results["missing_tool"].is_available is False
    assert len(results["missing_tool"].warnings) > 0
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_adapters.py -v`
Expected: FAIL with "No module named 'src.adapters'"

- [ ] **Step 3: Implement `ToolAdapter` base and concrete adapters in `src/adapters/`**

Implement `NoirAdapter` (runs `noir -b <repo> --format json`), `SemgrepAdapter` (runs `semgrep scan --json --quiet`), and `TruffleHogAdapter` (runs `trufflehog filesystem <repo> --json`). Wrap all subprocess calls in `subprocess.run(timeout=180)`. Normalize outputs into canonical endpoint, sink, and secret JSON schemas.

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_adapters.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/adapters/ tests/test_adapters.py
git commit -m "feat(adapters): implement pluggable ToolAdapter engine with soft degradation"
```

---

### Task 5: Polyglot Tree-Sitter AST & Symbol/Import Indexer

**Files:**
- Create: `src/indexer/__init__.py`
- Create: `src/indexer/treesitter.py`
- Create: `src/indexer/symbols.py`
- Test: `tests/test_indexer.py`

**Interfaces:**
- Consumes: Source file content and language string
- Produces: `TreeSitterIndexer.index_file(file_path: Path, code: str, language: str) -> IndexResult` containing `symbols: List[ASTSymbol]` and `imports: List[ASTImport]`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_indexer.py
from pathlib import Path
from src.indexer.treesitter import TreeSitterIndexer

def test_treesitter_parses_python_and_js():
    indexer = TreeSitterIndexer()
    
    py_code = """
def authenticate_user(username, password):
    query = f"SELECT * FROM users WHERE name = '{username}'"
    return db.execute(query)
"""
    result = indexer.index_source("auth.py", py_code, "python")
    func_names = [s.name for s in result.symbols]
    assert "authenticate_user" in func_names
    assert any("SELECT" in s.signature or "query" in s.signature for s in result.symbols if s.signature)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_indexer.py -v`
Expected: FAIL with "No module named 'src.indexer'"

- [ ] **Step 3: Implement `TreeSitterIndexer` in `src/indexer/treesitter.py`**

Use `tree_sitter_languages` to load grammars for Python, JavaScript, TypeScript, Go, Java, Ruby, PHP. Implement tree queries extracting function declarations, method definitions, class declarations, and import statements. Handle `ERROR` CST nodes gracefully without crashing.

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_indexer.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/indexer/ tests/test_indexer.py
git commit -m "feat(indexer): implement Tree-sitter polyglot symbol and import indexer"
```

---

### Task 6: Vendor Code Signature Harvester

**Files:**
- Create: `src/indexer/vendor.py`
- Test: `tests/test_vendor.py`

**Interfaces:**
- Consumes: Vendor directories (`node_modules/`, `vendor/`, `site-packages/`)
- Produces: `VendorSignatureHarvester.harvest(vendor_root: Path) -> List[VendorAPISignature]` matching known dangerous sinks into persistent `vendor_signatures`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_vendor.py
from pathlib import Path
from src.indexer.vendor import VendorSignatureHarvester

def test_vendor_signature_harvesting(tmp_path: Path):
    pkg_dir = tmp_path / "node_modules" / "db-helper"
    pkg_dir.mkdir(parents=True)
    (pkg_dir / "index.js").write_text("exports.rawQuery = function(sql) { return db.run(sql); };")
    
    harvester = VendorSignatureHarvester()
    signatures = harvester.harvest(tmp_path / "node_modules")
    
    matched = [s for s in signatures if s.api_name == "rawQuery"]
    assert len(matched) == 1
    assert matched[0].potential_sink_class == "SQLI"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_vendor.py -v`
Expected: FAIL with "No module named 'src.indexer.vendor'"

- [ ] **Step 3: Implement `VendorSignatureHarvester` in `src/indexer/vendor.py`**

Implement shallow regex/AST export parsing across vendor packages, mapping exported APIs against a curated database of known sink signatures.

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_vendor.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/indexer/vendor.py tests/test_vendor.py
git commit -m "feat(indexer): implement shallow vendor signature harvester"
```

---

### Task 7: In-Memory Code Property Graph & Reachability Engine

**Files:**
- Create: `src/graph/__init__.py`
- Create: `src/graph/cpg.py`
- Create: `src/graph/reachability.py`
- Test: `tests/test_reachability.py`

**Interfaces:**
- Consumes: Persistent Repository Graph (from SQLite `.audit/audit.db`)
- Produces: `ReachabilityAnalyzer.find_candidate_paths(endpoint_id: int, sink_id: int, max_hops=20) -> List[CandidatePath]` with cycle pruning.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_reachability.py
from src.graph.cpg import CodePropertyGraph
from src.graph.reachability import ReachabilityAnalyzer

def test_reachability_finds_paths_and_prunes_cycles():
    cpg = CodePropertyGraph()
    # Add nodes: Endpoint -> FuncA -> FuncB (cycle to FuncA) -> Sink
    cpg.add_node("endpoint_1", kind="ENDPOINT")
    cpg.add_node("func_a", kind="FUNCTION")
    cpg.add_node("func_b", kind="FUNCTION")
    cpg.add_node("sink_1", kind="SINK")
    
    cpg.add_edge("endpoint_1", "func_a", edge_type="CALL", confidence=1.0)
    cpg.add_edge("func_a", "func_b", edge_type="CALL", confidence=1.0)
    cpg.add_edge("func_b", "func_a", edge_type="CALL", confidence=1.0) # Cycle!
    cpg.add_edge("func_b", "sink_1", edge_type="CALL", confidence=1.0)
    
    analyzer = ReachabilityAnalyzer(cpg)
    paths = analyzer.find_paths("endpoint_1", "sink_1", max_hops=20)
    
    assert len(paths) == 1
    assert paths[0].nodes == ["endpoint_1", "func_a", "func_b", "sink_1"]
    assert paths[0].hop_count == 3
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_reachability.py -v`
Expected: FAIL with "No module named 'src.graph'"

- [ ] **Step 3: Implement `CodePropertyGraph` and `ReachabilityAnalyzer` in `src/graph/`**

Use NetworkX `DiGraph` synchronized from persistent SQLite tables. Implement depth-first path search tracking visited sets `(node, edge)` to terminate cycles and prune at 20 hops.

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_reachability.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/graph/ tests/test_reachability.py
git commit -m "feat(graph): implement in-memory CPG and cycle-pruning reachability analyzer"
```

---

### Task 8: Composite Triage Scorer & Priority Queue

**Files:**
- Create: `src/triage/__init__.py`
- Create: `src/triage/scorer.py`
- Create: `src/triage/queue.py`
- Test: `tests/test_triage.py`

**Interfaces:**
- Consumes: Candidate paths from `ReachabilityAnalyzer`
- Produces: `TriageQueue.enqueue(path: CandidatePath)` prioritized by `Priority = (Severity * Reachability * Exposure) / Complexity` with SHA256 path deduplication per scan.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_triage.py
from src.triage.scorer import CompositeScorer
from src.triage.queue import TriageQueue, TriageItem

def test_composite_scoring_and_deduplication():
    # Critical RCE, unauthenticated, 2 hops
    score_high = CompositeScorer.calculate_priority(
        sink_severity="CRITICAL",
        reachability_confidence=0.9,
        is_unauthenticated=True,
        hop_count=2
    )
    
    # Low Info, authenticated, 8 hops
    score_low = CompositeScorer.calculate_priority(
        sink_severity="LOW",
        reachability_confidence=0.5,
        is_unauthenticated=False,
        hop_count=8
    )
    
    assert score_high > score_low
    
    queue = TriageQueue()
    queue.push(TriageItem(path_id="sha_1", priority=score_high, data={"val": 1}))
    queue.push(TriageItem(path_id="sha_1", priority=score_high, data={"val": 1})) # Duplicate
    
    assert queue.size() == 1
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_triage.py -v`
Expected: FAIL with "No module named 'src.triage'"

- [ ] **Step 3: Implement `CompositeScorer` and `TriageQueue` in `src/triage/`**

Implement formula from SPEC.md Section 5.4. Implement thread-safe priority queue backed by Python `heapq` and a set of visited `path_id`s.

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_triage.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/triage/ tests/test_triage.py
git commit -m "feat(triage): implement composite scorer and deduplicated priority queue"
```

---

### Task 9: Model Backend Router (Gemini 3.8 Flash + Local Ollama Fallback)

**Files:**
- Create: `src/llm/__init__.py`
- Create: `src/llm/router.py`
- Create: `src/llm/gemini.py`
- Create: `src/llm/ollama.py`
- Test: `tests/test_llm_router.py`

**Interfaces:**
- Consumes: LLM Prompt / Messages, Configuration (Model ID, API Key, Fallback flag)
- Produces: `ModelBackendRouter.generate(prompt: str, context_tokens: int) -> ModelResponse` with exponential backoff on HTTP 429 and automatic failover to Ollama when configured.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_llm_router.py
import pytest
from unittest.mock import MagicMock
from src.llm.router import ModelBackendRouter

def test_router_retries_on_rate_limit():
    mock_backend = MagicMock()
    # First call raises RateLimit (429), second call succeeds
    mock_backend.generate.side_effect = [
        Exception("HTTP 429: Resource Exhausted"),
        {"text": "Analysis complete", "tokens": 150}
    ]
    
    router = ModelBackendRouter(primary_backend=mock_backend, max_retries=2, backoff_base=0.01)
    response = router.complete("Review this code slice")
    
    assert response["text"] == "Analysis complete"
    assert mock_backend.generate.call_count == 2
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_llm_router.py -v`
Expected: FAIL with "No module named 'src.llm'"

- [ ] **Step 3: Implement `ModelBackendRouter`, `GeminiBackend`, and `OllamaBackend` in `src/llm/`**

Integrate Gemini 3.8 Flash via Google GenAI SDK. Integrate local Ollama backend via HTTP REST endpoint (`http://localhost:11434/api/generate`). Implement exponential backoff with jitter on 429/503 errors and 45s hard timeout.

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_llm_router.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/llm/ tests/test_llm_router.py
git commit -m "feat(llm): implement model backend router with exponential backoff and local fallback"
```

---

### Task 10: Strands Linker Agent & Persistent Edge Insertion

**Files:**
- Create: `src/agents/__init__.py`
- Create: `src/agents/tools.py`
- Create: `src/agents/linker.py`
- Test: `tests/test_linker_agent.py`

**Interfaces:**
- Consumes: Broken edge callsite (caller symbol, unresolved target name, enclosing file) and `db: DatabaseManager`
- Produces: `LinkerAgent.resolve_and_persist(...) -> Optional[InferredEdge]`, directly inserting the inferred edge into persistent `graph_edges` with `provenance='AGENT_INFERRED'`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_linker_agent.py
from pathlib import Path
from unittest.mock import MagicMock
from src.agents.linker import LinkerAgent
from src.storage.db import DatabaseManager

def test_linker_agent_infers_and_persists_edge(tmp_path: Path):
    db = DatabaseManager(tmp_path / "test.db")
    db.init_schema()
    f_id = db.upsert_file("src/user.controller.ts", "typescript", False, "h1", 100)
    c_sym = db.insert_symbol(f_id, "UserController.handle", "METHOD", 1, 0, 10, 0, "handle()", "class")
    t_sym = db.insert_symbol(f_id, "UserServiceImpl.update", "METHOD", 20, 0, 30, 0, "update()", "class")
    
    mock_llm = MagicMock()
    mock_llm.complete.return_value = {
        "text": '{"target_symbol": "UserServiceImpl.update", "confidence": 0.85, "reasoning": "Found NestJS provider registration"}'
    }
    
    agent = LinkerAgent(llm_client=mock_llm, db_manager=db, max_turns=2)
    result = agent.resolve_and_persist(
        caller_symbol_id=c_sym,
        target_interface="IUserService.update",
        file_path="src/user.controller.ts"
    )
    
    assert result is not None
    assert result.confidence == 0.85
    assert result.provenance == "AGENT_INFERRED"
    
    # Assert edge was actually persisted in SQLite graph_edges
    edges = db.get_edges_for_caller(c_sym)
    assert len(edges) == 1
    assert edges[0]["callee_symbol_id"] == t_sym
    assert edges[0]["provenance"] == "AGENT_INFERRED"
    assert edges[0]["confidence"] == 0.85
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_linker_agent.py -v`
Expected: FAIL with "No module named 'src.agents'"

- [ ] **Step 3: Implement `LinkerAgent` and tools in `src/agents/linker.py` and `src/agents/tools.py`**

Provide tools to the agent: `grep_codebase(pattern)`, `lookup_symbol(name)`, and `read_file_lines(path, start, end)`. Enforce maximum 2 Linker agent attempts per broken edge. Persist verified inferences into `graph_edges` using SQLite transactions.

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_linker_agent.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/agents/ tests/test_linker_agent.py
git commit -m "feat(agents): implement Strands Linker Agent with persistent graph edge insertion"
```

---

### Task 11: Strands Contract-Flow Agent (Sanitizer & Taint Evaluation)

**Files:**
- Create: `src/agents/contract_flow.py`
- Test: `tests/test_contract_flow.py`

**Interfaces:**
- Consumes: Candidate path context slice (endpoint params, intermediate functions, sink expression)
- Produces: `ContractFlowAgent.evaluate(path_slice: dict) -> TaintVerdict` where verdict is one of `EXPLOITABLE`, `LIKELY_EXPLOITABLE_PARTIAL_SANITIZATION`, `SAFE_PROVEN`, `INSUFFICIENT_CONTEXT`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_contract_flow.py
from unittest.mock import MagicMock
from src.agents.contract_flow import ContractFlowAgent
from src.storage.db import VerdictStatus

def test_contract_flow_agent_evaluates_sanitization():
    mock_llm = MagicMock()
    mock_llm.complete.return_value = {
        "text": '''{
            "verdict": "EXPLOITABLE",
            "confidence": 0.95,
            "source_control_evidence": "User controls req.body.command directly",
            "transform_sanitizer_evidence": "No escaping or validation applied before execution",
            "sink_requirements": "POSIX shell metacharacters trigger command injection",
            "bypass_reasoning": "Direct string concatenation into child_process.exec",
            "suggested_curl": "curl -X POST http://localhost:3000/api/run -d 'command=id'"
        }'''
    }
    
    agent = ContractFlowAgent(llm_client=mock_llm)
    verdict = agent.evaluate({"path_id": "test_p1", "sink": "child_process.exec(cmd)"})
    
    assert verdict.verdict == VerdictStatus.EXPLOITABLE
    assert verdict.confidence == 0.95
    assert "curl" in verdict.suggested_curl
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_contract_flow.py -v`
Expected: FAIL with "No module named 'src.agents.contract_flow'"

- [ ] **Step 3: Implement `ContractFlowAgent` in `src/agents/contract_flow.py`**

Format structured prompts covering source context, intermediate sanitizers/transforms, and sink requirements. Parse response into `TaintVerdict` dataclass. Validate all verdict status strings strictly.

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_contract_flow.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/agents/contract_flow.py tests/test_contract_flow.py
git commit -m "feat(agents): implement ContractFlowAgent for structured taint and sanitizer evaluation"
```

---

### Task 12: Strands Adversarial Debate Engine (Without Storing Private CoT)

**Files:**
- Create: `src/agents/debate.py`
- Test: `tests/test_debate.py`

**Interfaces:**
- Consumes: Ambiguous or critical sink path slice + initial verdict
- Produces: `AdversarialDebateEngine.conduct_debate(path_slice: dict) -> TaintVerdict` returning curated structured evidence only, ensuring raw scratchpads and private model debate monologues are discarded from persisted dossiers.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_debate.py
from unittest.mock import MagicMock
from src.agents.debate import AdversarialDebateEngine
from src.storage.db import VerdictStatus

def test_debate_engine_synthesizes_structured_evidence_without_cot():
    mock_llm = MagicMock()
    # Mock Prosecutor, Defender, and final Judge synthesis
    mock_llm.complete.side_effect = [
        {"text": "Prosecutor: Regex lacks ^ and $ anchors, allowing leading payload injection."},
        {"text": "Defender: Regex correctly matches letters only, but concedes anchor absence."},
        {"text": '''{
            "verdict": "EXPLOITABLE",
            "confidence": 0.88,
            "source_control_evidence": "Attacker supplies unanchored string",
            "transform_sanitizer_evidence": "Regex /admin_[a-z]+/ misses end anchor",
            "sink_requirements": "Requires valid prefix plus SQL injection trailer",
            "bypass_reasoning": "Payload 'admin_user\\' OR 1=1--' bypasses regex and triggers SQLi",
            "suggested_curl": "curl 'http://localhost:8000/role?name=admin_user%27+OR+1%3D1--'"
        }'''}
    ]
    
    engine = AdversarialDebateEngine(llm_client=mock_llm, max_rounds=1)
    verdict = engine.conduct_debate({"sink": "db.raw(query)", "vuln_class": "SQLI"})
    
    assert verdict.verdict == VerdictStatus.EXPLOITABLE
    assert "Prosecutor:" not in verdict.sanitizer_analysis_json  # No private monologue stored!
    assert "bypass_reasoning" in verdict.sanitizer_analysis_json
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_debate.py -v`
Expected: FAIL with "No module named 'src.agents.debate'"

- [ ] **Step 3: Implement `AdversarialDebateEngine` in `src/agents/debate.py`**

Orchestrate ephemeral prosecutor and defender prompts. Synthesize only structured public evidence (`source_control_evidence`, `transform_sanitizer_evidence`, `sink_requirements`, `bypass_reasoning`) and the final verdict into `TaintVerdict`. Discard raw turn transcripts.

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_debate.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/agents/debate.py tests/test_debate.py
git commit -m "feat(agents): implement AdversarialDebateEngine persisting structured evidence without private CoT"
```

---

### Task 13: Incremental Git-Diff Scanner with Working-Tree & Version Gating

**Files:**
- Create: `src/diff/__init__.py`
- Create: `src/diff/git_scanner.py`
- Test: `tests/test_git_scanner.py`

**Interfaces:**
- Consumes: Target git repository, `base_ref: str`, `current_config: dict`, and `db: DatabaseManager`
- Produces: `GitDiffEngine.compute_impact(base_ref: str, current_config: dict) -> DiffImpactPlan` comparing working-tree/index/untracked files against `base_ref`, validating `engine_fingerprint`, updating persistent graph records, and determining reusable findings.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_git_scanner.py
import subprocess
from pathlib import Path
from src.diff.git_scanner import GitDiffEngine
from src.storage.db import DatabaseManager

def test_git_diff_handles_working_tree_and_version_gating(tmp_path: Path):
    # Initialize a git repo and commit two files
    subprocess.run(["git", "init"], cwd=tmp_path, check=True)
    subprocess.run(["git", "config", "user.name", "Tester"], cwd=tmp_path, check=True)
    subprocess.run(["git", "config", "user.email", "test@test.com"], cwd=tmp_path, check=True)
    
    f1 = tmp_path / "f1.py"
    f2 = tmp_path / "f2.py"
    f1.write_text("def a(): pass")
    f2.write_text("def b(): pass")
    subprocess.run(["git", "add", "."], cwd=tmp_path, check=True)
    subprocess.run(["git", "commit", "-m", "init"], cwd=tmp_path, check=True)
    
    db = DatabaseManager(tmp_path / ".audit" / "audit.db")
    db.init_schema()
    db.upsert_file("f1.py", "python", is_vendor=False, file_hash="h1", loc=1)
    db.upsert_file("f2.py", "python", is_vendor=False, file_hash="h2", loc=1)
    
    # 1. Modify f1.py in working tree (uncommitted) + add untracked f3.py
    f1.write_text("def a(): return 1")
    f3 = tmp_path / "f3.py"
    f3.write_text("def c(): pass")
    
    diff_engine = GitDiffEngine(tmp_path, db)
    config = {"ruleset": "v1", "model": "gemini-3.8-flash"}
    plan = diff_engine.compute_impact(base_ref="HEAD", current_config=config)
    
    changed_names = [p.name for p in plan.changed_files]
    assert "f1.py" in changed_names
    assert "f3.py" in changed_names
    assert "f2.py" not in changed_names
    
    # 2. Version Gating Test: If config changes, cache is invalidated
    changed_config = {"ruleset": "v2", "model": "gemini-3.8-flash"}
    plan_invalidated = diff_engine.compute_impact(base_ref="HEAD", current_config=changed_config)
    assert len(plan_invalidated.reusable_dossier_ids) == 0  # Cache invalidated due to rule change!
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_git_scanner.py -v`
Expected: FAIL with "No module named 'src.diff'"

- [ ] **Step 3: Implement `GitDiffEngine` in `src/diff/git_scanner.py`**

Execute `git diff --name-only <base_ref>` plus `git ls-files --others --exclude-standard` to capture modified, staged, and untracked files. Compute SHA256 `engine_fingerprint`. Invalidate reusable findings if fingerprint differs from the previous scan.

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_git_scanner.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/diff/ tests/test_git_scanner.py
git commit -m "feat(diff): implement incremental git diff engine with working tree support and version gating"
```

---

### Task 14: Dossier Synthesizer, Multi-Format Exporter (Markdown + SARIF 2.1.0 + Graph JSON), and CLI

**Files:**
- Create: `src/reporting/__init__.py`
- Create: `src/reporting/synthesizer.py`
- Create: `src/reporting/sarif.py`
- Create: `src/reporting/markdown.py`
- Create: `src/reporting/graph_json.py`
- Create: `src/cli.py`
- Test: `tests/test_reporting.py`

**Interfaces:**
- Consumes: Verified dossiers and persistent graph from `.audit/audit.db`
- Produces: CLI commands (`review scan <dir>`, `review report --format <md|sarif|graph>`, `review resume`), generating Markdown reports, SARIF 2.1.0, and Graph JSON.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_reporting.py
import json
from pathlib import Path
from src.reporting.sarif import SARIFExporter
from src.reporting.graph_json import GraphJSONExporter
from src.storage.db import DatabaseManager, VerdictStatus

def test_exporters_generate_sarif_and_graph_json(tmp_path: Path):
    db = DatabaseManager(tmp_path / "test.db")
    db.init_schema()
    f_id = db.upsert_file("app.py", "python", False, "h1", 50)
    s_id = db.insert_symbol(f_id, "run", "FUNCTION", 1, 0, 5, 0, "run()", "global")
    
    dossiers = [{
        "dossier_id": "D1",
        "title": "Command Injection in UploadHandler",
        "vuln_class": "RCE",
        "severity": "CRITICAL",
        "cwe_id": "CWE-78",
        "verdict": VerdictStatus.EXPLOITABLE.value,
        "confidence": 0.95,
        "source_trace_json": json.dumps([{"file": "app.py", "line": 42}]),
        "sanitizer_analysis_json": json.dumps({"bypass_reasoning": "Unquoted exec"}),
        "repro_curl_template": "curl http://localhost:3000/upload"
    }]
    
    sarif_exporter = SARIFExporter()
    sarif_json = sarif_exporter.export(dossiers)
    assert sarif_json["version"] == "2.1.0"
    
    graph_exporter = GraphJSONExporter()
    graph_json = graph_exporter.export(db)
    assert "nodes" in graph_json
    assert len(graph_json["nodes"]) == 1
    assert graph_json["nodes"][0]["name"] == "run"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_reporting.py -v`
Expected: FAIL with "No module named 'src.reporting'"

- [ ] **Step 3: Implement `DossierSynthesizer`, `SARIFExporter`, `MarkdownExporter`, `GraphJSONExporter`, and Click CLI in `src/cli.py`**

Format findings into OASIS SARIF v2.1.0 with code flows. Export Code Property Graph nodes, edges, endpoints, and sinks to structured JSON. Generate research Markdown report with threat surface summary, call traces, and curl templates. Provide Click CLI interface supporting `scan`, `diff`, `report`, and `resume` commands.

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_reporting.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/reporting/ src/cli.py tests/test_reporting.py
git commit -m "feat(reporting): implement multi-format reporting suite with SARIF 2.1.0, Graph JSON, and CLI"
```

---

## Self-Review Checklist

1. **Working-Tree Diff:** Task 13 captures working-tree, staged, and untracked files against `base_ref`.
2. **Version Gating:** Task 13 explicitly tests that changes to rules/models/config invalidate reusable cache via `engine_fingerprint`.
3. **Linker Edge Persistence:** Task 10 tests both the returned `InferredEdge` and that the edge is inserted into SQLite `graph_edges`.
4. **No Private CoT Persistence:** Task 12 enforces that raw debate monologues are discarded, storing only structured evidence in `scan_dossiers`.
5. **Thread-Safe Event Logger:** Task 3 tests 100 concurrent multi-threaded writes without record corruption.
6. **Complete Output Suite:** Task 14 explicitly includes and tests `GraphJSONExporter` alongside SARIF and Markdown.
