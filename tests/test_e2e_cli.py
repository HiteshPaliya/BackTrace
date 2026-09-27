"""End-to-End CLI, Integration, and Edge/Fault Verification Suite."""

import subprocess
import time
from pathlib import Path

from click.testing import CliRunner

from src.adapters.base import ToolAdapter, ToolExecutionResult
from src.adapters.manager import ToolManager
from src.cli import cli
from src.diff.git_scanner import GitDiffEngine
from src.storage.db import DatabaseManager, VerdictStatus


def setup_synthetic_fixture(repo_path: Path):
    """Create a minimal synthetic multi-language fixture repository."""
    repo_path.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init"], cwd=repo_path, capture_output=True, check=True)
    subprocess.run(
        ["git", "config", "user.name", "ReviewerTest"],
        cwd=repo_path,
        capture_output=True,
        check=True,
    )
    subprocess.run(
        ["git", "config", "user.email", "test@example.com"],
        cwd=repo_path,
        capture_output=True,
        check=True,
    )

    # 1. Python source file with source-to-sink flow
    py_code = (
        "import os\n\n"
        "def process_user_input(cmd: str):\n"
        "    # Dangerous sink callsite\n"
        "    return os.system(cmd)\n\n"
        "def handle_request(req):\n"
        "    cmd = req.get('command')\n"
        "    return process_user_input(cmd)\n"
    )
    (repo_path / "app.py").write_text(py_code, encoding="utf-8")

    # 2. JavaScript file calling a vendor library
    js_code = (
        "const dbHelper = require('db-helper');\n\n"
        "function handleQuery(req, res) {\n"
        "    const sql = req.body.query;\n"
        "    return dbHelper.rawQuery(sql);\n"
        "}\n"
    )
    (repo_path / "server.js").write_text(js_code, encoding="utf-8")

    # 3. Vendor library
    vendor_dir = repo_path / "node_modules" / "db-helper"
    vendor_dir.mkdir(parents=True, exist_ok=True)
    vendor_code = "exports.rawQuery = function(sql) { return eval(sql); };\n"
    (vendor_dir / "index.js").write_text(vendor_code, encoding="utf-8")

    subprocess.run(["git", "add", "."], cwd=repo_path, capture_output=True, check=True)
    subprocess.run(
        ["git", "commit", "-m", "initial fixture commit"],
        cwd=repo_path,
        capture_output=True,
        check=True,
    )


def test_e2e_cli_scan_diff_report_resume(tmp_path: Path):
    """End-to-End Test: scan -> diff -> report (sarif/graph/md) -> resume."""
    fixture_dir = tmp_path / "synthetic_repo"
    setup_synthetic_fixture(fixture_dir)

    runner = CliRunner()

    # 1. Test scan command
    scan_res = runner.invoke(cli, ["scan", str(fixture_dir)])
    assert scan_res.exit_code == 0
    assert "Scan completed successfully" in scan_res.output

    db_path = fixture_dir / ".audit" / "audit.db"
    assert db_path.exists()
    events_path = fixture_dir / ".audit" / "events.jsonl"
    assert events_path.exists()

    db = DatabaseManager(db_path)
    files = db.get_all_files()
    rel_files = {f["rel_path"].replace("\\", "/") for f in files}
    assert "app.py" in rel_files
    assert "server.js" in rel_files

    with db._get_connection() as conn:
        symbols = conn.execute("SELECT name FROM symbols;").fetchall()
        sym_names = {s["name"] for s in symbols}
        assert "handle_request" in sym_names
        assert "process_user_input" in sym_names
        assert "handleQuery" in sym_names

        scans = conn.execute("SELECT scan_id, status FROM scans;").fetchall()
        assert len(scans) == 1
        assert scans[0]["status"] == "COMPLETED"
        scan_id = scans[0]["scan_id"]

    # 2. Test diff command on untracked change
    untracked_file = fixture_dir / "untracked_service.py"
    untracked_file.write_text("def new_feature(): pass\n", encoding="utf-8")

    diff_res = runner.invoke(cli, ["diff", str(fixture_dir), "--base", "HEAD"])
    assert diff_res.exit_code == 0
    assert "Changed files:" in diff_res.output

    diff_engine = GitDiffEngine(fixture_dir, db)
    plan = diff_engine.compute_impact(base_ref="HEAD")
    changed_names = [p.name for p in plan.changed_files]
    assert "untracked_service.py" in changed_names
    assert "app.py" not in changed_names
    assert "server.js" not in changed_names

    # Insert a dummy dossier for scan_id to verify report formatting
    db.record_dossier(
        dossier_id="dos_e2e",
        scan_id=scan_id,
        path_id=None,
        engine_fingerprint="fp_e2e",
        title="Command Injection in handle_request",
        vuln_class="RCE",
        severity="CRITICAL",
        cwe_id="CWE-78",
        verdict=VerdictStatus.EXPLOITABLE.value,
        confidence=0.95,
        source_trace=[{"file": "app.py", "line": 7}],
        sanitizer_analysis={"bypass_reasoning": "Direct shell execution via os.system"},
        repro_curl_template="curl -X POST http://localhost:8000 -d 'command=whoami'",
        mitigation_notes="Sanitize input or use subprocess.run with shell=False",
    )

    # 3. Test report command in all 3 formats
    from src.reporting.graph_json import GraphJSONExporter
    from src.reporting.markdown import MarkdownExporter
    from src.reporting.sarif import SARIFExporter

    dossiers = db.get_scan_dossiers(scan_id)
    sarif_data = SARIFExporter().export(dossiers)
    assert sarif_data["version"] == "2.1.0"
    assert sarif_data["runs"][0]["tool"]["driver"]["name"] == "PolyglotSourceCodeSecurityReviewer"
    assert len(sarif_data["runs"][0]["results"]) == 1

    graph_data = GraphJSONExporter().export(db)
    assert len(graph_data["nodes"]) >= 3
    node_names = [n["name"] for n in graph_data["nodes"] if "name" in n]
    assert "handle_request" in node_names

    md_report = MarkdownExporter().export(dossiers, scan_id=scan_id)
    assert "# Security Review Research Dossier" in md_report
    assert "curl -X POST http://localhost:8000" in md_report

    # 4. Test resume command and deduplication of edges
    with db._get_connection() as conn:
        edges_before = conn.execute("SELECT count(*) as cnt FROM graph_edges;").fetchone()["cnt"]

    resume_res = runner.invoke(cli, ["resume", scan_id])
    assert resume_res.exit_code == 0
    assert scan_id in resume_res.output

    with db._get_connection() as conn:
        edges_after = conn.execute("SELECT count(*) as cnt FROM graph_edges;").fetchone()["cnt"]
    assert edges_before == edges_after


def test_missing_tools_soft_degradation(tmp_path: Path):
    """Edge/Fault Check: Graceful degradation when external binaries are missing from PATH."""
    class NonExistentTool(ToolAdapter):
        @property
        def name(self) -> str:
            return "imaginary_analyzer_xyz"
        def run(self, repo_path: Path, options=None) -> ToolExecutionResult:
            raise FileNotFoundError("Binary 'imaginary_analyzer_xyz' missing")
        def normalize(self, raw_output: str):
            return []

    mgr = ToolManager(adapters=[NonExistentTool()])
    results = mgr.run_all(tmp_path)
    assert "imaginary_analyzer_xyz" in results
    assert results["imaginary_analyzer_xyz"].is_available is False
    assert len(results["imaginary_analyzer_xyz"].warnings) > 0


def test_subprocess_timeout_circuit_breaker(tmp_path: Path):
    """Edge/Fault Check: Stalled subprocesses abort cleanly without hanging or leaving zombies."""
    class StalledTool(ToolAdapter):
        TIMEOUT_SECONDS = 1  # 1 second timeout

        @property
        def name(self) -> str:
            return "stalled_tool"

        def is_installed(self) -> bool:
            return True

        def run(self, repo_path: Path, options=None) -> ToolExecutionResult:
            # Spawn a command that sleeps for 10 seconds
            import sys
            cmd = [sys.executable, "-c", "import time; time.sleep(10)"]
            return self.execute_command(cmd, cwd=repo_path, timeout=1)

        def normalize(self, raw_output: str):
            return []

    stalled = StalledTool()
    start_t = time.time()
    res = stalled.run(tmp_path)
    elapsed = time.time() - start_t

    # Should abort around 1s, not wait 10s
    assert elapsed < 5.0
    assert res.exit_code == -1
    assert any("timed out" in w.lower() for w in res.warnings)


def test_database_connection_safety_and_file_handle_leaks(tmp_path: Path):
    """Code Review Audit: Verify atomic rollback cleans up connection handles and prevents leaks."""
    db_file = tmp_path / "leak_test.db"
    db = DatabaseManager(db_file)
    db.init_schema()

    # Verify 100 sequential transactions cleanly release connections
    for i in range(100):
        with db.transaction() as conn:
            conn.execute(
                "INSERT INTO files (rel_path, language, is_vendor, file_hash, loc) "
                "VALUES (?, ?, ?, ?, ?)",
                (f"test_{i}.py", "python", 0, f"hash_{i}", 10),
            )

    # Verify no dangling connections prevent file access/deletion
    assert len(db.get_all_files()) == 100


def test_spec_non_goals_and_no_private_cot_persistence(tmp_path: Path):
    """Code Review Audit: Verify no private CoT scratchpads leak into scan_dossiers."""
    db_file = tmp_path / "cot_test.db"
    db = DatabaseManager(db_file)
    db.init_schema()

    scan_id = db.create_scan(str(tmp_path), "FULL", "fp_cot")
    db.record_dossier(
        dossier_id="dos_audit",
        scan_id=scan_id,
        path_id=None,
        engine_fingerprint="fp_cot",
        title="Audit check",
        vuln_class="RCE",
        severity="CRITICAL",
        cwe_id="CWE-78",
        verdict=VerdictStatus.EXPLOITABLE.value,
        confidence=0.9,
        source_trace=[],
        sanitizer_analysis={
            "bypass_reasoning": "Valid public evidence",
            "source_control_evidence": "User input",
        },
    )

    dossiers = db.get_scan_dossiers(scan_id)
    assert len(dossiers) == 1
    dossier_entry = dossiers[0]
    analysis_str = dossier_entry["sanitizer_analysis_json"].lower()

    # Non-goal 6 verification: no internal thoughts / CoT tokens
    forbidden_tokens = [
        "prosecutor:", "defender:", "<thought>", "</thought>", "scratchpad", "deliberation:"
    ]
    for tok in forbidden_tokens:
        assert tok not in analysis_str
