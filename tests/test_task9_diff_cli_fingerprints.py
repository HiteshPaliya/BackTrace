"""Regression tests for Task 9: Fingerprints, Engine Gating, Diff, Resume, and CLI."""

import json
import subprocess
from pathlib import Path

from click.testing import CliRunner

from src.cli import cli
from src.diff.git_scanner import GitDiffEngine
from src.storage.db import DatabaseManager

# =============================================================================
# 1. Finding Fingerprint Tests
# =============================================================================

def test_finding_fingerprint_deterministic_and_line_churn_immune():
    """Invariant C & D: Stable finding fingerprints across runs and line-number movement."""
    fp1 = DatabaseManager.compute_finding_fingerprint(
        schema_version=1,
        vuln_class="SQLI",
        norm_endpoint="POST /api/login",
        norm_source="PARAM.email",
        norm_sink="SQL.models.sequelize.query",
        norm_path="routes/login.ts:34",
    )

    # Move line from 34 to 45 (line-number churn) -> fingerprint must remain IDENTICAL
    fp2 = DatabaseManager.compute_finding_fingerprint(
        schema_version=1,
        vuln_class="SQLI",
        norm_endpoint="POST /api/login",
        norm_source="PARAM.email",
        norm_sink="SQL.models.sequelize.query",
        norm_path="routes/login.ts:45",
    )
    assert fp1 == fp2

    # Changed vuln class -> changed fingerprint
    fp_vuln = DatabaseManager.compute_finding_fingerprint(
        schema_version=1,
        vuln_class="RCE",
        norm_endpoint="POST /api/login",
        norm_source="PARAM.email",
        norm_sink="SQL.models.sequelize.query",
        norm_path="routes/login.ts:34",
    )
    assert fp1 != fp_vuln

    # Changed endpoint -> changed fingerprint
    fp_ep = DatabaseManager.compute_finding_fingerprint(
        schema_version=1,
        vuln_class="SQLI",
        norm_endpoint="POST /api/admin/login",
        norm_source="PARAM.email",
        norm_sink="SQL.models.sequelize.query",
        norm_path="routes/login.ts:34",
    )
    assert fp1 != fp_ep

    # Changed source -> changed fingerprint
    fp_src = DatabaseManager.compute_finding_fingerprint(
        schema_version=1,
        vuln_class="SQLI",
        norm_endpoint="POST /api/login",
        norm_source="PARAM.password",
        norm_sink="SQL.models.sequelize.query",
        norm_path="routes/login.ts:34",
    )
    assert fp1 != fp_src

    # Changed sink -> changed fingerprint
    fp_sink = DatabaseManager.compute_finding_fingerprint(
        schema_version=1,
        vuln_class="SQLI",
        norm_endpoint="POST /api/login",
        norm_source="PARAM.email",
        norm_sink="SQL.db.raw",
        norm_path="routes/login.ts:34",
    )
    assert fp1 != fp_sink

    # Changed schema version -> changed fingerprint
    fp_ver = DatabaseManager.compute_finding_fingerprint(
        schema_version=2,
        vuln_class="SQLI",
        norm_endpoint="POST /api/login",
        norm_source="PARAM.email",
        norm_sink="SQL.models.sequelize.query",
        norm_path="routes/login.ts:34",
    )
    assert fp1 != fp_ver


# =============================================================================
# 2. Strengthened Engine Fingerprint Tests
# =============================================================================

def test_engine_fingerprint_lockfile_and_config_sensitivity(tmp_path: Path):
    """Invariant B: Changing ruleset, model, config, or lockfile alters engine fingerprint."""
    db = DatabaseManager(tmp_path / "test.db")
    db.init_schema()

    diff_engine = GitDiffEngine(tmp_path, db)

    config_base = {"model": "gemini-3.8-flash", "ruleset": "owasp-top-10"}
    fp_base = diff_engine.compute_engine_fingerprint(config_base)

    # Identical config -> identical fingerprint
    assert diff_engine.compute_engine_fingerprint(config_base) == fp_base

    # Model change -> changed fingerprint
    fp_model = diff_engine.compute_engine_fingerprint(
        {"model": "ollama/deepseek-coder", "ruleset": "owasp-top-10"}
    )
    assert fp_base != fp_model

    # Ruleset change -> changed fingerprint
    fp_rules = diff_engine.compute_engine_fingerprint(
        {"model": "gemini-3.8-flash", "ruleset": "cwe-top-25"}
    )
    assert fp_base != fp_rules

    # Lockfile change -> changed fingerprint
    lockfile = tmp_path / "package-lock.json"
    lockfile.write_text(
        '{"lockfileVersion": 2, "dependencies": {"express": "4.18.2"}}', encoding="utf-8"
    )
    fp_lock1 = diff_engine.compute_engine_fingerprint(config_base)
    assert fp_base != fp_lock1

    # Mutate lockfile dependency -> changed fingerprint
    lockfile.write_text(
        '{"lockfileVersion": 2, "dependencies": {"express": "4.19.0"}}', encoding="utf-8"
    )
    fp_lock2 = diff_engine.compute_engine_fingerprint(config_base)
    assert fp_lock1 != fp_lock2


# =============================================================================
# 3. Incremental Diff & Dependency Invalidation Tests
# =============================================================================

def test_incremental_diff_mutation_and_deleted_file_invalidation(tmp_path: Path):
    """Invariant A, E & Spec 7.4: Tracks modified, added, deleted files and invalidates."""
    subprocess.run(["git", "init"], cwd=tmp_path, capture_output=True, check=True)
    subprocess.run(
        ["git", "config", "user.name", "Tester"], cwd=tmp_path, capture_output=True, check=True
    )
    subprocess.run(
        ["git", "config", "user.email", "test@example.com"],
        cwd=tmp_path,
        capture_output=True,
        check=True,
    )

    f1 = tmp_path / "f1.py"
    f2 = tmp_path / "f2.py"
    f1.write_text("def a(): pass\n", encoding="utf-8")
    f2.write_text("def b(): pass\n", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=tmp_path, capture_output=True, check=True)
    subprocess.run(["git", "commit", "-m", "init"], cwd=tmp_path, capture_output=True, check=True)

    db = DatabaseManager(tmp_path / ".audit" / "audit.db")
    db.init_schema()
    f1_id = db.upsert_file("f1.py", "python", False, "h1", 1)
    f2_id = db.upsert_file("f2.py", "python", False, "h2", 1)

    s1 = db.insert_symbol(f1_id, "func_a", "FUNCTION", 1, 0, 1, 10)
    s2 = db.insert_symbol(f2_id, "func_b", "FUNCTION", 1, 0, 1, 10)
    edge_id = db.insert_graph_edge(s1, s2, "CALL", provenance="DETERMINISTIC", confidence=1.0)
    assert len(db.get_active_edge_evidence(edge_id)) == 1

    diff_engine = GitDiffEngine(tmp_path, db)

    # 1. Modify f1.py (unstaged) + delete f2.py + add untracked f3.py
    f1.write_text("def a(): return 'modified'\n", encoding="utf-8")
    f2.unlink()
    f3 = tmp_path / "f3.py"
    f3.write_text("def c(): pass\n", encoding="utf-8")

    plan = diff_engine.compute_impact(base_ref="HEAD")
    changed_names = [p.name for p in plan.changed_files]
    deleted_names = [p.name for p in plan.deleted_files]

    assert "f1.py" in changed_names
    assert "f3.py" in changed_names
    assert "f2.py" in deleted_names

    # Invariant A: Modified f1 invalidated its edge evidence
    assert len(db.get_active_edge_evidence(edge_id)) == 0

    # Invariant A: Deleted f2 purged from files and CASCADE removed its symbol
    with db._get_connection() as conn:
        f2_row = conn.execute("SELECT * FROM files WHERE rel_path = 'f2.py';").fetchone()
        assert f2_row is None
        s2_row = conn.execute("SELECT * FROM symbols WHERE symbol_id = ?;", (s2,)).fetchone()
        assert s2_row is None


# =============================================================================
# 4. Resume & CLI Orchestration Tests
# =============================================================================

def test_resume_command_evaluates_unresolved_without_duplication(tmp_path: Path):
    """Invariant G: Resuming scan completes pending paths without duplicating evidence."""
    app_file = tmp_path / "app.js"
    app_file.write_text(
        """
        const express = require('express');
        const needle = require('needle');
        const app = express();
        app.get('/fetch', (req, res) => {
            needle.get(req.query.url);
        });
        """,
        encoding="utf-8",
    )

    runner = CliRunner()
    # Initial scan
    res_scan = runner.invoke(cli, ["scan", str(tmp_path)])
    assert res_scan.exit_code == 0

    db = DatabaseManager(tmp_path / ".audit" / "audit.db")
    with db._get_connection() as conn:
        scan_id = conn.execute("SELECT scan_id FROM scans LIMIT 1;").fetchone()["scan_id"]
        count_query = "SELECT count(*) as cnt FROM scan_dossiers;"
        dossier_count_before = conn.execute(count_query).fetchone()["cnt"]

    # Resume the completed scan -> should be idempotent, no duplicates
    res_resume = runner.invoke(cli, ["resume", scan_id, "--target", str(tmp_path)])
    assert res_resume.exit_code == 0
    assert "already complete" in res_resume.output or "completed successfully" in res_resume.output

    with db._get_connection() as conn:
        dossier_count_after = conn.execute(count_query).fetchone()["cnt"]
    assert dossier_count_before == dossier_count_after


def test_cli_report_diff_integration(tmp_path: Path):
    """Test diff and report subcommands operate cleanly on valid repository."""
    app_file = tmp_path / "server.js"
    app_file.write_text("console.log('hello');", encoding="utf-8")

    runner = CliRunner()
    res_scan = runner.invoke(cli, ["scan", str(tmp_path)])
    assert res_scan.exit_code == 0

    db = DatabaseManager(tmp_path / ".audit" / "audit.db")
    with db._get_connection() as conn:
        scan_id = conn.execute("SELECT scan_id FROM scans LIMIT 1;").fetchone()["scan_id"]

    # Test report command with markdown, sarif, graph
    res_report_md = runner.invoke(
        cli, ["report", "--scan-id", scan_id, "--target", str(tmp_path), "--format", "md"]
    )
    assert res_report_md.exit_code == 0
    assert "Security Review Research Dossier" in res_report_md.output

    res_report_sarif = runner.invoke(
        cli, ["report", "--scan-id", scan_id, "--target", str(tmp_path), "--format", "sarif"]
    )
    assert res_report_sarif.exit_code == 0
    sarif_data = json.loads(res_report_sarif.output)
    assert sarif_data["version"] == "2.1.0"

    res_diff = runner.invoke(cli, ["diff", str(tmp_path)])
    assert res_diff.exit_code == 0
    assert "Changed files:" in res_diff.output


def test_deleted_file_end_to_end_invalidation_and_unrelated_retention(tmp_path: Path):
    """Spec 7.4: Deleting a file via diff purges symbols and edge evidence."""
    subprocess.run(["git", "init"], cwd=tmp_path, capture_output=True, check=True)
    subprocess.run(
        ["git", "config", "user.name", "Tester"], cwd=tmp_path, capture_output=True, check=True
    )
    subprocess.run(
        ["git", "config", "user.email", "test@example.com"],
        cwd=tmp_path,
        capture_output=True,
        check=True,
    )

    fv = tmp_path / "vuln.py"
    fu = tmp_path / "unrelated.py"
    fv.write_text("def vuln(): pass\n", encoding="utf-8")
    fu.write_text("def unrelated(): pass\n", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=tmp_path, capture_output=True, check=True)
    subprocess.run(["git", "commit", "-m", "init"], cwd=tmp_path, capture_output=True, check=True)

    db = DatabaseManager(tmp_path / ".audit" / "audit.db")
    db.init_schema()

    fv_id = db.upsert_file("vuln.py", "python", False, "h_vuln", 1)
    fu_id = db.upsert_file("unrelated.py", "python", False, "h_unrelated", 1)

    s_v = db.insert_symbol(fv_id, "vuln", "FUNCTION", 1, 0, 1, 10)
    s_u = db.insert_symbol(fu_id, "unrelated", "FUNCTION", 1, 0, 1, 10)
    edge_id = db.insert_graph_edge(s_v, s_u, "CALL", provenance="DETERMINISTIC", confidence=1.0)

    diff_engine = GitDiffEngine(tmp_path, db)
    fp = diff_engine.compute_engine_fingerprint({"config": "v1"})
    scan_id = db.create_scan(str(tmp_path), "FULL", fp)

    sink_v = db.insert_candidate_sink(fv_id, "RCE", "CRITICAL", 1, "os.system()", "r1", "Semgrep")
    sink_u = db.insert_candidate_sink(fu_id, "SQLI", "HIGH", 1, "db.query()", "r2", "Semgrep")

    db.record_candidate_path("p_v", scan_id, sink_v, 1, [s_v], 0.9)
    db.record_candidate_path("p_u", scan_id, sink_u, 1, [s_u], 0.8)

    db.record_dossier(
        "dos_v", scan_id, "p_v", fp, "Vuln in vuln", "RCE", "CRITICAL", "CWE-78", "EXPLOITABLE"
    )
    db.record_dossier(
        "dos_u", scan_id, "p_u", fp, "Vuln in unrel", "SQLI", "HIGH", "CWE-89", "EXPLOITABLE"
    )

    # Delete vuln.py on filesystem (simulating developer deletion)
    fv.unlink()

    # 1. Run compute_impact through the real GitDiffEngine path
    plan = diff_engine.compute_impact(base_ref="HEAD", current_config={"config": "v1"})

    # 2. Verify deleted_files captures vuln.py
    assert any(p.name == "vuln.py" for p in plan.deleted_files)

    # 3. Verify symbols, sinks, files are deleted via CASCADE
    with db._get_connection() as conn:
        assert conn.execute("SELECT * FROM files WHERE rel_path = 'vuln.py';").fetchone() is None
        assert conn.execute("SELECT * FROM symbols WHERE symbol_id = ?;", (s_v,)).fetchone() is None
        sink_check = "SELECT * FROM candidate_sinks WHERE sink_id = ?;"
        assert conn.execute(sink_check, (sink_v,)).fetchone() is None

    # 4. Verify dependent edge evidence cannot remain active
    assert len(db.get_active_edge_evidence(edge_id)) == 0

    # 5. Verify deleted dossier is excluded and unrelated dossier is retained
    assert "dos_v" not in plan.reusable_dossier_ids
    assert "dos_u" in plan.reusable_dossier_ids

    # 6. Verify subsequent run does not resurrect stale evidence
    plan_next = diff_engine.compute_impact(base_ref="HEAD", current_config={"config": "v1"})
    assert "dos_v" not in plan_next.reusable_dossier_ids
    assert "dos_u" in plan_next.reusable_dossier_ids
    assert len(db.get_active_edge_evidence(edge_id)) == 0
