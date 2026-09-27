"""Tests for Incremental Git-Diff Scanner with Working-Tree and Version Gating."""

import subprocess
from pathlib import Path

from src.diff.git_scanner import GitDiffEngine
from src.storage.db import DatabaseManager


def test_git_diff_handles_working_tree_and_version_gating(tmp_path: Path):
    """Happy path: Captures working-tree changes and gates version on config changes."""
    subprocess.run(["git", "init"], cwd=tmp_path, check=True)
    subprocess.run(["git", "config", "user.name", "Tester"], cwd=tmp_path, check=True)
    subprocess.run(["git", "config", "user.email", "test@test.com"], cwd=tmp_path, check=True)

    f1 = tmp_path / "f1.py"
    f2 = tmp_path / "f2.py"
    f1.write_text("def a(): pass", encoding="utf-8")
    f2.write_text("def b(): pass", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=tmp_path, check=True)
    subprocess.run(["git", "commit", "-m", "init"], cwd=tmp_path, check=True)

    db = DatabaseManager(tmp_path / ".audit" / "audit.db")
    db.init_schema()
    db.upsert_file("f1.py", "python", is_vendor=False, file_hash="h1", loc=1)
    f2_id = db.upsert_file("f2.py", "python", is_vendor=False, file_hash="h2", loc=1)

    # Record a previous scan and dossier on f2.py with fingerprint v1
    config = {"ruleset": "v1", "model": "gemini-3.8-flash"}
    diff_engine = GitDiffEngine(tmp_path, db)
    fp_v1 = diff_engine.compute_engine_fingerprint(config)

    scan_1 = db.create_scan(str(tmp_path), "FULL", engine_fingerprint=fp_v1, config=config)
    sink_id = db.insert_candidate_sink(
        f2_id, "SQLI", "HIGH", 1, "db.query()", "rule.sql", "semgrep"
    )
    db.record_candidate_path(
        "path_f2",
        scan_1,
        sink_id=sink_id,
        hop_count=1,
        call_sequence=[1],
        priority_score=0.8,
    )
    db.record_dossier(
        dossier_id="dos_f2",
        scan_id=scan_1,
        path_id="path_f2",
        engine_fingerprint=fp_v1,
        title="SQLi in f2",
        vuln_class="SQLI",
        severity="HIGH",
        cwe_id="CWE-89",
        verdict="EXPLOITABLE",
        confidence=0.9,
        source_trace=[],
        sanitizer_analysis={},
    )

    # 1. Modify f1.py in working tree (uncommitted) + add untracked f3.py
    f1.write_text("def a(): return 1", encoding="utf-8")
    f3 = tmp_path / "f3.py"
    f3.write_text("def c(): pass", encoding="utf-8")

    plan = diff_engine.compute_impact(base_ref="HEAD", current_config=config)
    changed_names = [p.name for p in plan.changed_files]
    assert "f1.py" in changed_names
    assert "f3.py" in changed_names
    assert "f2.py" not in changed_names
    assert "dos_f2" in plan.reusable_dossier_ids  # Matches fingerprint v1

    # 2. Version Gating Test: If config changes, cache is invalidated
    changed_config = {"ruleset": "v2", "model": "gemini-3.8-flash"}
    plan_invalidated = diff_engine.compute_impact(base_ref="HEAD", current_config=changed_config)
    assert len(plan_invalidated.reusable_dossier_ids) == 0  # Cache invalidated due to rule change!


def test_git_diff_non_git_repo_boundary(tmp_path: Path):
    """Boundary test: Target directory without git falls back safely to full scan."""
    db = DatabaseManager(tmp_path / ".audit" / "audit.db")
    db.init_schema()

    (tmp_path / "standalone.py").write_text("pass", encoding="utf-8")
    diff_engine = GitDiffEngine(tmp_path, db)
    plan = diff_engine.compute_impact(base_ref="HEAD", current_config={})
    assert any(p.name == "standalone.py" for p in plan.changed_files)
