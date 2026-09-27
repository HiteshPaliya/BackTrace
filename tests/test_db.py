"""Tests for SQLite Decoupled Repository & Scan State Store."""

from pathlib import Path

import pytest

from src.storage.db import DatabaseManager


def test_database_initialization_and_scan_decoupling(tmp_path: Path):
    """Happy path: Verify schema init, persistent repo CRUD, and decoupled scan lifecycle."""
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
        config={"workers": 4},
    )
    db.update_scan_status(scan_1, "COMPLETED")

    # 3. Start Scan 2 (DIFF) - verify persistent graph still exists
    scan_2 = db.create_scan(
        target_path=str(tmp_path),
        scan_mode="DIFF",
        engine_fingerprint="fp_v1",
        config={"workers": 4},
    )
    assert scan_1 != scan_2

    files = db.get_all_files()
    assert len(files) == 1
    assert files[0]["rel_path"] == "app.py"


def test_transaction_rollback_on_error(tmp_path: Path):
    """Error boundary: Verify rollback inside atomic transaction context."""
    db_file = tmp_path / ".audit" / "audit.db"
    db = DatabaseManager(db_file)
    db.init_schema()

    with pytest.raises(RuntimeError):
        with db.transaction() as conn:
            conn.execute(
                "INSERT INTO files (rel_path, language, is_vendor, file_hash, loc) "
                "VALUES ('fail.py', 'python', 0, 'h1', 10)"
            )
            raise RuntimeError("Forced transaction failure")

    files = db.get_all_files()
    assert len(files) == 0


def test_foreign_key_and_version_gating(tmp_path: Path):
    """Boundary test: Foreign key enforcement and engine_fingerprint cache matching."""
    db_file = tmp_path / ".audit" / "audit.db"
    db = DatabaseManager(db_file)
    db.init_schema()

    # Foreign key enforcement: inserting symbol for non-existent file must fail
    with pytest.raises(Exception):
        db.insert_symbol(9999, "orphan", "FUNCTION", 1, 0, 2, 0)

    # Version gating for dossier reuse
    file_id = db.upsert_file("vuln.py", "python", is_vendor=False, file_hash="hash_v", loc=20)
    sink_id = db.insert_candidate_sink(
        file_id=file_id,
        vuln_class="RCE",
        severity="CRITICAL",
        line_number=10,
        sink_expression="os.system(cmd)",
        raw_rule_id="semgrep.py.rce",
        tool_provenance="Semgrep",
    )
    scan_id = db.create_scan(
        target_path=str(tmp_path),
        scan_mode="FULL",
        engine_fingerprint="fp_match",
        config={},
    )
    path_id = "path_123"
    db.record_candidate_path(
        path_id=path_id,
        scan_id=scan_id,
        endpoint_id=None,
        sink_id=sink_id,
        hop_count=2,
        call_sequence=[1, 2],
        priority_score=0.95,
    )
    db.record_dossier(
        dossier_id="dos_1",
        scan_id=scan_id,
        path_id=path_id,
        engine_fingerprint="fp_match",
        title="Command Injection via os.system",
        vuln_class="RCE",
        severity="CRITICAL",
        cwe_id="CWE-78",
        verdict="EXPLOITABLE",
        confidence=0.9,
        source_trace={"steps": ["entry", "sink"]},
        sanitizer_analysis={"sanitized": False},
        repro_curl_template="curl -X POST ...",
    )

    # Reusable when fingerprint matches
    reusable = db.get_reusable_dossier(path_id="path_123", engine_fingerprint="fp_match")
    assert reusable is not None
    assert reusable["title"] == "Command Injection via os.system"

    # Invalidated / None when fingerprint differs
    invalidated = db.get_reusable_dossier(path_id="path_123", engine_fingerprint="fp_different")
    assert invalidated is None
