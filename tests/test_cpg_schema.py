"""Tests for Persistent CPG Schema Evolution and Edge Evidence Lifecycle."""

from pathlib import Path

from src.storage.db import DatabaseManager, VerdictStatus


def test_schema_supports_multi_evidence_and_lifecycle(tmp_path: Path):
    """Happy path: Logical edge supports multiple independent evidence records and invalidation."""
    db = DatabaseManager(tmp_path / "cpg.db")
    db.init_schema()

    f1 = db.upsert_file(
        "app.py",
        "python",
        False,
        "h1",
        100,
        execution_domain="APPLICATION_RUNTIME",
        runtime_role="ROUTE_HANDLER",
        environment="PRODUCTION",
        artifact_type="PYTHON",
        classification_confidence=0.95,
        classification_evidence="Flask route file",
    )
    s1 = db.insert_symbol(f1, "main", "FUNCTION", 1, 0, 5, 0)
    s2 = db.insert_symbol(f1, "helper", "FUNCTION", 6, 0, 10, 0)

    # Insert logical edge
    edge_id = db.insert_graph_edge(s1, s2, "CALL")

    # Insert multiple independent evidence records for the same logical edge
    db.insert_edge_evidence(
        edge_id=edge_id,
        resolution_method="FRAMEWORK_RESOLVER",
        confidence=0.98,
        evidence={"route": "/api"},
        commit_sha="abc1",
    )
    db.insert_edge_evidence(
        edge_id=edge_id,
        resolution_method="LINKER_AGENT",
        confidence=0.75,
        evidence={"reason": "DI binding"},
        commit_sha="abc1",
    )

    evidence = db.get_active_edge_evidence(edge_id)
    assert len(evidence) == 2

    # Invalidate evidence on symbol mutation / file change
    db.invalidate_file_symbols(f1)
    active_evidence = db.get_active_edge_evidence(edge_id)
    assert len(active_evidence) == 0


def test_candidate_sink_triage_severity_and_fingerprint(tmp_path: Path):
    """Happy path: candidate_sinks has triage_severity and scan_dossiers stores fingerprint."""
    db = DatabaseManager(tmp_path / "cpg.db")
    db.init_schema()

    f1 = db.upsert_file("routes/user.py", "python", False, "h1", 50)
    sink_id = db.insert_candidate_sink(
        file_id=f1,
        vuln_class="SQLI",
        triage_severity="CRITICAL",
        line_number=25,
        sink_expression="cursor.execute(query)",
        raw_rule_id="rules.sqli",
        tool_provenance="Semgrep",
    )
    assert sink_id > 0

    scan_id = db.create_scan(str(tmp_path), "FULL", "fp_1")
    path_id = "path_user_1"
    db.record_candidate_path(
        path_id=path_id,
        scan_id=scan_id,
        sink_id=sink_id,
        hop_count=1,
        call_sequence=[sink_id],
        priority_score=0.9,
    )

    fingerprint = db.compute_finding_fingerprint(
        schema_version=1,
        vuln_class="SQLI",
        norm_endpoint="GET /user",
        norm_source="req.query.id",
        norm_sink="SQL.cursor.execute",
        norm_path="routes/user.py:25",
    )
    assert len(fingerprint) == 64

    dossier_id = "dos_fingerprint_test"
    db.record_dossier(
        dossier_id=dossier_id,
        scan_id=scan_id,
        path_id=path_id,
        engine_fingerprint="fp_1",
        title="SQL Injection in User Route",
        vuln_class="SQLI",
        severity="CRITICAL",
        cwe_id="CWE-89",
        verdict=VerdictStatus.EXPLOITABLE.value,
        reachability_confidence=0.95,
        exploitability_confidence=0.90,
        source_trace=[],
        evidence_bundle={"source": "untrusted"},
        finding_fingerprint=fingerprint,
        fingerprint_schema_version=1,
    )

    dossiers = db.get_scan_dossiers(scan_id)
    assert len(dossiers) == 1
    assert dossiers[0]["finding_fingerprint"] == fingerprint
    assert dossiers[0]["fingerprint_schema_version"] == 1
    assert dossiers[0]["reachability_confidence"] == 0.95
    assert dossiers[0]["exploitability_confidence"] == 0.90
