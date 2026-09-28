"""Dedicated regression test suite verifying all 8 core architectural invariants."""

from pathlib import Path

from click.testing import CliRunner

from src.agents.verifier import EvidenceBundle, EvidenceGateVerifier
from src.cli import cli
from src.core.scope import ScopeClassifier
from src.core.workspace import FileInfo
from src.graph.cpg import CodePropertyGraph
from src.graph.reachability import ReachabilityAnalyzer
from src.semantic.authz import AuthorizationAnalyzer
from src.semantic.detector import SemanticDetector
from src.storage.db import DatabaseManager, VerdictStatus


def test_invariant_1_semantic_arguments_not_literals():
    """Invariant 1: Sinks inspect argument semantics; static literals and Supertest are rejected."""
    code = """
        const request = require('supertest');
        request(app).get('/api/users');
        fetch("https://fixed.example.com/api");
        fetch('/internal/relative/path');
        fs.readFileSync('./swagger.yml', 'utf8');
        // Valid dynamic sinks
        fetch(userSuppliedUrl);
        fs.readFile(userSuppliedPath, 'utf8');
    """
    detector = SemanticDetector()
    findings = detector.scan_source("app.js", code, "javascript")

    # Static literals and Supertest must be excluded; only dynamic sinks remain
    assert not any("request(app)" in s.expression for s in findings.sinks)
    assert not any("swagger.yml" in s.expression for s in findings.sinks)
    assert not any("fixed.example.com" in s.expression for s in findings.sinks)
    assert any("userSuppliedUrl" in s.expression for s in findings.sinks)
    assert any("userSuppliedPath" in s.expression for s in findings.sinks)


def test_invariant_2_language_context_pug_vs_js():
    """Invariant 2: Template unescape != is evaluated ONLY on templates, never JS !==."""
    js_code = "if (val !== undefined && x != null) { return true; }"
    pug_code = "div!= userComment"

    detector = SemanticDetector()
    js_findings = detector.scan_source("service.ts", js_code, "typescript")
    pug_findings = detector.scan_source("comment.pug", pug_code, "javascript")

    # JS code must have 0 XSS sinks
    assert len(js_findings.sinks) == 0
    # Pug file must have XSS sink
    assert any(s.vuln_class == "XSS" for s in pug_findings.sinks)


def test_invariant_3_scope_gated_eligibility():
    """Invariant 3: Scope classification precedes candidate generation and denies tests."""
    test_file = FileInfo(
        "test/auth.test.ts", "/repo/test/auth.test.ts", "typescript", False, "h1", 100
    )
    vendor_file = FileInfo(
        "assets/three.js", "/repo/assets/three.js", "javascript", False, "h2", 5000
    )
    prod_file = FileInfo(
        "routes/user.ts", "/repo/routes/user.ts", "typescript", False, "h3", 60
    )

    classifier = ScopeClassifier()
    assert classifier.eligible_for_detector(test_file, "SSRF") is False
    assert classifier.eligible_for_detector(vendor_file, "XSS") is False
    assert classifier.eligible_for_detector(prod_file, "SQLI") is True


def test_invariant_4_zero_endpoint_fallback(tmp_path: Path):
    """Invariant 4: Sinks without CPG-proven routes receive NONE reproduction and zero curl."""
    # File containing internal sink with no HTTP route attached
    worker_file = tmp_path / "worker.js"
    worker_file.write_text(
        """
        function internalJob(cmd) {
            child_process.exec(cmd);
        }
        """,
        encoding="utf-8",
    )

    runner = CliRunner()
    res = runner.invoke(cli, ["scan", str(tmp_path)])
    assert res.exit_code == 0

    db = DatabaseManager(tmp_path / ".audit" / "audit.db")
    with db._get_connection() as conn:
        q = "SELECT scan_id FROM scans ORDER BY started_at DESC LIMIT 1;"
        scans = conn.execute(q).fetchone()
        scan_id = scans["scan_id"]

    dossiers = db.get_scan_dossiers(scan_id)
    for d in dossiers:
        # Unrouted internal sinks must NOT have fake HTTP curl templates
        if d["vuln_class"] == "RCE":
            assert d["repro_curl_template"] is None
            assert d["verdict"] == VerdictStatus.INSUFFICIENT_CONTEXT.value


def test_invariant_5_direct_import_resolution():
    """Invariant 5: Sinks resolve through direct imports (e.g. parseXmlString directly)."""
    code = """
        import { parseXmlString } from '../lib/xml';
        const result = parseXmlString(untrustedData);
    """
    detector = SemanticDetector()
    findings = detector.scan_source("routes/upload.ts", code, "typescript")
    assert any(s.vuln_class == "XXE" for s in findings.sinks)


def test_invariant_6_operation_semantics_over_naming():
    """Invariant 6: Detectors evaluate operation semantics regardless of receiver naming."""
    # Lowercase collection in NoSQL
    code_nosql = "db.ordersCollection.find({ $where: `this.id === '${id}'` });"
    detector = SemanticDetector()
    findings = detector.scan_source("routes/track.js", code_nosql, "javascript")
    assert any(s.vuln_class == "NOSQLI" for s in findings.sinks)

    # Scoped vs unscoped lookups in AuthZ
    authz = AuthorizationAnalyzer()
    unscoped_code = "const b = await BasketModel.findOne({ where: { id: req.params.id } });"
    res = authz.analyze_handler("GET", "/basket/:id", unscoped_code, "javascript")
    assert res.has_gap is True
    assert res.gap_type == "CANDIDATE_AUTHZ_GAP"


def test_invariant_7_authoritative_evidence_gate():
    """Invariant 7: Evidence gate requires real CPG bundle; missing path refuses EXPLOITABLE."""
    verifier = EvidenceGateVerifier()

    # Incomplete evidence bundle (missing CPG path)
    incomplete_bundle = EvidenceBundle(
        source_node=None,
        path_trace=None,
        sink_node={"vuln_class": "SQLI"},
        reachability_confidence=0.0,
        bypass_reasoning="Synthesized claim without CPG path",
    )
    result = verifier.evaluate_contract(evidence_bundle=incomplete_bundle)
    assert result.verdict == VerdictStatus.INSUFFICIENT_CONTEXT
    assert result.verdict != VerdictStatus.EXPLOITABLE


def test_invariant_8_evidence_derived_confidence():
    """Invariant 8: Confidence is calculated from edge quality and completeness."""
    cpg = CodePropertyGraph()
    cpg.add_node("src", kind="ENDPOINT")
    cpg.add_node("mid", kind="SYMBOL")
    cpg.add_node("dest", kind="SINK")

    # Weak linker edge in middle
    cpg.add_edge_with_evidence("src", "mid", "CALL", "DETERMINISTIC_AST", 0.95)
    cpg.add_edge_with_evidence("mid", "dest", "CALL", "LINKER_AGENT", 0.62)

    analyzer = ReachabilityAnalyzer(cpg)
    paths = analyzer.find_paths("src", "dest")
    assert len(paths) == 1
    # Must equal weakest link (0.62), NEVER flat 0.90
    assert paths[0].reachability_confidence == 0.62

    verifier = EvidenceGateVerifier()
    bundle = EvidenceBundle(
        source_node={"route": "/test"},
        path_trace=paths[0].nodes,
        sink_node={"vuln_class": "SSRF"},
        reachability_confidence=paths[0].reachability_confidence,
        bypass_reasoning="Valid path",
    )
    res = verifier.evaluate_contract(evidence_bundle=bundle)
    # Final confidence must reflect the weaker reachability link
    assert res.confidence == 0.62
    assert res.confidence != 0.90
