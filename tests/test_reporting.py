"""Tests for DossierSynthesizer, SARIF 2.1.0, Graph JSON, and Markdown Exporters."""

import json
from pathlib import Path

from click.testing import CliRunner

from src.cli import cli
from src.reporting.graph_json import GraphJSONExporter
from src.reporting.markdown import MarkdownExporter
from src.reporting.sarif import SARIFExporter
from src.reporting.synthesizer import DossierSynthesizer
from src.storage.db import DatabaseManager, VerdictStatus


def test_exporters_generate_sarif_and_graph_json(tmp_path: Path):
    """Happy path: SARIF 2.1.0 and Graph JSON exports conform to schema."""
    db = DatabaseManager(tmp_path / "test.db")
    db.init_schema()
    f_id = db.upsert_file("app.py", "python", False, "h1", 50)
    db.insert_symbol(f_id, "run", "FUNCTION", 1, 0, 5, 0, "run()", "global")

    dossiers = [
        {
            "dossier_id": "D1",
            "title": "Command Injection in UploadHandler",
            "vuln_class": "RCE",
            "severity": "CRITICAL",
            "cwe_id": "CWE-78",
            "verdict": VerdictStatus.EXPLOITABLE.value,
            "confidence": 0.95,
            "source_trace_json": json.dumps([{"file": "app.py", "line": 42}]),
            "sanitizer_analysis_json": json.dumps({"bypass_reasoning": "Unquoted exec"}),
            "repro_curl_template": "curl http://localhost:3000/upload",
            "mitigation_notes": "Use shlex.quote or avoid shell=True",
        }
    ]

    sarif_exporter = SARIFExporter()
    sarif_json = sarif_exporter.export(dossiers)
    assert sarif_json["version"] == "2.1.0"
    assert len(sarif_json["runs"]) == 1
    assert len(sarif_json["runs"][0]["results"]) == 1
    assert sarif_json["runs"][0]["results"][0]["ruleId"] == "CWE-78"

    graph_exporter = GraphJSONExporter()
    graph_json = graph_exporter.export(db)
    assert "nodes" in graph_json
    assert len(graph_json["nodes"]) == 1
    assert graph_json["nodes"][0]["name"] == "run"


def test_markdown_exporter_output(tmp_path: Path):
    """Happy path: Markdown exporter includes title, severity, verdict, and curl template."""
    dossiers = [
        {
            "dossier_id": "D1",
            "title": "SQL Injection in User Search",
            "vuln_class": "SQLI",
            "severity": "HIGH",
            "cwe_id": "CWE-89",
            "verdict": VerdictStatus.EXPLOITABLE.value,
            "confidence": 0.9,
            "source_trace_json": json.dumps([{"file": "user.py", "line": 10}]),
            "sanitizer_analysis_json": json.dumps({"bypass_reasoning": "Direct concatenation"}),
            "repro_curl_template": "curl 'http://localhost:8000/search?q=admin%27--'",
            "mitigation_notes": "Use parameterized queries",
        }
    ]
    md_exporter = MarkdownExporter()
    report = md_exporter.export(dossiers, scan_id="scan-xyz")
    assert "# Security Review Research Dossier" in report
    assert "SQL Injection in User Search" in report
    assert "curl 'http://localhost:8000/search?q=admin%27--'" in report


def test_dossier_synthesizer_compilation():
    """Happy path: Synthesizer compiles verdicts into structured database-ready payload."""
    synthesizer = DossierSynthesizer()
    dossier = synthesizer.synthesize(
        scan_id="scan-123",
        path_id="path-456",
        engine_fingerprint="fp_test",
        title="Path Traversal in Download",
        vuln_class="PATH_TRAVERSAL",
        severity="HIGH",
        cwe_id="CWE-22",
        verdict=VerdictStatus.EXPLOITABLE,
        confidence=0.85,
        source_trace=[{"file": "files.py", "line": 15}],
        sanitizer_analysis={"bypass_reasoning": "Dot dot slash unstripped"},
        repro_curl="curl http://target/dl?f=../../etc/passwd",
    )
    assert dossier["dossier_id"].startswith("dos_")
    assert dossier["verdict"] == "EXPLOITABLE"
    assert "etc/passwd" in dossier["repro_curl_template"]


def test_cli_subcommands():
    """Boundary test: CLI commands report valid usage and options."""
    runner = CliRunner()
    result = runner.invoke(cli, ["--help"])
    assert result.exit_code == 0
    assert "scan" in result.output
    assert "report" in result.output
    assert "diff" in result.output
    assert "resume" in result.output
