"""Tests for Endpoint-Aware Non-Weaponized Reproduction Templates and Scoped Exporters."""

from pathlib import Path

from src.reporting.graph_json import GraphJSONExporter
from src.reporting.synthesizer import DossierSynthesizer
from src.storage.db import DatabaseManager


def test_reproduction_synthesizer_emits_assertion_blueprint():
    """Happy path: Synthesizer emits structured reproduction blueprint with inert markers."""
    synthesizer = DossierSynthesizer()
    blueprint = synthesizer.generate_reproduction_template(
        endpoint_method="POST",
        route_pattern="/rest/user/login",
        auth_state="REQUIRED",
        tainted_param={"location": "BODY", "name": "email"},
        sibling_params=[{"location": "BODY", "name": "password", "dummy": "dummyPass123!"}],
        sink_target="models.sequelize.query",
    )

    assert blueprint["reproduction_type"] == "HTTP_TEMPLATE"
    # Must use inert marker, NEVER weaponized payload
    assert "BT_FLOW_MARKER_001" in blueprint["curl_command"]
    assert "' OR 1=1--" not in blueprint["curl_command"]
    assert "Authorization: Bearer ${AUTH_TOKEN}" in blueprint["curl_command"]
    assert blueprint["expected_assertion"]["assertion_type"] == "PARAMETER_REACHABILITY"


def test_reproduction_synthesizer_non_http_template():
    """Boundary test: CLI or internal sink returns NON_HTTP_TEMPLATE."""
    synthesizer = DossierSynthesizer()
    blueprint = synthesizer.generate_reproduction_template(
        endpoint_method=None,
        route_pattern=None,
        auth_state="NOT_REQUIRED",
        tainted_param={"location": "CLI_ARG", "name": "file_arg"},
        sink_target="os.system",
    )
    assert blueprint["reproduction_type"] == "NON_HTTP_TEMPLATE"
    assert "CLI" in blueprint["expected_assertion"]["description"]


def test_graph_json_export_scoping(tmp_path: Path):
    """Happy path: Graph JSON exporter supports scoped export filtering."""
    db = DatabaseManager(tmp_path / "scope_graph.db")
    db.init_schema()

    f1 = db.upsert_file("app.py", "python", False, "h1", 50)
    s1 = db.insert_symbol(f1, "funcA", "FUNCTION", 1, 0, 5, 0)
    s2 = db.insert_symbol(f1, "funcB", "FUNCTION", 6, 0, 10, 0)
    db.insert_graph_edge(s1, s2, "CALL")

    exporter = GraphJSONExporter()
    repo_graph = exporter.export(db, scope="repository")
    assert len(repo_graph["nodes"]) == 2

    # Scoped export to specific symbol
    sym_graph = exporter.export(db, scope="symbol", symbol_name="funcA")
    assert len(sym_graph["nodes"]) == 1
    assert sym_graph["nodes"][0]["name"] == "funcA"
