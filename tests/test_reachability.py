"""Tests for CodePropertyGraph and ReachabilityAnalyzer."""

from pathlib import Path

from src.graph.cpg import CodePropertyGraph
from src.graph.reachability import ReachabilityAnalyzer
from src.storage.db import DatabaseManager


def test_reachability_finds_paths_and_prunes_cycles():
    """Happy path: Finds directed path from source to target while pruning cyclic loops."""
    cpg = CodePropertyGraph()
    # Add nodes: Endpoint -> FuncA -> FuncB (cycle to FuncA) -> Sink
    cpg.add_node("endpoint_1", kind="ENDPOINT")
    cpg.add_node("func_a", kind="FUNCTION")
    cpg.add_node("func_b", kind="FUNCTION")
    cpg.add_node("sink_1", kind="SINK")

    cpg.add_edge("endpoint_1", "func_a", edge_type="CALL", confidence=1.0)
    cpg.add_edge("func_a", "func_b", edge_type="CALL", confidence=1.0)
    cpg.add_edge("func_b", "func_a", edge_type="CALL", confidence=1.0)  # Cycle!
    cpg.add_edge("func_b", "sink_1", edge_type="CALL", confidence=1.0)

    analyzer = ReachabilityAnalyzer(cpg)
    paths = analyzer.find_paths("endpoint_1", "sink_1", max_hops=20)

    assert len(paths) == 1
    assert paths[0].nodes == ["endpoint_1", "func_a", "func_b", "sink_1"]
    assert paths[0].hop_count == 3


def test_reachability_max_hops_circuit_breaker():
    """Boundary test: Paths longer than max_hops (20) are pruned."""
    cpg = CodePropertyGraph()
    nodes = [f"n_{i}" for i in range(25)]
    for n in nodes:
        cpg.add_node(n, kind="FUNCTION")
    for i in range(24):
        cpg.add_edge(nodes[i], nodes[i + 1], edge_type="CALL", confidence=1.0)

    analyzer = ReachabilityAnalyzer(cpg)
    # Default 20 hops limit
    paths = analyzer.find_paths("n_0", "n_24", max_hops=20)
    assert len(paths) == 0

    # With higher limit
    paths_allowed = analyzer.find_paths("n_0", "n_24", max_hops=25)
    assert len(paths_allowed) == 1


def test_reachability_disconnected_graph():
    """Boundary test: Disconnected nodes return empty list."""
    cpg = CodePropertyGraph()
    cpg.add_node("src", kind="ENDPOINT")
    cpg.add_node("dest", kind="SINK")
    analyzer = ReachabilityAnalyzer(cpg)
    paths = analyzer.find_paths("src", "dest")
    assert paths == []


def test_cpg_load_from_database(tmp_path: Path):
    """Integration test: CodePropertyGraph loads nodes and edges directly from SQLite."""
    db_file = tmp_path / "test.db"
    db = DatabaseManager(db_file)
    db.init_schema()

    file_id = db.upsert_file("app.py", "python", is_vendor=False, file_hash="h", loc=50)
    sym_a = db.insert_symbol(file_id, "entry", "FUNCTION", 1, 0, 5, 0)
    sym_b = db.insert_symbol(file_id, "worker", "FUNCTION", 6, 0, 10, 0)
    db.insert_graph_edge(sym_a, sym_b, "CALL", "DETERMINISTIC", 1.0)

    cpg = CodePropertyGraph()
    cpg.load_from_db(db)

    assert f"sym_{sym_a}" in cpg.graph
    assert f"sym_{sym_b}" in cpg.graph
    assert cpg.graph.has_edge(f"sym_{sym_a}", f"sym_{sym_b}")
