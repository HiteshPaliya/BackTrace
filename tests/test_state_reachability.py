"""Tests for State-Aware Graph Reachability and Bounded Confidence Aggregation."""

from src.graph.cpg import CodePropertyGraph
from src.graph.reachability import ReachabilityAnalyzer
from src.triage.scorer import CompositeScorer


def test_state_aware_traversal_and_bounded_confidence():
    """Happy path: Traversal uses weakest-link confidence instead of multiplicative decay."""
    cpg = CodePropertyGraph()
    cpg.add_node("ep_1", kind="ENDPOINT")
    cpg.add_node("ctrl_1", kind="SYMBOL")
    cpg.add_node("srv_1", kind="SYMBOL")
    cpg.add_node("sink_1", kind="SINK")

    # Add edges with resolution evidence and confidence
    cpg.add_edge_with_evidence("ep_1", "ctrl_1", "HANDLED_BY", "FRAMEWORK_RESOLVER", 0.98)
    cpg.add_edge_with_evidence("ctrl_1", "srv_1", "CALL", "DETERMINISTIC_AST", 0.95)
    cpg.add_edge_with_evidence("srv_1", "sink_1", "CALL", "LINKER_AGENT", 0.70)

    analyzer = ReachabilityAnalyzer(cpg)
    paths = analyzer.find_paths("ep_1", "sink_1", max_hops=20)

    assert len(paths) == 1
    # Bounded weakest-link confidence aggregation: min(0.98, 0.95, 0.70) = 0.70
    assert paths[0].reachability_confidence == 0.70
    assert paths[0].hop_count == 3


def test_state_aware_cycle_termination():
    """Boundary test: State-aware key (node, edge, state) terminates cyclic loops safely."""
    cpg = CodePropertyGraph()
    cpg.add_node("a", kind="SYMBOL")
    cpg.add_node("b", kind="SYMBOL")
    cpg.add_node("c", kind="SINK")

    cpg.add_edge_with_evidence("a", "b", "CALL", "DETERMINISTIC_AST", 1.0)
    cpg.add_edge_with_evidence("b", "a", "CALL", "DETERMINISTIC_AST", 1.0)  # Direct cycle
    cpg.add_edge_with_evidence("b", "c", "CALL", "DETERMINISTIC_AST", 1.0)

    analyzer = ReachabilityAnalyzer(cpg)
    paths = analyzer.find_paths("a", "c", max_hops=10)

    assert len(paths) == 1
    assert paths[0].nodes == ["a", "b", "c"]


def test_composite_scorer_with_scope_and_tri_state_auth():
    """Happy path: Triage formula incorporates ScopeFactor and tri-state exposure."""
    # Production web runtime, unauthenticated exposure
    prio_prod_unauth = CompositeScorer.calculate_priority(
        sink_severity="CRITICAL",
        reachability_confidence=0.90,
        auth_state="NOT_REQUIRED",
        hop_count=2,
        execution_domain="APPLICATION_RUNTIME",
    )

    # CI pipeline workflow (supply-chain threat model)
    prio_ci = CompositeScorer.calculate_priority(
        sink_severity="CRITICAL",
        reachability_confidence=0.90,
        auth_state="NOT_REQUIRED",
        hop_count=2,
        execution_domain="CI_CD_PIPELINE",
    )

    # Test mock scope
    prio_test = CompositeScorer.calculate_priority(
        sink_severity="CRITICAL",
        reachability_confidence=0.90,
        auth_state="NOT_REQUIRED",
        hop_count=2,
        execution_domain="TEST_MOCK",
    )

    assert prio_prod_unauth > prio_ci > prio_test
