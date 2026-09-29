"""Tests for Evidence-Gated Verification and Canonical Verdicts."""

from unittest.mock import MagicMock

from src.agents.verifier import EvidenceGateVerifier
from src.storage.db import VerdictStatus


def test_evidence_sufficiency_gate_strict_verdicts():
    """Happy path: Verifier strictly maps contract criteria to canonical verdicts."""
    mock_llm = MagicMock()
    verifier = EvidenceGateVerifier(mock_llm)

    # Case 1: Full proof -> EXPLOITABLE
    res_exploit = verifier.evaluate_contract(
        source_control="CONFIRMED",
        reachability_confidence=0.85,
        sink_preconditions="POSIX shell metacharacters",
        transform_status="FAILED",
        bypass_reasoning="Raw string concatenation into exec",
    )
    assert res_exploit.verdict == VerdictStatus.EXPLOITABLE

    # Case 2: Partial transform / unanchored regex -> LIKELY_EXPLOITABLE_PARTIAL_SANITIZATION
    res_partial = verifier.evaluate_contract(
        source_control="CONFIRMED",
        reachability_confidence=0.80,
        sink_preconditions="SQL string delimiter",
        transform_status="PARTIAL",
        bypass_reasoning="Regex /admin_[a-z]+/ misses end anchor",
    )
    assert res_partial.verdict == VerdictStatus.LIKELY_EXPLOITABLE_PARTIAL_SANITIZATION

    # Case 3: Ambiguous or missing source line -> INSUFFICIENT_CONTEXT
    res_ambiguous = verifier.evaluate_contract(
        source_control="UNKNOWN",
        reachability_confidence=0.50,
        sink_preconditions="Unknown",
        transform_status="UNKNOWN",
        bypass_reasoning="Missing source lines",
    )
    assert res_ambiguous.verdict == VerdictStatus.INSUFFICIENT_CONTEXT

    # Case 4: Effective transform -> SAFE_PROVEN
    res_safe = verifier.evaluate_contract(
        source_control="CONFIRMED",
        reachability_confidence=0.95,
        sink_preconditions="SQL string delimiter",
        transform_status="EFFECTIVE",
        bypass_reasoning="Strict integer casting prevents injection",
    )
    assert res_safe.verdict == VerdictStatus.SAFE_PROVEN


def test_evidence_bundle_zero_cot():
    """Security audit: Evidence bundle contains structured fields and zero raw CoT."""
    mock_llm = MagicMock()
    verifier = EvidenceGateVerifier(mock_llm)

    res = verifier.evaluate_contract(
        source_control="CONFIRMED",
        reachability_confidence=0.90,
        sink_preconditions="Unescaped HTML",
        transform_status="FAILED",
        bypass_reasoning="User string in innerHTML",
    )
    bundle = res.evidence_bundle
    assert "source_control" in bundle
    assert "transform_status" in bundle
    assert "bypass_reasoning" in bundle

    bundle_str = str(bundle).lower()
    for forbidden in ["<thought>", "scratchpad", "prosecutor:", "defender:"]:
        assert forbidden not in bundle_str


def test_max_agent_turns_per_path_circuit_breaker():
    """Global constraint: Exceeding 8 agent turns per path triggers circuit breaker."""
    from src.agents.verifier import EvidenceBundle

    verifier = EvidenceGateVerifier()
    # 9 turns exceeds limit of 8
    bundle_exceeded = EvidenceBundle(
        source_node={"route": "/api/test"},
        path_trace=[{"node": "ep"}, {"node": "sink"}],
        sink_node={"vuln_class": "RCE"},
        reachability_confidence=0.90,
        bypass_reasoning="Valid path",
        agent_turns=9,
    )
    res = verifier.evaluate_contract(evidence_bundle=bundle_exceeded)
    assert res.verdict == VerdictStatus.INSUFFICIENT_CONTEXT
    assert "8 agent turns" in res.bypass_reasoning
