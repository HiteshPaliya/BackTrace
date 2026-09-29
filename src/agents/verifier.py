"""Evidence sufficiency gate verifier enforcing canonical contract verdicts."""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from src.storage.db import VerdictStatus


@dataclass
class EvidenceBundle:
    """Concrete evidence harvested from CPG graph traversal and semantic analysis."""

    source_node: Optional[Dict[str, Any]] = None
    path_trace: Optional[List[Dict[str, Any]]] = None
    sink_node: Optional[Dict[str, Any]] = None
    transforms: List[Dict[str, Any]] = field(default_factory=list)
    auth_state: str = "UNKNOWN"
    reachability_confidence: float = 0.0
    bypass_reasoning: Optional[str] = None
    has_effective_sanitizer: bool = False
    has_partial_sanitizer: bool = False
    agent_turns: int = 0


@dataclass
class VerificationResult:
    """Standardized verdict outcome backed by a structured evidence bundle."""

    verdict: VerdictStatus
    reachability_confidence: float
    exploitability_confidence: float
    confidence: float
    evidence_bundle: Dict[str, Any] = field(default_factory=dict)
    bypass_reasoning: str = ""


class EvidenceGateVerifier:
    """Enforces strict evidence thresholds before assigning canonical verdicts."""

    MAX_AGENT_TURNS_PER_PATH: int = 8

    def __init__(self, llm_client: Any = None) -> None:
        self.llm = llm_client

    def evaluate_contract(
        self,
        source_control: Optional[str] = None,
        reachability_confidence: float = 0.0,
        sink_preconditions: str = "",
        transform_status: str = "UNKNOWN",
        bypass_reasoning: str = "",
        auth_state: str = "NOT_REQUIRED",
        evidence_bundle: Optional[EvidenceBundle] = None,
    ) -> VerificationResult:
        """Evaluate evidence sufficiency against security contracts."""
        if evidence_bundle is not None:
            # Circuit breaker: Max 8 agent turns per path
            reach_conf = evidence_bundle.reachability_confidence
            if evidence_bundle.agent_turns > self.MAX_AGENT_TURNS_PER_PATH:
                return VerificationResult(
                    verdict=VerdictStatus.INSUFFICIENT_CONTEXT,
                    reachability_confidence=reach_conf,
                    exploitability_confidence=0.0,
                    confidence=0.0,
                    evidence_bundle={
                        "circuit_breaker": "EXCEEDED_MAX_AGENT_TURNS_8",
                        "agent_turns": evidence_bundle.agent_turns,
                    },
                    bypass_reasoning=(
                        "Circuit breaker triggered: Exceeded max 8 agent turns per path"
                    ),
                )

            # Invariant 7: Verifier evaluates strictly from EvidenceBundle
            has_source = evidence_bundle.source_node is not None
            has_path = bool(evidence_bundle.path_trace)
            has_sink = evidence_bundle.sink_node is not None
            reasoning = evidence_bundle.bypass_reasoning or ""
            auth = evidence_bundle.auth_state

            bundle_dict = {
                "source_node": evidence_bundle.source_node,
                "path_trace_len": len(evidence_bundle.path_trace or []),
                "sink_node": evidence_bundle.sink_node,
                "transforms_count": len(evidence_bundle.transforms),
                "auth_state": auth,
                "reachability_confidence": reach_conf,
                "agent_turns": evidence_bundle.agent_turns,
                "bypass_reasoning": self._sanitize_cot(reasoning),
            }

            # Invariant 7 & 8: Insufficient CPG evidence -> INSUFFICIENT_CONTEXT
            if not has_source or not has_path or not has_sink or reach_conf < 0.60:
                return VerificationResult(
                    verdict=VerdictStatus.INSUFFICIENT_CONTEXT,
                    reachability_confidence=reach_conf,
                    exploitability_confidence=0.0,
                    confidence=0.0,
                    evidence_bundle=bundle_dict,
                    bypass_reasoning="Insufficient CPG path, source, or sink evidence",
                )

            if evidence_bundle.has_effective_sanitizer:
                exp_conf = 0.95
                return VerificationResult(
                    verdict=VerdictStatus.SAFE_PROVEN,
                    reachability_confidence=reach_conf,
                    exploitability_confidence=exp_conf,
                    confidence=round(min(reach_conf, exp_conf), 2),
                    evidence_bundle=bundle_dict,
                    bypass_reasoning=reasoning,
                )

            if evidence_bundle.has_partial_sanitizer:
                exp_conf = 0.75
                return VerificationResult(
                    verdict=VerdictStatus.LIKELY_EXPLOITABLE_PARTIAL_SANITIZATION,
                    reachability_confidence=reach_conf,
                    exploitability_confidence=exp_conf,
                    confidence=round(min(reach_conf, exp_conf), 2),
                    evidence_bundle=bundle_dict,
                    bypass_reasoning=reasoning,
                )

            # Invariant 8: Evidence-derived confidence
            exp_conf = 0.90
            final_conf = round(min(reach_conf, exp_conf), 2)
            return VerificationResult(
                verdict=VerdictStatus.EXPLOITABLE,
                reachability_confidence=reach_conf,
                exploitability_confidence=exp_conf,
                confidence=final_conf,
                evidence_bundle=bundle_dict,
                bypass_reasoning=reasoning,
            )

        # Legacy / direct arguments fallback
        bundle_dict = {
            "source_control": source_control,
            "reachability_confidence": reachability_confidence,
            "sink_preconditions": sink_preconditions,
            "transform_status": transform_status,
            "bypass_reasoning": self._sanitize_cot(bypass_reasoning),
            "auth_state": auth_state,
        }

        # 1. Ambiguity or missing evidence -> INSUFFICIENT_CONTEXT
        if (
            source_control != "CONFIRMED"
            or reachability_confidence < 0.60
            or transform_status == "UNKNOWN"
        ):
            return VerificationResult(
                verdict=VerdictStatus.INSUFFICIENT_CONTEXT,
                reachability_confidence=reachability_confidence,
                exploitability_confidence=0.0,
                confidence=0.0,
                evidence_bundle=bundle_dict,
                bypass_reasoning="Insufficient context to confirm exploitability or safety",
            )

        # 2. Effective transformation satisfying contract -> SAFE_PROVEN
        if transform_status == "EFFECTIVE":
            exp_conf = 0.95
            return VerificationResult(
                verdict=VerdictStatus.SAFE_PROVEN,
                reachability_confidence=reachability_confidence,
                exploitability_confidence=exp_conf,
                confidence=round(min(reachability_confidence, exp_conf), 2),
                evidence_bundle=bundle_dict,
                bypass_reasoning=bypass_reasoning,
            )

        # 3. Flawed / partial sanitizer -> LIKELY_EXPLOITABLE_PARTIAL_SANITIZATION
        if transform_status == "PARTIAL":
            exp_conf = 0.75
            return VerificationResult(
                verdict=VerdictStatus.LIKELY_EXPLOITABLE_PARTIAL_SANITIZATION,
                reachability_confidence=reachability_confidence,
                exploitability_confidence=exp_conf,
                confidence=round(min(reachability_confidence, exp_conf), 2),
                evidence_bundle=bundle_dict,
                bypass_reasoning=bypass_reasoning,
            )

        # 4. Verified control and failed transforms -> EXPLOITABLE
        exp_conf = 0.90
        return VerificationResult(
            verdict=VerdictStatus.EXPLOITABLE,
            reachability_confidence=reachability_confidence,
            exploitability_confidence=exp_conf,
            confidence=round(min(reachability_confidence, exp_conf), 2),
            evidence_bundle=bundle_dict,
            bypass_reasoning=bypass_reasoning,
        )

    def _sanitize_cot(self, text: str) -> str:
        """Strip raw chain-of-thought tokens and monologue scratchpads."""
        cleaned = text
        for token in ["<thought>", "</thought>", "Prosecutor:", "Defender:", "scratchpad:"]:
            cleaned = cleaned.replace(token, "")
        return cleaned.strip()
