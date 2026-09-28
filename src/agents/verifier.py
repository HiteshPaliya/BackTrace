"""Evidence sufficiency gate verifier enforcing canonical contract verdicts."""

from dataclasses import dataclass, field
from typing import Any, Dict

from src.storage.db import VerdictStatus


@dataclass
class VerificationResult:
    """Standardized verdict outcome backed by a structured evidence bundle."""

    verdict: VerdictStatus
    reachability_confidence: float
    exploitability_confidence: float
    evidence_bundle: Dict[str, Any] = field(default_factory=dict)
    bypass_reasoning: str = ""


class EvidenceGateVerifier:
    """Enforces strict evidence thresholds before assigning canonical verdicts."""

    def __init__(self, llm_client: Any = None) -> None:
        self.llm = llm_client

    def evaluate_contract(
        self,
        source_control: str,
        reachability_confidence: float,
        sink_preconditions: str,
        transform_status: str,
        bypass_reasoning: str,
        auth_state: str = "NOT_REQUIRED",
    ) -> VerificationResult:
        """Evaluate evidence sufficiency against security contracts."""
        evidence_bundle = {
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
                evidence_bundle=evidence_bundle,
                bypass_reasoning="Insufficient context to confirm exploitability or safety",
            )

        # 2. Effective transformation satisfying contract -> SAFE_PROVEN
        if transform_status == "EFFECTIVE":
            return VerificationResult(
                verdict=VerdictStatus.SAFE_PROVEN,
                reachability_confidence=reachability_confidence,
                exploitability_confidence=0.95,
                evidence_bundle=evidence_bundle,
                bypass_reasoning=bypass_reasoning,
            )

        # 3. Flawed / partial sanitizer -> LIKELY_EXPLOITABLE_PARTIAL_SANITIZATION
        if transform_status == "PARTIAL":
            return VerificationResult(
                verdict=VerdictStatus.LIKELY_EXPLOITABLE_PARTIAL_SANITIZATION,
                reachability_confidence=reachability_confidence,
                exploitability_confidence=0.80,
                evidence_bundle=evidence_bundle,
                bypass_reasoning=bypass_reasoning,
            )

        # 4. Verified control and failed transforms -> EXPLOITABLE
        return VerificationResult(
            verdict=VerdictStatus.EXPLOITABLE,
            reachability_confidence=reachability_confidence,
            exploitability_confidence=0.90,
            evidence_bundle=evidence_bundle,
            bypass_reasoning=bypass_reasoning,
        )

    def _sanitize_cot(self, text: str) -> str:
        """Strip raw chain-of-thought tokens and monologue scratchpads."""
        cleaned = text
        for token in ["<thought>", "</thought>", "Prosecutor:", "Defender:", "scratchpad:"]:
            cleaned = cleaned.replace(token, "")
        return cleaned.strip()
