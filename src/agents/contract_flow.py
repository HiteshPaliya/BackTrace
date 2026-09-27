"""Strands Contract-Flow Agent evaluating sanitizers, transforms, and taint reachability."""

import json
import re
from dataclasses import dataclass
from typing import Any, Dict, Optional

from src.storage.db import VerdictStatus


@dataclass
class TaintVerdict:
    """Structured verdict representing taint reachability and sanitizer evaluation."""

    verdict: VerdictStatus
    confidence: float
    source_control_evidence: str
    transform_sanitizer_evidence: str
    sink_requirements: str
    bypass_reasoning: str
    suggested_curl: Optional[str] = None


class ContractFlowAgent:
    """Agent that performs semantic taint analysis on intermediate sanitizers along a path."""

    def __init__(self, llm_client: Any) -> None:
        self.llm = llm_client

    def evaluate(self, path_slice: Dict[str, Any]) -> TaintVerdict:
        """Evaluate whether untrusted taint flows through sanitizers into the candidate sink."""
        slice_json = json.dumps(path_slice, indent=2, default=str)
        prompt = (
            f"You are a taint analysis security reviewer. Evaluate this candidate path slice:\n"
            f"{slice_json}\n\n"
            f"Determine if the sink is exploitable or properly sanitized.\n"
            f"Return JSON matching:\n"
            f'{{\n'
            f'  "verdict": "EXPLOITABLE" | "SAFE_PROVEN" | "INSUFFICIENT_CONTEXT",\n'
            f'  "confidence": 0.0 to 1.0,\n'
            f'  "source_control_evidence": "...",\n'
            f'  "transform_sanitizer_evidence": "...",\n'
            f'  "sink_requirements": "...",\n'
            f'  "bypass_reasoning": "...",\n'
            f'  "suggested_curl": "curl ..."\n'
            f"}}"
        )

        try:
            resp = self.llm.complete(prompt)
            raw_text = resp.get("text", "") if isinstance(resp, dict) else str(resp)

            json_match = re.search(r"\{.*?\}", raw_text, re.DOTALL)
            if not json_match:
                return self._fallback_verdict("No JSON block detected in response")

            data = json.loads(json_match.group(0))
            raw_verdict = data.get("verdict", "").strip().upper()

            try:
                verdict_enum = VerdictStatus(raw_verdict)
            except ValueError:
                verdict_enum = VerdictStatus.INSUFFICIENT_CONTEXT

            return TaintVerdict(
                verdict=verdict_enum,
                confidence=float(data.get("confidence", 0.5)),
                source_control_evidence=str(data.get("source_control_evidence", "")),
                transform_sanitizer_evidence=str(data.get("transform_sanitizer_evidence", "")),
                sink_requirements=str(data.get("sink_requirements", "")),
                bypass_reasoning=str(data.get("bypass_reasoning", "")),
                suggested_curl=data.get("suggested_curl") or None,
            )
        except Exception as exc:
            return self._fallback_verdict(f"Evaluation failed: {exc}")

    def _fallback_verdict(self, reason: str) -> TaintVerdict:
        return TaintVerdict(
            verdict=VerdictStatus.INSUFFICIENT_CONTEXT,
            confidence=0.0,
            source_control_evidence="",
            transform_sanitizer_evidence="",
            sink_requirements="",
            bypass_reasoning=reason,
            suggested_curl=None,
        )
