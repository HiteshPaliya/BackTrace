"""Strands Adversarial Debate Engine (dialectic taint verification without private CoT)."""

import json
import re
from dataclasses import dataclass
from typing import Any, Dict, Optional

from src.storage.db import VerdictStatus


@dataclass
class DebateVerdict:
    """Public curated verdict synthesized from adversarial debate."""

    verdict: VerdictStatus
    confidence: float
    source_control_evidence: str
    transform_sanitizer_evidence: str
    sink_requirements: str
    bypass_reasoning: str
    suggested_curl: Optional[str] = None
    sanitizer_analysis_json: str = ""


class AdversarialDebateEngine:
    """Orchestrates ephemeral Prosecutor vs Defender debate and Judge synthesis."""

    def __init__(self, llm_client: Any, max_rounds: int = 1) -> None:
        self.llm = llm_client
        self.max_rounds = min(max_rounds, 3)

    def conduct_debate(self, path_slice: Dict[str, Any]) -> DebateVerdict:
        """Run dialectic debate and synthesize curated public evidence only."""
        slice_repr = json.dumps(path_slice, default=str)

        # 1. Ephemeral Prosecutor turn
        pros_prompt = (
            f"You are the Offensive Security Prosecutor. Argue why this path is exploitable:\n"
            f"{slice_repr}"
        )
        pros_resp = self.llm.complete(pros_prompt)
        pros_text = pros_resp.get("text", "") if isinstance(pros_resp, dict) else str(pros_resp)

        # 2. Ephemeral Defender turn
        def_prompt = (
            f"You are the AppSec Defender. Argue why this path is safe or sanitized:\n"
            f"Context: {slice_repr}\n"
            f"Prosecutor Claim: {pros_text}"
        )
        def_resp = self.llm.complete(def_prompt)
        def_text = def_resp.get("text", "") if isinstance(def_resp, dict) else str(def_resp)

        # 3. Final Arbiter / Judge: Synthesizes curated public evidence only
        judge_prompt = (
            f"You are the Neutral AppSec Judge. Deliberate and synthesize a verdict.\n"
            f"Produce strictly a JSON object with keys:\n"
            f'{{"verdict": "EXPLOITABLE" | "SAFE_PROVEN" | "INSUFFICIENT_CONTEXT",\n'
            f' "confidence": float,\n'
            f' "source_control_evidence": str,\n'
            f' "transform_sanitizer_evidence": str,\n'
            f' "sink_requirements": str,\n'
            f' "bypass_reasoning": str,\n'
            f' "suggested_curl": str or null}}\n'
            f"Prosecution: {pros_text}\n"
            f"Defense: {def_text}\n"
        )
        judge_resp = self.llm.complete(judge_prompt)
        judge_text = judge_resp.get("text", "") if isinstance(judge_resp, dict) else str(judge_resp)

        return self._parse_curated_verdict(judge_text)

    def _parse_curated_verdict(self, raw_judge_text: str) -> DebateVerdict:
        json_match = re.search(r"\{.*?\}", raw_judge_text, re.DOTALL)
        if not json_match:
            # Fallback verdict if judge produces invalid output
            fallback_dict = {
                "source_control_evidence": "",
                "transform_sanitizer_evidence": "",
                "sink_requirements": "",
                "bypass_reasoning": "Judge output unparseable",
            }
            return DebateVerdict(
                verdict=VerdictStatus.INSUFFICIENT_CONTEXT,
                confidence=0.0,
                source_control_evidence="",
                transform_sanitizer_evidence="",
                sink_requirements="",
                bypass_reasoning="Judge output unparseable",
                suggested_curl=None,
                sanitizer_analysis_json=json.dumps(fallback_dict),
            )

        try:
            cleaned_json = re.sub(r"\\'", "'", json_match.group(0))
            data = json.loads(cleaned_json)
            raw_verdict = data.get("verdict", "").strip().upper()
            try:
                verdict_enum = VerdictStatus(raw_verdict)
            except ValueError:
                verdict_enum = VerdictStatus.INSUFFICIENT_CONTEXT

            # Build strictly curated analysis json without ephemeral scratchpad
            curated_evidence = {
                "source_control_evidence": str(data.get("source_control_evidence", "")),
                "transform_sanitizer_evidence": str(data.get("transform_sanitizer_evidence", "")),
                "sink_requirements": str(data.get("sink_requirements", "")),
                "bypass_reasoning": str(data.get("bypass_reasoning", "")),
            }

            return DebateVerdict(
                verdict=verdict_enum,
                confidence=float(data.get("confidence", 0.5)),
                source_control_evidence=curated_evidence["source_control_evidence"],
                transform_sanitizer_evidence=curated_evidence["transform_sanitizer_evidence"],
                sink_requirements=curated_evidence["sink_requirements"],
                bypass_reasoning=curated_evidence["bypass_reasoning"],
                suggested_curl=data.get("suggested_curl") or None,
                sanitizer_analysis_json=json.dumps(curated_evidence),
            )
        except Exception:
            return DebateVerdict(
                verdict=VerdictStatus.INSUFFICIENT_CONTEXT,
                confidence=0.0,
                source_control_evidence="",
                transform_sanitizer_evidence="",
                sink_requirements="",
                bypass_reasoning="Parse failure",
                suggested_curl=None,
                sanitizer_analysis_json=json.dumps({"bypass_reasoning": "Parse failure"}),
            )
