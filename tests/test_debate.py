"""Tests for Strands Adversarial Debate Engine (ephemeral CoT, curated structured evidence)."""

from unittest.mock import MagicMock

from src.agents.debate import AdversarialDebateEngine
from src.storage.db import VerdictStatus


def test_debate_engine_synthesizes_structured_evidence_without_cot():
    """Happy path: Debate produces curated evidence without raw monologue."""
    mock_llm = MagicMock()
    mock_llm.complete.side_effect = [
        {"text": "Prosecutor: Regex lacks ^ and $ anchors, allowing leading payload injection."},
        {"text": "Defender: Regex correctly matches letters only, but concedes anchor absence."},
        {
            "text": """{
            "verdict": "EXPLOITABLE",
            "confidence": 0.88,
            "source_control_evidence": "Attacker supplies unanchored string",
            "transform_sanitizer_evidence": "Regex /admin_[a-z]+/ misses end anchor",
            "sink_requirements": "Requires valid prefix plus SQL injection trailer",
            "bypass_reasoning": "Payload 'admin_user\\' OR 1=1--' bypasses regex and triggers SQLi",
            "suggested_curl": "curl 'http://localhost:8000/role?name=admin_user%27+OR+1%3D1--'"
        }"""
        },
    ]

    engine = AdversarialDebateEngine(llm_client=mock_llm, max_rounds=1)
    verdict = engine.conduct_debate({"sink": "db.raw(query)", "vuln_class": "SQLI"})

    assert verdict.verdict == VerdictStatus.EXPLOITABLE
    assert "Prosecutor:" not in verdict.sanitizer_analysis_json  # No private monologue stored!
    assert "Defender:" not in verdict.sanitizer_analysis_json
    assert "bypass_reasoning" in verdict.sanitizer_analysis_json


def test_debate_engine_fallback_on_malformed_judge():
    """Boundary test: Broken judge response falls back to INSUFFICIENT_CONTEXT safely."""
    mock_llm = MagicMock()
    mock_llm.complete.side_effect = [
        {"text": "Prosecutor: issue"},
        {"text": "Defender: disagreement"},
        {"text": "Judge: unable to formulate valid json"},
    ]

    engine = AdversarialDebateEngine(llm_client=mock_llm, max_rounds=1)
    verdict = engine.conduct_debate({"sink": "unknown"})

    assert verdict.verdict == VerdictStatus.INSUFFICIENT_CONTEXT
    assert "Prosecutor:" not in verdict.sanitizer_analysis_json
