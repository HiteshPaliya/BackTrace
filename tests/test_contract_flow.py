"""Tests for Strands ContractFlowAgent evaluating sanitizers and taint."""

from unittest.mock import MagicMock

from src.agents.contract_flow import ContractFlowAgent, TaintVerdict
from src.storage.db import VerdictStatus


def test_contract_flow_agent_evaluates_sanitization():
    """Happy path: Contract flow agent parses structured taint analysis and curl template."""
    mock_llm = MagicMock()
    mock_llm.complete.return_value = {
        "text": """{
            "verdict": "EXPLOITABLE",
            "confidence": 0.95,
            "source_control_evidence": "User controls req.body.command directly",
            "transform_sanitizer_evidence": "No escaping or validation applied before execution",
            "sink_requirements": "POSIX shell metacharacters trigger command injection",
            "bypass_reasoning": "Direct string concatenation into child_process.exec",
            "suggested_curl": "curl -X POST http://localhost:3000/api/run -d 'command=id'"
        }"""
    }

    agent = ContractFlowAgent(llm_client=mock_llm)
    verdict = agent.evaluate({"path_id": "test_p1", "sink": "child_process.exec(cmd)"})

    assert isinstance(verdict, TaintVerdict)
    assert verdict.verdict == VerdictStatus.EXPLOITABLE
    assert verdict.confidence == 0.95
    assert "curl" in verdict.suggested_curl


def test_contract_flow_sanitizer_safe_proven():
    """Happy path: Safe sanitizer leads to SAFE_PROVEN verdict."""
    mock_llm = MagicMock()
    mock_llm.complete.return_value = {
        "text": """{
            "verdict": "SAFE_PROVEN",
            "confidence": 0.99,
            "source_control_evidence": "Input from query param",
            "transform_sanitizer_evidence": "int(val) ensures strict numeric type casting",
            "sink_requirements": "Requires non-integer string",
            "bypass_reasoning": "Bypass impossible due to ValueError on non-digit",
            "suggested_curl": ""
        }"""
    }

    agent = ContractFlowAgent(llm_client=mock_llm)
    verdict = agent.evaluate({"path_id": "test_p2", "sink": "db.get_user(int(val))"})

    assert verdict.verdict == VerdictStatus.SAFE_PROVEN
    assert verdict.confidence == 0.99


def test_contract_flow_malformed_fallback():
    """Boundary test: Invalid LLM JSON falls back to INSUFFICIENT_CONTEXT."""
    mock_llm = MagicMock()
    mock_llm.complete.return_value = {"text": "I am not sure..."}

    agent = ContractFlowAgent(llm_client=mock_llm)
    verdict = agent.evaluate({"path_id": "test_p3"})

    assert verdict.verdict == VerdictStatus.INSUFFICIENT_CONTEXT
    assert verdict.confidence == 0.0
