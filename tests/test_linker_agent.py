"""Tests for Strands Linker Agent and persistent edge insertion."""

from pathlib import Path
from unittest.mock import MagicMock

from src.agents.linker import InferredEdge, LinkerAgent
from src.storage.db import DatabaseManager


def test_linker_agent_infers_and_persists_edge(tmp_path: Path):
    """Happy path: Linker agent resolves dynamic dispatch and persists edge to SQLite."""
    db = DatabaseManager(tmp_path / "test.db")
    db.init_schema()
    f_id = db.upsert_file("src/user.controller.ts", "typescript", False, "h1", 100)
    c_sym = db.insert_symbol(
        f_id, "UserController.handle", "METHOD", 1, 0, 10, 0, "handle()", "class"
    )
    t_sym = db.insert_symbol(
        f_id, "UserServiceImpl.update", "METHOD", 20, 0, 30, 0, "update()", "class"
    )

    mock_llm = MagicMock()
    mock_llm.complete.return_value = {
        "text": (
            '{"target_symbol": "UserServiceImpl.update", "confidence": 0.85, '
            '"reasoning": "Found NestJS provider registration"}'
        )
    }

    agent = LinkerAgent(llm_client=mock_llm, db_manager=db, max_turns=2)
    result = agent.resolve_and_persist(
        caller_symbol_id=c_sym,
        target_interface="IUserService.update",
        file_path="src/user.controller.ts",
    )

    assert result is not None
    assert isinstance(result, InferredEdge)
    assert result.confidence == 0.85
    assert result.provenance == "AGENT_INFERRED"

    # Assert edge was actually persisted in SQLite graph_edges
    edges = db.get_edges_for_caller(c_sym)
    assert len(edges) == 1
    assert edges[0]["callee_symbol_id"] == t_sym
    assert edges[0]["provenance"] == "AGENT_INFERRED"
    assert edges[0]["confidence"] == 0.85


def test_linker_agent_circuit_breaker(tmp_path: Path):
    """Boundary test: Linker agent strictly stops after max_turns attempts."""
    db = DatabaseManager(tmp_path / "test.db")
    db.init_schema()

    mock_llm = MagicMock()
    mock_llm.complete.return_value = {"text": "invalid json"}

    agent = LinkerAgent(llm_client=mock_llm, db_manager=db, max_turns=2)
    result = agent.resolve_and_persist(
        caller_symbol_id=1,
        target_interface="Unknown.api",
        file_path="src/test.ts",
    )
    assert result is None
    assert mock_llm.complete.call_count <= 2
