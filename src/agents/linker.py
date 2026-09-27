"""Strands Linker Agent resolving dynamic dispatches and persisting inferred edges."""

import json
import re
from dataclasses import dataclass
from typing import Any, Optional

from src.storage.db import DatabaseManager


@dataclass
class InferredEdge:
    """An inferred dynamic dispatch call edge."""

    caller_symbol_id: int
    callee_symbol_id: int
    target_symbol_name: str
    confidence: float
    provenance: str = "AGENT_INFERRED"
    reasoning: str = ""


class LinkerAgent:
    """Agent that resolves broken or dynamic dispatch edges using LLM inference and code context."""

    def __init__(
        self,
        llm_client: Any,
        db_manager: DatabaseManager,
        max_turns: int = 2,
    ) -> None:
        self.llm = llm_client
        self.db = db_manager
        self.max_turns = min(max_turns, 2)  # Circuit breaker: max 2 turns per edge

    def resolve_and_persist(
        self,
        caller_symbol_id: int,
        target_interface: str,
        file_path: str,
    ) -> Optional[InferredEdge]:
        """Infer target symbol implementation and persist edge directly to graph_edges."""
        prompt = (
            f"You are a code property graph linker agent. Resolve the dynamic dispatch callsite:\n"
            f"Caller Symbol ID: {caller_symbol_id}\n"
            f"Target Interface / Method: {target_interface}\n"
            f"Source File: {file_path}\n\n"
            f"Output JSON with keys: 'target_symbol', 'confidence' (0.0-1.0), and 'reasoning'."
        )

        for _ in range(self.max_turns):
            try:
                resp = self.llm.complete(prompt)
                raw_text = resp.get("text", "") if isinstance(resp, dict) else str(resp)

                # Extract JSON block
                json_match = re.search(r"\{.*?\}", raw_text, re.DOTALL)
                if not json_match:
                    continue

                parsed = json.loads(json_match.group(0))
                target_symbol = parsed.get("target_symbol")
                confidence = float(parsed.get("confidence", 0.0))
                reasoning = parsed.get("reasoning", "")

                if not target_symbol or confidence <= 0.0:
                    continue

                # Query database for target symbol
                target_sym_record = self.db.get_symbol_by_name(target_symbol)
                if not target_sym_record:
                    continue

                callee_symbol_id = int(target_sym_record["symbol_id"])

                # Persist inferred edge to SQLite
                self.db.insert_graph_edge(
                    caller_symbol_id=caller_symbol_id,
                    callee_symbol_id=callee_symbol_id,
                    edge_type="DYNAMIC_DISPATCH",
                    provenance="AGENT_INFERRED",
                    confidence=confidence,
                    metadata={"reasoning": reasoning, "target_interface": target_interface},
                )

                return InferredEdge(
                    caller_symbol_id=caller_symbol_id,
                    callee_symbol_id=callee_symbol_id,
                    target_symbol_name=target_symbol,
                    confidence=confidence,
                    provenance="AGENT_INFERRED",
                    reasoning=reasoning,
                )
            except Exception:
                continue

        return None
