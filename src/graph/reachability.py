"""Reachability analyzer traversing CodePropertyGraph with cycle pruning."""

from dataclasses import dataclass, field
from typing import Any, Dict, List

from src.graph.cpg import CodePropertyGraph


@dataclass
class CandidatePath:
    """A directed reachability path from entrypoint to candidate vulnerability sink."""

    source: str
    target: str
    nodes: List[str]
    hop_count: int
    confidence: float = 1.0
    reachability_confidence: float = 1.0
    edges: List[Dict[str, Any]] = field(default_factory=list)


class ReachabilityAnalyzer:
    """Finds cross-file deterministic reachability paths with state-aware cycle pruning."""

    def __init__(self, cpg: CodePropertyGraph) -> None:
        self.cpg = cpg

    def find_paths(
        self,
        source: str,
        target: str,
        max_hops: int = 20,
    ) -> List[CandidatePath]:
        """Search all paths from source to target within max_hops using bounded confidence."""
        if source not in self.cpg.graph or target not in self.cpg.graph:
            return []

        results: List[CandidatePath] = []

        def dfs(
            curr: str,
            path: List[str],
            edge_list: List[Dict[str, Any]],
            visited_states: set,
            analysis_state: str = "TAINTED",
        ):
            if curr == target:
                confidences = [float(e.get("confidence", 1.0)) for e in edge_list]
                # Bounded weakest-link confidence aggregation
                weakest_link = min(confidences) if confidences else 1.0
                results.append(
                    CandidatePath(
                        source=source,
                        target=target,
                        nodes=list(path),
                        hop_count=len(path) - 1,
                        confidence=weakest_link,
                        reachability_confidence=weakest_link,
                        edges=list(edge_list),
                    )
                )
                return

            if len(path) - 1 >= max_hops:
                # Circuit breaker depth cutoff
                return

            for neighbor in self.cpg.graph.successors(curr):
                edge_data = self.cpg.graph.get_edge_data(curr, neighbor) or {}
                edge_type = edge_data.get("edge_type", "CALL")
                state_key = (neighbor, edge_type, analysis_state)

                if state_key in visited_states or neighbor in path:
                    # State-aware cycle detected - prune to prevent infinite loops
                    continue

                edge_conf = float(edge_data.get("confidence", 1.0))
                new_edge_record = {
                    "from": curr,
                    "to": neighbor,
                    "type": edge_type,
                    "confidence": edge_conf,
                    "resolution_method": edge_data.get("resolution_method", "DETERMINISTIC_AST"),
                }

                path.append(neighbor)
                edge_list.append(new_edge_record)
                visited_states.add(state_key)

                dfs(neighbor, path, edge_list, visited_states, analysis_state)

                visited_states.remove(state_key)
                edge_list.pop()
                path.pop()

        initial_state = ("source", "ENTRY", "TAINTED")
        dfs(source, [source], [], {initial_state}, "TAINTED")
        return results
