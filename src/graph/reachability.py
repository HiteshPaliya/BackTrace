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
    edges: List[Dict[str, Any]] = field(default_factory=list)


class ReachabilityAnalyzer:
    """Finds cross-file deterministic reachability paths and prunes cycles."""

    def __init__(self, cpg: CodePropertyGraph) -> None:
        self.cpg = cpg

    def find_paths(
        self,
        source: str,
        target: str,
        max_hops: int = 20,
    ) -> List[CandidatePath]:
        """Search all simple paths from source to target within max_hops limit."""
        if source not in self.cpg.graph or target not in self.cpg.graph:
            return []

        results: List[CandidatePath] = []

        def dfs(curr: str, path: List[str], current_conf: float, edge_list: List[Dict[str, Any]]):
            if curr == target:
                results.append(
                    CandidatePath(
                        source=source,
                        target=target,
                        nodes=list(path),
                        hop_count=len(path) - 1,
                        confidence=current_conf,
                        edges=list(edge_list),
                    )
                )
                return

            if len(path) - 1 >= max_hops:
                # Circuit breaker depth cutoff
                return

            for neighbor in self.cpg.graph.successors(curr):
                if neighbor in path:
                    # Cycle detected - prune to prevent infinite loops
                    continue

                edge_data = self.cpg.graph.get_edge_data(curr, neighbor) or {}
                edge_conf = float(edge_data.get("confidence", 1.0))
                new_conf = current_conf * edge_conf
                new_edge_record = {
                    "from": curr,
                    "to": neighbor,
                    "type": edge_data.get("edge_type", "CALL"),
                    "confidence": edge_conf,
                }

                path.append(neighbor)
                edge_list.append(new_edge_record)
                dfs(neighbor, path, new_conf, edge_list)
                edge_list.pop()
                path.pop()

        dfs(source, [source], 1.0, [])
        return results
