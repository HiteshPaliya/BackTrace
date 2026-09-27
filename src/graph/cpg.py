"""In-memory Code Property Graph wrapping NetworkX DiGraph synchronized with SQLite."""

from typing import Any, Dict

import networkx as nx

from src.storage.db import DatabaseManager


class CodePropertyGraph:
    """Directed Code Property Graph representing symbols, endpoints, sinks, and call flows."""

    def __init__(self) -> None:
        self.graph: nx.DiGraph = nx.DiGraph()

    def add_node(self, node_id: str, **attrs: Any) -> None:
        """Add a node with metadata attributes."""
        self.graph.add_node(node_id, **attrs)

    def add_edge(self, u: str, v: str, **attrs: Any) -> None:
        """Add a directed edge between nodes u and v."""
        self.graph.add_edge(u, v, **attrs)

    def get_node_data(self, node_id: str) -> Dict[str, Any]:
        """Get attributes for node_id."""
        return dict(self.graph.nodes.get(node_id, {}))

    def load_from_db(self, db: DatabaseManager) -> None:
        """Hydrate graph in-memory from SQLite persistent tables."""
        with db._get_connection() as conn:
            # 1. Load symbols
            sym_rows = conn.execute("SELECT * FROM symbols;").fetchall()
            for r in sym_rows:
                node_id = f"sym_{r['symbol_id']}"
                self.add_node(
                    node_id,
                    kind="SYMBOL",
                    symbol_kind=r["kind"],
                    name=r["name"],
                    file_id=r["file_id"],
                    start_line=r["start_line"],
                    end_line=r["end_line"],
                    signature=r["signature"],
                )

            # 2. Load endpoints
            ep_rows = conn.execute("SELECT * FROM endpoints;").fetchall()
            for r in ep_rows:
                node_id = f"ep_{r['endpoint_id']}"
                self.add_node(
                    node_id,
                    kind="ENDPOINT",
                    http_method=r["http_method"],
                    route=r["route_pattern"],
                    file_id=r["file_id"],
                    line_number=r["line_number"],
                )
                if r["handler_symbol_id"]:
                    self.add_edge(
                        node_id,
                        f"sym_{r['handler_symbol_id']}",
                        edge_type="HANDLER",
                        confidence=1.0,
                    )

            # 3. Load sinks
            sink_rows = conn.execute("SELECT * FROM candidate_sinks;").fetchall()
            for r in sink_rows:
                node_id = f"sink_{r['sink_id']}"
                self.add_node(
                    node_id,
                    kind="SINK",
                    vuln_class=r["vuln_class"],
                    severity=r["severity"],
                    file_id=r["file_id"],
                    line_number=r["line_number"],
                    sink_expr=r["sink_expression"],
                )
                if r["symbol_id"]:
                    self.add_edge(
                        f"sym_{r['symbol_id']}",
                        node_id,
                        edge_type="CONTAINS_SINK",
                        confidence=1.0,
                    )

            # 4. Load edges
            edge_rows = conn.execute("SELECT * FROM graph_edges;").fetchall()
            for r in edge_rows:
                u = f"sym_{r['caller_symbol_id']}"
                v = f"sym_{r['callee_symbol_id']}"
                self.add_edge(
                    u,
                    v,
                    edge_type=r["edge_type"],
                    provenance=r["provenance"],
                    confidence=float(r["confidence"]),
                )
