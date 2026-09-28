"""Graph JSON exporter serializing Code Property Graph into structured JSON format."""

from typing import Any, Dict, List, Optional

from src.storage.db import DatabaseManager


class GraphJSONExporter:
    """Exports persistent repository graph nodes and edges to standard JSON."""

    def export(
        self,
        db: DatabaseManager,
        scope: str = "repository",
        symbol_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Query repository graph from SQLite with optional scope filtering."""
        nodes: List[Dict[str, Any]] = []
        edges: List[Dict[str, Any]] = []

        with db._get_connection() as conn:
            # Symbols
            if scope == "symbol" and symbol_name:
                sym_rows = conn.execute(
                    "SELECT * FROM symbols WHERE name = ?;", (symbol_name,)
                ).fetchall()
            else:
                sym_rows = conn.execute("SELECT * FROM symbols;").fetchall()
            for r in sym_rows:
                nodes.append(
                    {
                        "id": f"sym_{r['symbol_id']}",
                        "kind": "SYMBOL",
                        "symbol_kind": r["kind"],
                        "name": r["name"],
                        "file_id": r["file_id"],
                        "start_line": r["start_line"],
                        "end_line": r["end_line"],
                        "signature": r["signature"],
                    }
                )

            # Endpoints
            ep_rows = conn.execute("SELECT * FROM endpoints;").fetchall()
            for r in ep_rows:
                nodes.append(
                    {
                        "id": f"ep_{r['endpoint_id']}",
                        "kind": "ENDPOINT",
                        "method": r["http_method"],
                        "route": r["route_pattern"],
                        "file_id": r["file_id"],
                        "line": r["line_number"],
                    }
                )

            # Sinks
            sink_rows = conn.execute("SELECT * FROM candidate_sinks;").fetchall()
            for r in sink_rows:
                sev = (
                    r["triage_severity"]
                    if "triage_severity" in r.keys()
                    else r["severity"]
                )
                nodes.append(
                    {
                        "id": f"sink_{r['sink_id']}",
                        "kind": "SINK",
                        "vuln_class": r["vuln_class"],
                        "severity": sev,
                        "file_id": r["file_id"],
                        "line": r["line_number"],
                        "expression": r["sink_expression"],
                    }
                )

            # Graph Edges with active evidence
            query = """
                SELECT e.*,
                       COALESCE(ev.resolution_method, 'DETERMINISTIC') as provenance,
                       COALESCE(ev.confidence, 1.0) as confidence
                FROM graph_edges e
                LEFT JOIN graph_edge_evidence ev ON e.edge_id = ev.edge_id AND ev.is_active = 1;
            """
            edge_rows = conn.execute(query).fetchall()
            for r in edge_rows:
                edges.append(
                    {
                        "caller_symbol_id": r["caller_symbol_id"],
                        "callee_symbol_id": r["callee_symbol_id"],
                        "edge_type": r["edge_type"],
                        "provenance": r["provenance"],
                        "confidence": float(r["confidence"]),
                    }
                )

        return {"nodes": nodes, "edges": edges}
