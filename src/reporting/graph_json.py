"""Graph JSON exporter serializing Code Property Graph into structured JSON format."""

import json
from typing import Any, Dict, List, Optional

from src.storage.db import DatabaseManager


class GraphJSONExporter:
    """Exports persistent repository graph nodes and edges to standard JSON."""

    def export(
        self,
        db: DatabaseManager,
        scope: str = "repository",
        symbol_name: Optional[str] = None,
        finding_id: Optional[str] = None,
        endpoint_route: Optional[str] = None,
        path_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Query repository graph from SQLite with optional scope filtering."""
        nodes: List[Dict[str, Any]] = []
        edges: List[Dict[str, Any]] = []

        with db._get_connection() as conn:
            # 1. Finding scope
            if scope == "finding" and finding_id:
                row = conn.execute(
                    "SELECT source_trace_json, title FROM scan_dossiers WHERE dossier_id = ?;",
                    (finding_id,),
                ).fetchone()
                if row:
                    trace = json.loads(row["source_trace_json"])
                    for idx, step in enumerate(trace, start=1):
                        nodes.append(
                            {
                                "id": f"trace_{idx}",
                                "kind": "TRACE_NODE",
                                "file": step.get("file", ""),
                                "line": step.get("line", 1),
                                "finding_title": row["title"],
                            }
                        )
                return {"nodes": nodes, "edges": []}

            # 2. Path scope
            if scope == "path" and path_id:
                query_path = (
                    "SELECT call_sequence_json, endpoint_id, sink_id "
                    "FROM scan_candidate_paths WHERE path_id = ?;"
                )
                row = conn.execute(query_path, (path_id,)).fetchone()
                if row:
                    seq = json.loads(row["call_sequence_json"])
                    for idx, item in enumerate(seq, start=1):
                        nodes.append(
                            {
                                "id": f"path_step_{idx}",
                                "kind": "PATH_STEP",
                                "node_reference": str(item),
                                "path_id": path_id,
                            }
                        )
                return {"nodes": nodes, "edges": []}

            # 3. Endpoint scope
            if scope == "endpoint" and endpoint_route:
                ep_rows = conn.execute(
                    "SELECT * FROM endpoints WHERE route_pattern = ?;",
                    (endpoint_route,),
                ).fetchall()
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
                return {"nodes": nodes, "edges": []}

            # 4. Symbol scope or full repository scope
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
