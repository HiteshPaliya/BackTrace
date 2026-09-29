"""CLI entrypoint for Polyglot Cross-File Source Code Security Reviewer."""

import json
import sys
from pathlib import Path
from typing import Optional

import click
from rich.console import Console

from src.adapters.manager import ToolManager
from src.core.workspace import WorkspaceManager
from src.diff.git_scanner import GitDiffEngine
from src.graph.cpg import CodePropertyGraph
from src.graph.reachability import ReachabilityAnalyzer
from src.indexer.treesitter import TreeSitterIndexer
from src.reporting.graph_json import GraphJSONExporter
from src.reporting.markdown import MarkdownExporter
from src.reporting.sarif import SARIFExporter
from src.storage.db import DatabaseManager
from src.storage.events import EventLogger

console = Console()


@click.group()
def cli():
    """Polyglot Cross-File Source Code Security Reviewer."""
    pass


@cli.command()
@click.argument("target_path", default=".", type=click.Path(exists=True))
@click.option("--workers", default=4, help="Parallel indexing workers.")
@click.option("--model", default="gemini-3.8-flash", help="LLM model identifier.")
def scan(target_path: str, workers: int, model: str):
    """Execute full repository source code security review."""
    root = Path(target_path).resolve()
    audit_dir = root / ".audit"
    db = DatabaseManager(audit_dir / "audit.db")
    db.init_schema()

    config = {"workers": workers, "model": model, "mode": "FULL"}
    diff_engine = GitDiffEngine(root, db)
    fingerprint = diff_engine.compute_engine_fingerprint(config)

    scan_id = db.create_scan(str(root), "FULL", engine_fingerprint=fingerprint, config=config)
    event_logger = EventLogger(audit_dir / "events.jsonl", scan_id=scan_id)
    event_logger.log("CLI", "SCAN_STARTED", {"target_path": str(root), "scan_id": scan_id})

    console.print(f"[bold green]Started Scan:[/bold green] {scan_id}")

    # 1. Discover Workspace Files & Classify Scope
    wm = WorkspaceManager(root)
    files = wm.discover_files()
    console.print(f"Discovered [cyan]{len(files)}[/cyan] valid source files.")

    from src.core.scope import ScopeClassifier

    classifier = ScopeClassifier()
    file_map = {}
    for f in files:
        meta = classifier.classify(f)
        f_id = db.upsert_file(
            f.rel_path,
            f.language or "unknown",
            f.is_vendor,
            f.file_hash,
            f.loc,
            execution_domain=meta.execution_domain.value,
            runtime_role=meta.runtime_role.value,
            environment=meta.environment.value,
            artifact_type=meta.artifact_type,
            classification_confidence=meta.confidence,
            classification_evidence=meta.evidence,
        )
        file_map[f.rel_path.replace("\\", "/")] = f_id

    # 2. Framework Semantic Resolvers
    from src.frameworks.detector import FrameworkDetector
    from src.frameworks.express import ExpressResolver

    detector = FrameworkDetector(root)
    fw = detector.identify()
    if fw == "express":
        resolver = ExpressResolver(root)
        endpoints = resolver.resolve_endpoints()
        ep_count = len(endpoints)
        console.print(f"Framework resolver mapped [cyan]{ep_count}[/cyan] endpoints.")
        for ep in endpoints:
            f_id = file_map.get(ep.file_path)
            if not f_id:
                f_id = db.upsert_file(ep.file_path, "javascript", False, "fw", 1)
                file_map[ep.file_path] = f_id
            db.insert_endpoint(
                file_id=f_id,
                http_method=ep.http_method,
                route_pattern=ep.route_pattern,
                line_number=ep.line_number,
                tool_provenance="FrameworkResolver",
                auth_required=(ep.auth_state == "REQUIRED"),
                parameters=[],
            )

    # 3. Built-in Semantic Detectors (Track A & Track B)
    from src.semantic.authz import AuthorizationAnalyzer
    from src.semantic.detector import SemanticDetector

    sem_detector = SemanticDetector()
    authz_analyzer = AuthorizationAnalyzer()

    for f in files:
        if f.is_vendor:
            continue
        try:
            code = Path(f.abs_path).read_text(encoding="utf-8", errors="replace")
            f_id = file_map.get(f.rel_path.replace("\\", "/"))
            if not f_id:
                continue

            # Track A: Semantic Sinks
            findings = sem_detector.scan_source(f.rel_path, code, f.language or "")
            for s in findings.sinks:
                # Invariant 3: Scope-Gated Detector Eligibility
                if not classifier.eligible_for_detector(f, s.vuln_class):
                    continue

                db.insert_candidate_sink(
                    file_id=f_id,
                    vuln_class=s.vuln_class,
                    triage_severity=s.triage_severity,
                    line_number=s.line_number,
                    sink_expression=s.expression,
                    raw_rule_id=f"semantic.{s.vuln_class.lower()}",
                    tool_provenance="SemanticAST",
                    cwe_id=s.cwe_id,
                )

            # Track B: AuthZ Gaps (BOLA/IDOR)
            if any(part in f.rel_path.lower() for part in ["route", "controller", "server", "app"]):
                authz_res = authz_analyzer.analyze_handler(
                    "GET", f.rel_path, code, f.language or "javascript"
                )
                if authz_res.has_gap:
                    db.insert_candidate_sink(
                        file_id=f_id,
                        vuln_class="BOLA_IDOR",
                        triage_severity="HIGH",
                        line_number=1,
                        sink_expression=authz_res.retrieval_op or "Unscoped query",
                        raw_rule_id="semantic.authz.gap",
                        tool_provenance="AuthzAnalyzer",
                        cwe_id="CWE-639",
                    )
        except Exception:
            continue

    # 4. Run Pluggable Tool Adapters & Persist Corroborating Evidence
    tool_mgr = ToolManager()
    tool_results = tool_mgr.run_all(root)
    for tool_name, res in tool_results.items():
        if res.is_available:
            console.print(f"Tool [cyan]{tool_name}[/cyan] found {len(res.parsed_items)} items.")
            for item in res.parsed_items:
                rel = item.get("rel_path", "").replace("\\", "/")
                file_id = file_map.get(rel)
                if not file_id:
                    file_id = db.upsert_file(rel, "unknown", False, "unknown", 1)
                    file_map[rel] = file_id

                f_obj = next(
                    (f for f in files if f.rel_path.replace("\\", "/") == rel), None
                )
                if f_obj and not classifier.eligible_for_detector(
                    f_obj, item.get("vuln_class", "")
                ):
                    continue

                if tool_name == "noir":
                    db.insert_endpoint(
                        file_id=file_id,
                        http_method=item.get("http_method", "GET"),
                        route_pattern=item.get("route_pattern", "/"),
                        line_number=item.get("line_number", 1),
                        tool_provenance="Noir",
                        auth_required=item.get("auth_required", False),
                        parameters=item.get("parameters"),
                    )
                elif tool_name == "semgrep":
                    db.insert_candidate_sink(
                        file_id=file_id,
                        vuln_class=item.get("vuln_class", "GENERAL_VULN"),
                        triage_severity=item.get("severity", "MEDIUM"),
                        line_number=item.get("line_number", 1),
                        sink_expression=item.get("sink_expression", ""),
                        raw_rule_id=item.get("raw_rule_id", "semgrep.rule"),
                        tool_provenance="Semgrep",
                        cwe_id=item.get("cwe_id"),
                    )
        else:
            console.print(f"[yellow]Tool {tool_name} not available, softly degraded.[/yellow]")

    # 5. Index AST Symbols and Calls
    indexer = TreeSitterIndexer()
    for f in files:
        if f.is_vendor:
            continue
        try:
            code = Path(f.abs_path).read_text(encoding="utf-8", errors="replace")
            res = indexer.index_source(f.rel_path, code, f.language)
            file_rec = db.upsert_file(
                f.rel_path, f.language or "unknown", f.is_vendor, f.file_hash, f.loc
            )
            created_symbols = {}
            for sym in res.symbols:
                sym_id = db.insert_symbol(
                    file_rec,
                    sym.name,
                    sym.kind,
                    sym.start_line,
                    sym.start_col,
                    sym.end_line,
                    sym.end_col,
                    sym.signature,
                    sym.scope,
                )
                created_symbols[sym.name] = sym_id

            for call in res.calls:
                caller_name = call.caller_scope.split(".")[-1] if call.caller_scope else None
                caller_id = created_symbols.get(caller_name)
                callee_id = created_symbols.get(call.callee_name)
                if caller_id and callee_id and caller_id != callee_id:
                    db.insert_graph_edge(
                        caller_symbol_id=caller_id,
                        callee_symbol_id=callee_id,
                        edge_type="CALL",
                        provenance="DETERMINISTIC",
                        confidence=1.0,
                    )
        except Exception:
            continue

    # 4. In-Memory Graph and Reachability
    cpg = CodePropertyGraph()
    cpg.load_from_db(db)
    node_count = cpg.graph.number_of_nodes()
    console.print(f"Code Property Graph loaded with [cyan]{node_count}[/cyan] nodes.")

    # 6. Synthesize Dossiers from Candidate Sinks & Paths
    from src.agents.verifier import EvidenceBundle, EvidenceGateVerifier
    from src.reporting.synthesizer import DossierSynthesizer

    synthesizer = DossierSynthesizer()
    verifier = EvidenceGateVerifier()
    reachability_analyzer = ReachabilityAnalyzer(cpg)

    with db._get_connection() as conn:
        sinks = conn.execute(
            """
            SELECT s.*, f.rel_path
            FROM candidate_sinks s
            JOIN files f ON s.file_id = f.file_id;
            """
        ).fetchall()
        endpoints = conn.execute("SELECT * FROM endpoints;").fetchall()

    if sinks:
        console.print(f"Synthesizing dossiers for [cyan]{len(sinks)}[/cyan] candidate sinks...")
        for s in sinks:
            sev = (
                s["triage_severity"]
                if "triage_severity" in s.keys()
                else s.get("severity", "MEDIUM")
            )
            path_id = f"path_{scan_id}_{s['sink_id']}"
            source_trace = [{"file": s["rel_path"], "line": s["line_number"]}]

            matching_ep = None
            proven_path = None
            sink_cpg_id = f"sink_{s['sink_id']}"

            # Invariant 4: Proof-based endpoint reachability via CPG
            for ep in endpoints:
                ep_cpg_id = f"ep_{ep['endpoint_id']}"
                found_paths = reachability_analyzer.find_paths(
                    ep_cpg_id, sink_cpg_id, max_hops=20
                )
                if found_paths:
                    matching_ep = ep
                    proven_path = found_paths[0]
                    break
                if ep["file_id"] == s["file_id"]:
                    matching_ep = ep
                    break

            # Invariant 7: Evidence-gated verifier bundle
            if matching_ep:
                ep_method = matching_ep["http_method"]
                ep_route = matching_ep["route_pattern"]
                auth_state = (
                    matching_ep["auth_state"]
                    if "auth_state" in matching_ep.keys()
                    else "NOT_REQUIRED"
                )
                reach_conf = proven_path.reachability_confidence if proven_path else 0.85
                ev_bundle = EvidenceBundle(
                    source_node={"method": ep_method, "route": ep_route},
                    path_trace=proven_path.nodes if proven_path else source_trace,
                    sink_node={
                        "vuln_class": s["vuln_class"],
                        "expression": s["sink_expression"],
                    },
                    auth_state=auth_state,
                    reachability_confidence=reach_conf,
                    bypass_reasoning=(
                        f"Tainted input reaches {s['vuln_class']} sink: "
                        f"{s['sink_expression'][:80]}"
                    ),
                )
            else:
                ep_method = None
                ep_route = None
                auth_state = "UNKNOWN"
                reach_conf = 0.0
                ev_bundle = EvidenceBundle(
                    source_node=None,
                    path_trace=None,
                    sink_node={
                        "vuln_class": s["vuln_class"],
                        "expression": s["sink_expression"],
                    },
                    auth_state="UNKNOWN",
                    reachability_confidence=0.0,
                    bypass_reasoning="No CPG reachability path proven from route to sink",
                )

            v_res = verifier.evaluate_contract(evidence_bundle=ev_bundle)

            # Invariant 4 & Invariant 8: Non-weaponized blueprint or NONE
            if matching_ep:
                param_name = (
                    "url"
                    if s["vuln_class"] == "SSRF"
                    else ("id" if s["vuln_class"] == "BOLA_IDOR" else "q")
                )
                blueprint = synthesizer.generate_reproduction_template(
                    endpoint_method=ep_method,
                    route_pattern=ep_route,
                    auth_state=auth_state,
                    tainted_param={
                        "location": "QUERY" if ep_method == "GET" else "BODY",
                        "name": param_name,
                    },
                    sink_target=s["sink_expression"][:50],
                )
                repro_curl = blueprint["curl_command"]
            else:
                blueprint = {
                    "reproduction_type": "NONE",
                    "expected_assertion": {
                        "assertion_type": "INTERNAL_UNEXPOSED_SINK",
                        "description": "Internal sink with no proven external HTTP route",
                    },
                }
                repro_curl = None

            norm_ep_str = f"{ep_method} {ep_route}" if ep_method else "N/A"
            finding_fp = db.compute_finding_fingerprint(
                schema_version=1,
                vuln_class=s["vuln_class"],
                norm_endpoint=norm_ep_str,
                norm_source="req.input" if matching_ep else "internal",
                norm_sink=s["raw_rule_id"],
                norm_path=f"{s['rel_path']}:{s['line_number']}",
            )

            if s["vuln_class"] == "BOLA_IDOR":
                title = (
                    f"BOLA / IDOR in {s['sink_expression']} "
                    f"({Path(s['rel_path']).name}:{s['line_number']})"
                )
            else:
                title = f"{s['vuln_class']} in {Path(s['rel_path']).name}:{s['line_number']}"
            db.record_candidate_path(
                path_id=path_id,
                scan_id=scan_id,
                sink_id=s["sink_id"],
                hop_count=1,
                call_sequence=[s["sink_id"]],
                priority_score=0.9 if sev in ("CRITICAL", "HIGH") else 0.5,
                reachability_confidence=reach_conf,
            )

            db.record_dossier(
                dossier_id=f"dos_{scan_id[:8]}_{s['sink_id']}",
                scan_id=scan_id,
                path_id=path_id,
                engine_fingerprint=fingerprint,
                title=title,
                vuln_class=s["vuln_class"],
                severity=sev,
                cwe_id=s["cwe_id"] or "CWE-Unknown",
                verdict=v_res.verdict.value,
                reachability_confidence=v_res.reachability_confidence,
                exploitability_confidence=v_res.exploitability_confidence,
                confidence=v_res.confidence,
                source_trace=source_trace,
                sanitizer_analysis={"bypass_reasoning": v_res.bypass_reasoning},
                evidence_bundle=v_res.evidence_bundle,
                finding_fingerprint=finding_fp,
                fingerprint_schema_version=1,
                repro_curl_template=repro_curl,
                repro_template=blueprint,
                mitigation_notes=(
                    f"Sanitize and validate untrusted input before "
                    f"{s['vuln_class']} sink."
                ),
            )

    db.update_scan_status(scan_id, "COMPLETED", {"files_indexed": len(files)})
    event_logger.log("CLI", "PATH_TRANSITION", {"status": "COMPLETED"})
    console.print(f"[bold green]Scan completed successfully:[/bold green] {scan_id}")


@cli.command()
@click.argument("target_path", default=".", type=click.Path(exists=True))
@click.option("--base", default="HEAD", help="Base git ref for diff.")
def diff(target_path: str, base: str):
    """Execute incremental scan evaluating working tree and untracked files."""
    root = Path(target_path).resolve()
    db = DatabaseManager(root / ".audit" / "audit.db")
    db.init_schema()

    diff_engine = GitDiffEngine(root, db)
    plan = diff_engine.compute_impact(base_ref=base, current_config={"mode": "DIFF"})

    console.print(f"Changed files: [yellow]{len(plan.changed_files)}[/yellow]")
    console.print(f"Reusable dossiers: [green]{len(plan.reusable_dossier_ids)}[/green]")


@cli.command()
@click.option("--scan-id", required=True, help="Scan ID to export.")
@click.option(
    "--format",
    "export_format",
    type=click.Choice(["md", "sarif", "graph"]),
    default="md",
    help="Export format.",
)
@click.option(
    "--target",
    default=None,
    help="Target repository directory or database path containing .audit/audit.db.",
)
@click.option("--output", "-o", default=None, help="Output destination file.")
def report(scan_id: str, export_format: str, target: Optional[str], output: str | None):
    """Export scan report in Markdown, SARIF 2.1.0, or Graph JSON format."""
    db_path: Optional[Path] = None

    if target:
        p = Path(target).resolve()
        if (p / ".audit" / "audit.db").exists():
            db_path = p / ".audit" / "audit.db"
        elif p.is_file():
            db_path = p

    if not db_path:
        # Check current directory
        if Path(".audit/audit.db").exists():
            db_path = Path(".audit/audit.db")
        else:
            # Search parent or test-area
            for candidate in Path(".").glob("**/audit.db"):
                db_path = candidate
                break

    if not db_path or not db_path.exists():
        console.print("[red]No audit database found. Specify --target <repo>[/red]")
        sys.exit(1)

    db = DatabaseManager(db_path)
    dossiers = db.get_scan_dossiers(scan_id)

    if export_format == "sarif":
        exporter = SARIFExporter()
        content = json.dumps(exporter.export(dossiers), indent=2)
    elif export_format == "graph":
        exporter = GraphJSONExporter()
        content = json.dumps(exporter.export(db), indent=2)
    else:
        exporter = MarkdownExporter()
        content = exporter.export(dossiers, scan_id=scan_id)

    if output:
        Path(output).write_text(content, encoding="utf-8")
        console.print(f"[green]Report written to {output}[/green]")
    else:
        click.echo(content)


@cli.command()
@click.argument("scan_id")
@click.option(
    "--target",
    default=None,
    help="Target repository directory or database path containing .audit/audit.db.",
)
def resume(scan_id: str, target: Optional[str] = None):
    """Resume a paused or interrupted scan."""
    db_path: Optional[Path] = None
    if target:
        p = Path(target).resolve()
        if (p / ".audit" / "audit.db").exists():
            db_path = p / ".audit" / "audit.db"
        elif p.is_file():
            db_path = p

    if not db_path:
        if Path(".audit/audit.db").exists():
            db_path = Path(".audit/audit.db")
        else:
            for candidate in Path(".").glob("**/audit.db"):
                db_path = candidate
                break

    if not db_path or not db_path.exists():
        console.print("[red]No audit database found[/red]")
        sys.exit(1)

    db = DatabaseManager(db_path)
    console.print(f"[bold cyan]Resuming scan:[/bold cyan] {scan_id}")

    with db._get_connection() as conn:
        paths = conn.execute(
            """
            SELECT p.*, s.vuln_class, s.sink_expression, s.raw_rule_id,
                   s.triage_severity, f.rel_path
            FROM scan_candidate_paths p
            JOIN candidate_sinks s ON p.sink_id = s.sink_id
            JOIN files f ON s.file_id = f.file_id
            WHERE p.scan_id = ? AND p.state IN ('QUEUED', 'UNRESOLVED', 'RUNNING');
            """,
            (scan_id,),
        ).fetchall()

    if not paths:
        console.print(f"[green]Scan {scan_id} is already complete; no pending paths.[/green]")
        db.update_scan_status(scan_id, "COMPLETED")
        return

    cpg = CodePropertyGraph()
    cpg.load_from_db(db)
    analyzer = ReachabilityAnalyzer(cpg)
    from src.agents.verifier import EvidenceBundle, EvidenceGateVerifier
    from src.reporting.synthesizer import DossierSynthesizer

    verifier = EvidenceGateVerifier()
    synthesizer = DossierSynthesizer()

    with db._get_connection() as conn:
        scan_row = conn.execute("SELECT * FROM scans WHERE scan_id = ?;", (scan_id,)).fetchone()
        fingerprint = scan_row["engine_fingerprint"] if scan_row else "fp_resumed"
        endpoints = conn.execute("SELECT * FROM endpoints;").fetchall()

    for p in paths:
        path_id = p["path_id"]
        sink_id = p["sink_id"]

        matching_ep = None
        proven_path = None
        for ep in endpoints:
            f_paths = analyzer.find_paths(
                f"ep_{ep['endpoint_id']}", f"sink_{sink_id}", max_hops=20
            )
            if f_paths:
                matching_ep = ep
                proven_path = f_paths[0]
                break

        if matching_ep:
            ep_method = matching_ep["http_method"]
            ep_route = matching_ep["route_pattern"]
            reach_conf = proven_path.reachability_confidence if proven_path else 0.85
            ev_bundle = EvidenceBundle(
                source_node={"method": ep_method, "route": ep_route},
                path_trace=proven_path.nodes if proven_path else [{"file": p["rel_path"]}],
                sink_node={
                    "vuln_class": p["vuln_class"],
                    "expression": p["sink_expression"],
                },
                auth_state=matching_ep.get("auth_state", "NOT_REQUIRED"),
                reachability_confidence=reach_conf,
                bypass_reasoning=f"Resumed: Tainted input reaches {p['vuln_class']} sink",
            )
            blueprint = synthesizer.generate_reproduction_template(
                endpoint_method=ep_method,
                route_pattern=ep_route,
                auth_state=matching_ep.get("auth_state", "NOT_REQUIRED"),
                tainted_param={"location": "QUERY", "name": "q"},
                sink_target=p["sink_expression"][:50],
            )
            repro_curl = blueprint["curl_command"]
        else:
            ep_method = None
            ep_route = None
            reach_conf = 0.0
            ev_bundle = EvidenceBundle(
                source_node=None,
                path_trace=None,
                sink_node={
                    "vuln_class": p["vuln_class"],
                    "expression": p["sink_expression"],
                },
                auth_state="UNKNOWN",
                reachability_confidence=0.0,
                bypass_reasoning="Resumed: No CPG path proven",
            )
            blueprint = {"reproduction_type": "NONE"}
            repro_curl = None

        v_res = verifier.evaluate_contract(evidence_bundle=ev_bundle)
        norm_ep_str = f"{ep_method} {ep_route}" if ep_method else "N/A"
        finding_fp = db.compute_finding_fingerprint(
            schema_version=1,
            vuln_class=p["vuln_class"],
            norm_endpoint=norm_ep_str,
            norm_source="req.input" if matching_ep else "internal",
            norm_sink=p["raw_rule_id"],
            norm_path=p["rel_path"],
        )

        dossier_id = f"dos_{scan_id[:8]}_{sink_id}"
        with db.transaction() as conn:
            conn.execute(
                "UPDATE scan_candidate_paths SET state = 'RESOLVED', reachability_confidence = ? "
                "WHERE path_id = ?;",
                (reach_conf, path_id),
            )

        db.record_dossier(
            dossier_id=dossier_id,
            scan_id=scan_id,
            path_id=path_id,
            engine_fingerprint=fingerprint,
            title=f"{p['vuln_class']} in {Path(p['rel_path']).name}",
            vuln_class=p["vuln_class"],
            severity=p["triage_severity"],
            cwe_id="CWE-Unknown",
            verdict=v_res.verdict.value,
            reachability_confidence=v_res.reachability_confidence,
            exploitability_confidence=v_res.exploitability_confidence,
            confidence=v_res.confidence,
            source_trace=[{"file": p["rel_path"]}],
            sanitizer_analysis={"bypass_reasoning": v_res.bypass_reasoning},
            evidence_bundle=v_res.evidence_bundle,
            finding_fingerprint=finding_fp,
            fingerprint_schema_version=1,
            repro_curl_template=repro_curl,
            repro_template=blueprint,
            mitigation_notes=f"Sanitize input before {p['vuln_class']} sink.",
        )

    db.update_scan_status(scan_id, "COMPLETED")
    console.print(f"[bold green]Resumed scan completed successfully:[/bold green] {scan_id}")


def main():
    cli()


if __name__ == "__main__":
    main()
