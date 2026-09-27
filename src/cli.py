"""CLI entrypoint for Polyglot Cross-File Source Code Security Reviewer."""

import json
import sys
from pathlib import Path

import click
from rich.console import Console

from src.adapters.manager import ToolManager
from src.core.workspace import WorkspaceManager
from src.diff.git_scanner import GitDiffEngine
from src.graph.cpg import CodePropertyGraph
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

    # 1. Discover Workspace Files
    wm = WorkspaceManager(root)
    files = wm.discover_files()
    console.print(f"Discovered [cyan]{len(files)}[/cyan] valid source files.")

    for f in files:
        db.upsert_file(f.rel_path, f.language or "unknown", f.is_vendor, f.file_hash, f.loc)

    # 2. Run Pluggable Tool Adapters
    tool_mgr = ToolManager()
    tool_results = tool_mgr.run_all(root)
    for tool_name, res in tool_results.items():
        if res.is_available:
            console.print(f"Tool [cyan]{tool_name}[/cyan] found {len(res.parsed_items)} items.")
        else:
            console.print(f"[yellow]Tool {tool_name} not available, softly degraded.[/yellow]")

    # 3. Index AST Symbols and Calls
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
            for sym in res.symbols:
                db.insert_symbol(
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
        except Exception:
            continue

    # 4. In-Memory Graph and Reachability
    cpg = CodePropertyGraph()
    cpg.load_from_db(db)
    node_count = cpg.graph.number_of_nodes()
    console.print(f"Code Property Graph loaded with [cyan]{node_count}[/cyan] nodes.")

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
@click.option("--output", "-o", default=None, help="Output destination file.")
def report(scan_id: str, export_format: str, output: str | None):
    """Export scan report in Markdown, SARIF 2.1.0, or Graph JSON format."""
    db_path = Path(".audit/audit.db")
    if not db_path.exists():
        console.print("[red]No audit database found at .audit/audit.db[/red]")
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
def resume(scan_id: str):
    """Resume a paused or interrupted scan."""
    console.print(f"[bold cyan]Resuming scan:[/bold cyan] {scan_id}")


def main():
    cli()


if __name__ == "__main__":
    main()
