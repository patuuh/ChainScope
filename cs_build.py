#!/usr/bin/env python3
"""Build a ChainScope knowledge graph from a source repository."""
import sys
import time
import typer
from pathlib import Path

app = typer.Typer()


@app.command()
def build(
    repo_path: str = typer.Argument(..., help="Path to source repository"),
    db: str = typer.Option("graph.db", help="Output database path"),
    lang: str = typer.Option(None, help="Override detection (solidity/vyper/move/clarity/cairo/sway/ton/proto/xdr/anchor/substrate/soroban/cpp/rust/go/java/typescript/python)"),
    include_research: bool = typer.Option(False, help="Include scripts/poc/fuzz/invariant/certora research artifacts"),
    timeout_seconds: int = typer.Option(0, help="Stop indexing after N seconds and write a partial graph (0 disables)"),
    codeql: bool = typer.Option(False, help="Enable CodeQL taint analysis"),
    build_cmd: str = typer.Option(None, "--build", help="Build command for CodeQL"),
):
    repo = Path(repo_path)
    if not repo.is_dir():
        typer.echo(f"Error: {repo_path} is not a directory", err=True)
        raise typer.Exit(1)

    from core.indexer import Indexer
    indexer = Indexer(str(repo), lang_override=lang, include_research=include_research)
    deadline = time.monotonic() + timeout_seconds if timeout_seconds > 0 else None
    stats = indexer.index(db, deadline=deadline)

    typer.echo(
        f"Built graph: {stats['nodes']} nodes, {stats['edges']} edges, "
        f"{stats['transitions']} transitions, {stats['files_indexed']}/{stats['files_considered']} files indexed"
    )
    if stats.get("timed_out"):
        typer.echo(f"Build stopped at timeout_seconds={timeout_seconds}; graph is partial", err=True)
    typer.echo(f"Chain: {indexer.detected_chain}")
    typer.echo(f"Research mode: {include_research}")
    typer.echo(f"Database: {db}")
    typer.echo(
        f"Confidence: {stats['confidence']['score']} ({stats['confidence']['tier']}); "
        f"extractor failures={stats['extractor_failures']}"
    )
    if stats["failure_examples"]:
        typer.echo(f"Failure examples: {stats['failure_examples'][:5]}")

    if codeql:
        try:
            from core.codeql_bridge import CodeQLBridge
            bridge = CodeQLBridge(str(repo), db)
            codeql_stats = bridge.run(build_cmd)
            typer.echo(f"CodeQL: {codeql_stats['edges_added']} taint edges added")
        except Exception as e:
            typer.echo(f"CodeQL skipped: {e}", err=True)


if __name__ == "__main__":
    app()
