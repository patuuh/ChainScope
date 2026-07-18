#!/usr/bin/env python3
"""Build a ChainScope knowledge graph from a source repository."""
import json
import typer
import mcp_server

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
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    data = json.loads(mcp_server.cs_build(
        repo_path=repo_path,
        db=db,
        lang=lang or "",
        include_research=include_research,
        timeout_seconds=timeout_seconds,
    ))

    if "error" in data:
        typer.echo(data["error"], err=True)
        raise typer.Exit(1)

    if codeql:
        try:
            from core.codeql_bridge import CodeQLBridge
            bridge = CodeQLBridge(repo_path, data["database"])
            codeql_stats = bridge.run(build_cmd)
            data["codeql"] = {
                "status": "success",
                "edges_added": codeql_stats["edges_added"],
            }
        except Exception as e:
            data["codeql"] = {
                "status": "skipped",
                "error": str(e),
            }

    if json_output:
        typer.echo(json.dumps(data, indent=2))
        return

    typer.echo(
        f"Built graph: {data['nodes']} nodes, {data['edges']} edges, "
        f"{data['transitions']} transitions, {data['files_indexed']}/{data['files_considered']} files indexed"
    )
    if data.get("timed_out"):
        typer.echo(f"Build stopped at timeout_seconds={timeout_seconds}; graph is partial", err=True)
    typer.echo(f"Chain: {data['chain']}")
    typer.echo(f"Research mode: {data['include_research']}")
    typer.echo(f"Database: {data['database']}")
    typer.echo(
        f"Confidence: {data['confidence']['score']} ({data['confidence']['tier']}); "
        f"extractor failures={data['extractor_failures']}"
    )
    if data["failure_examples"]:
        typer.echo(f"Failure examples: {data['failure_examples'][:5]}")
    if data.get("codeql"):
        if data["codeql"]["status"] == "success":
            typer.echo(f"CodeQL: {data['codeql']['edges_added']} taint edges added")
        else:
            typer.echo(f"CodeQL skipped: {data['codeql']['error']}", err=True)


if __name__ == "__main__":
    app()
