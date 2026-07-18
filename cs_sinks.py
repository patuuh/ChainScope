#!/usr/bin/env python3
"""Map dangerous sinks and paths to them in a ChainScope knowledge graph."""
import json
import typer
import mcp_server

app = typer.Typer()


def _legacy_json_rows(result: dict) -> list[dict]:
    rows = []
    for sink in result.get("sinks", []):
        rows.append({
            "sink_id": sink["id"],
            "sink_label": sink["label"],
            "sink_type": sink["sink_type"],
            "file": sink["file"],
            "source_context": sink.get("source_context", "production"),
            "paths_from": [
                {
                    "caller": caller["label"],
                    "file": caller["file"],
                    "visibility": caller.get("visibility", ""),
                    "source_context": caller.get("source_context", "production"),
                    "distance": caller.get("distance", 1),
                }
                for caller in sink.get("callers", [])
            ],
        })
    return rows


@app.command()
def sinks(
    db: str = typer.Option("graph.db", help="Database path"),
    sink_type: str = typer.Option(None, "--type", help="Filter by sink type (fund_transfer/delegate/self_destruct/cpi_transfer)"),
    external_only: bool = typer.Option(False, "--external-only", help="Only show paths from external/public functions"),
    exclude_research: bool = typer.Option(False, "--exclude-research", help="Exclude research-mode nodes"),
    max_results: int = typer.Option(100, "--max-results", help="Max sinks to expand (0 = all)"),
    max_callers_per_sink: int = typer.Option(20, "--max-callers-per-sink", help="Max reachable callers per sink (0 = all)"),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    result = json.loads(mcp_server.cs_sinks(
        db=db,
        sink_type=sink_type or "",
        external_only=external_only,
        exclude_research=exclude_research,
        max_results=max_results,
        max_callers_per_sink=max_callers_per_sink,
    ))

    if "error" in result:
        typer.echo(result["error"], err=True)
        raise typer.Exit(1)

    if json_output:
        typer.echo(json.dumps(_legacy_json_rows(result), indent=2))
        return

    sinks_found = result.get("total", 0)
    if not sinks_found:
        typer.echo(f"No sinks found" + (f" of type '{sink_type}'" if sink_type else ""))
        return

    if result.get("truncated"):
        typer.echo(
            f"Sinks ({result['shown']}/{result['total']} shown, "
            f"scope={result['query_scope']}, use --max-results 0 for all):"
        )
    else:
        typer.echo(f"Sinks ({sinks_found} found, scope={result['query_scope']}):")

    if result.get("by_type"):
        counts = ", ".join(f"{name}={count}" for name, count in result["by_type"].items())
        typer.echo(f"Types: {counts}")

    for sink_info in result.get("sinks", []):
        typer.echo(
            f"\n  {sink_info['label']} [{sink_info['sink_type']}] "
            f"({sink_info['file']}) <{sink_info['source_context']}>"
        )
        callers = sink_info.get("callers", [])
        summary = sink_info.get("caller_summary", {})
        if callers:
            if summary.get("truncated"):
                typer.echo(
                    f"    callers: {summary['shown']}/{summary['total']} shown "
                    "(use --max-callers-per-sink 0 for all)"
                )
            for caller in callers:
                typer.echo(
                    f"    <- {caller['label']} ({caller['file']}) "
                    f"[{caller.get('visibility', '')}, distance={caller.get('distance', 1)}] "
                    f"<{caller.get('source_context', 'production')}>"
                )
        else:
            typer.echo("    (no reachable callers found)")


if __name__ == "__main__":
    app()
