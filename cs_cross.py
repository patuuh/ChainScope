#!/usr/bin/env python3
"""Identify cross-contract/cross-module calls in a ChainScope knowledge graph."""
import json
import typer
import mcp_server

app = typer.Typer()


@app.command()
def cross(
    db: str = typer.Option("graph.db", help="Database path"),
    external_calls: bool = typer.Option(False, "--external-calls", help="List all cross-contract calls"),
    from_func: str = typer.Option(None, "--from", help="Trace from a specific function"),
    max_depth: int = typer.Option(10, help="Max depth for tracing"),
    max_results: int = typer.Option(500, "--max-results", help="Max raw calls for cs_cross output (0 = all)"),
    summary: bool = typer.Option(False, "--summary", help="Show bounded cross-boundary summary"),
    top: int = typer.Option(50, "--top", help="Max sample calls for --summary"),
    max_counter_items: int = typer.Option(10, "--max-counter-items", help="Max source/target counters for --summary (0 = all)"),
    exclude_research: bool = typer.Option(False, "--exclude-research", help="Exclude research-mode nodes"),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    if not external_calls and not from_func and not summary:
        typer.echo("Specify --external-calls, --summary, or --from <function>", err=True)
        raise typer.Exit(1)

    if summary:
        result = json.loads(mcp_server.cs_cross_summary(
            db=db,
            from_func=from_func or "",
            top=top,
            max_counter_items=max_counter_items,
            exclude_research=exclude_research,
        ))
    else:
        result = json.loads(mcp_server.cs_cross(
            db=db,
            from_func=from_func or "",
            max_results=max_results,
            exclude_research=exclude_research,
        ))

    if isinstance(result, dict) and "error" in result:
        typer.echo(result["error"], err=True)
        raise typer.Exit(1)

    if json_output:
        typer.echo(json.dumps(result, indent=2, default=str))
        return

    if summary:
        typer.echo(
            f"Cross-boundary summary: {result['total']} calls "
            f"({result['shown']} shown, scope: {result['query_scope']})"
        )
        if result.get("by_attribute"):
            attrs = ", ".join(f"{name}={count}" for name, count in result["by_attribute"].items())
            typer.echo(f"Attributes: {attrs}")
        if result.get("top_source_files"):
            typer.echo("Top source files:")
            for item in result["top_source_files"]:
                typer.echo(f"  {item['file'] if 'file' in item else item['name']}: {item['calls']}")
            counter_summary = result.get("counter_summary", {})
            if counter_summary.get("truncated"):
                typer.echo("Counters capped; increase --max-counter-items for more.")
        if result.get("calls"):
            typer.echo("Sample calls:")
            for call in result["calls"]:
                attrs = call.get("attributes", {})
                interface = attrs.get("interface", "unknown")
                typer.echo(
                    f"  {call.get('source_label', '?')} → {call.get('target_label', '?')} "
                    f"(interface: {interface}, context: {call.get('source_context', 'production')})"
                )
        return

    if external_calls:
        cross_calls = result.get("calls", []) if isinstance(result, dict) else result
        if not cross_calls:
            typer.echo("No cross-contract calls found")
            return
        if isinstance(result, dict) and result.get("truncated"):
            typer.echo(
                f"Cross-contract calls ({result['shown']}/{result['total']} shown, "
                "use --max-results 0 for all):"
            )
        else:
            typer.echo(f"Cross-contract calls ({len(cross_calls)}):")
        for call in cross_calls:
            attrs = json.loads(call.get("attributes", "{}"))
            interface = attrs.get("interface", "unknown")
            ctx = call.get("source_context", "production")
            typer.echo(
                f"  {call.get('source_label', '?')} → {call.get('target_label', '?')} "
                f"(interface: {interface}, context: {ctx})"
            )
        return

    cross_boundary = result.get("calls", []) if isinstance(result, dict) else result
    typer.echo(f"Cross-contract calls reachable from '{from_func}':")
    if isinstance(result, dict) and result.get("truncated"):
        typer.echo(f"Showing {result['shown']}/{result['total']} calls; use --max-results 0 for all")
    for cb in cross_boundary:
        typer.echo(
            f"  {cb['source']['label']} → {cb['target']['label']} "
            f"({cb['source'].get('source_context', 'production')})"
        )


if __name__ == "__main__":
    app()
