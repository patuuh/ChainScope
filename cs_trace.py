#!/usr/bin/env python3
"""Trace state variable reads/writes in a ChainScope knowledge graph."""
import json
import typer
import mcp_server

app = typer.Typer()


@app.command()
def trace(
    db: str = typer.Option("graph.db", help="Database path"),
    var: str = typer.Option(..., "--var", help="State variable label to trace"),
    show_callers: bool = typer.Option(False, "--show-callers", help="Show one level of callers"),
    max_matches: int = typer.Option(20, "--max-matches", help="Max matching variables to trace fully (0 = all)"),
    max_candidates: int = typer.Option(50, "--max-candidates", help="Max ambiguous candidates to show (0 = all)"),
    exclude_research: bool = typer.Option(False, "--exclude-research", help="Exclude research-mode nodes"),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    data = json.loads(mcp_server.cs_trace(
        var=var,
        db=db,
        show_callers=show_callers,
        exclude_research=exclude_research,
        max_matches=max_matches,
        max_candidates=max_candidates,
    ))

    if "error" in data:
        typer.echo(data["error"], err=True)
        raise typer.Exit(1)

    if json_output:
        typer.echo(json.dumps(data, indent=2))
        return

    var_node = data["variable"]
    writers = data.get("writers", [])
    readers = data.get("readers", [])

    typer.echo(
        f"State Variable: {var_node['label']} ({var_node['file']}) [scope={data.get('query_scope', 'all_sources')}]"
    )
    if data.get("truncated"):
        typer.echo(
            f"  Matches: {data.get('variable_matches')}/{data.get('variable_matches_total')} "
            f"(use --max-matches 0 for all)"
        )
    typer.echo(f"  Type: {var_node.get('signature', 'unknown')}")

    typer.echo(f"\n  Writers ({len(writers)}):")
    for w in writers:
        typer.echo(
            f"    {w['label']} ({w['file']}) [{w.get('visibility', '')}] <{w.get('source_context', 'production')}>"
        )
        if show_callers and w.get("callers"):
            for c in w["callers"]:
                typer.echo(
                    f"      ← called by {c['label']} ({c['file']}) <{c.get('source_context', 'production')}>"
                )

    typer.echo(f"\n  Readers ({len(readers)}):")
    for r in readers:
        typer.echo(
            f"    {r['label']} ({r['file']}) [{r.get('visibility', '')}] <{r.get('source_context', 'production')}>"
        )
        if show_callers and r.get("callers"):
            for c in r["callers"]:
                typer.echo(
                    f"      ← called by {c['label']} ({c['file']}) <{c.get('source_context', 'production')}>"
                )


if __name__ == "__main__":
    app()
