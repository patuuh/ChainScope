#!/usr/bin/env python3
"""Find paths between functions in a ChainScope knowledge graph."""
import json
import typer
import mcp_server

app = typer.Typer()


@app.command()
def paths(
    db: str = typer.Option("graph.db", help="Database path"),
    from_label: str = typer.Option(..., "--from", help="Source function label"),
    to_label: str = typer.Option(..., "--to", help="Target function label"),
    max_depth: int = typer.Option(15, help="Maximum path depth"),
    max_paths: int = typer.Option(10, help="Maximum paths to find"),
    max_endpoint_matches: int = typer.Option(20, "--max-endpoint-matches", help="Max matching start/end nodes to search (0 = all)"),
    max_endpoint_candidates: int = typer.Option(50, "--max-endpoint-candidates", help="Max ambiguous endpoint candidates to show (0 = all)"),
    max_guards_per_node: int = typer.Option(20, "--max-guards-per-node", help="Max guard labels per path node with --show-guards (0 = all)"),
    max_state_access_per_node: int = typer.Option(25, "--max-state-access-per-node", help="Max reads and writes per path node with --show-state (0 = all)"),
    show_guards: bool = typer.Option(False, "--show-guards", help="Show guards along path"),
    show_state: bool = typer.Option(False, "--show-state", help="Show state reads/writes"),
    exclude_research: bool = typer.Option(False, "--exclude-research", help="Exclude research-mode nodes"),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    result = json.loads(mcp_server.cs_paths(
        from_label=from_label,
        to_label=to_label,
        db=db,
        max_depth=max_depth,
        max_paths=max_paths,
        max_endpoint_matches=max_endpoint_matches,
        max_endpoint_candidates=max_endpoint_candidates,
        max_guards_per_node=max_guards_per_node,
        max_state_access_per_node=max_state_access_per_node,
        show_guards=show_guards,
        show_state=show_state,
        exclude_research=exclude_research,
    ))

    if "error" in result:
        typer.echo(result["error"], err=True)
        raise typer.Exit(1)

    if json_output:
        typer.echo(json.dumps(result, indent=2))
        return

    all_paths = result.get("paths", [])
    if not all_paths:
        typer.echo(f"No path found from '{from_label}' to '{to_label}' (max_depth={max_depth})")
        return

    typer.echo(
        f"Paths from '{from_label}' to '{to_label}' ({len(all_paths)} found, scope={result.get('query_scope', 'all_sources')}):"
    )
    summary = result.get("_summary", {})
    if summary.get("truncated"):
        typer.echo(
            f"Search capped: paths={summary.get('paths_found')}/{summary.get('max_paths') or 'all'}, "
            f"from={summary.get('from_matches_used')}/{summary.get('from_matches_total')}, "
            f"to={summary.get('to_matches_used')}/{summary.get('to_matches_total')}"
        )
    for i, path in enumerate(all_paths, 1):
        typer.echo(f"  [{i}] {' → '.join(path)}")
        if show_guards:
            for label in path:
                guards = result.get("guards", {}).get(label)
                if guards:
                    typer.echo(f"       {label} guarded by: {', '.join(guards)}")
        if show_state:
            for label in path:
                state_access = result.get("state_access", {}).get(label)
                if state_access:
                    parts = []
                    if state_access.get("reads"):
                        parts.append(f"reads: {', '.join(state_access['reads'])}")
                    if state_access.get("writes"):
                        parts.append(f"writes: {', '.join(state_access['writes'])}")
                    typer.echo(f"       {label} state: {'; '.join(parts)}")


if __name__ == "__main__":
    app()
