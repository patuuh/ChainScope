#!/usr/bin/env python3
"""Query state machine transitions in a ChainScope knowledge graph."""
import json
import typer
import mcp_server

app = typer.Typer()


@app.command()
def state(
    db: str = typer.Option("graph.db", help="Database path"),
    entity: str = typer.Option(None, "--entity", help="Filter by entity name (e.g. VaultState)"),
    all_entities: bool = typer.Option(False, "--all", help="Show all state machines"),
    max_entities: int = typer.Option(20, "--max-entities", help="Max entity groups for --all (0 = all)"),
    max_transitions_per_entity: int = typer.Option(50, "--max-transitions-per-entity", help="Max transitions per entity (0 = all)"),
    max_warnings: int = typer.Option(50, "--max-warnings", help="Max warnings to show (0 = all)"),
    exclude_research: bool = typer.Option(False, "--exclude-research", help="Exclude research-mode transitions"),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    if not entity and not all_entities:
        typer.echo("Specify --entity <name> or --all", err=True)
        raise typer.Exit(1)

    data = json.loads(mcp_server.cs_state(
        db=db,
        entity=entity or "",
        exclude_research=exclude_research,
        max_entities=max_entities,
        max_transitions_per_entity=max_transitions_per_entity,
        max_warnings=max_warnings,
    ))

    if json_output:
        typer.echo(json.dumps(data, indent=2))
        return

    entities = data.get("entities", {})
    warnings = data.get("warnings", [])
    if not entities:
        typer.echo("No state machines found")
        return

    typer.echo(f"Scope: {data.get('query_scope', 'all_sources')}")
    summary = data.get("_summary", {})
    if summary.get("truncated"):
        typer.echo(
            f"Showing {summary.get('entities_shown')}/{summary.get('entities_total')} entities, "
            f"{summary.get('transitions_shown')}/{summary.get('transitions_total')} transitions, "
            f"{summary.get('warnings_shown')}/{summary.get('warnings_total')} warnings"
        )
    for ent, trans in entities.items():
        typer.echo(f"\nState Machine: {ent}")
        for t in trans:
            func_label = t.get("function_label") or t["function_id"].split("::")[-1]
            conds = json.loads(t.get("conditions", "[]"))
            cond_str = f" [{len(conds)} conditions]" if conds else ""
            from_str = t["from_state"] if t["from_state"] != "*" else "ANY"
            typer.echo(
                f"  {from_str} → {t['to_state']} via {func_label}(){cond_str} "
                f"<{t.get('source_context', 'production')}>"
            )

    if warnings:
        typer.echo(f"\nWarnings ({len(warnings)}):")
        for w in warnings:
            typer.echo(f"  ⚠ {w}")


if __name__ == "__main__":
    app()
