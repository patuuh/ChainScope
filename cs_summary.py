#!/usr/bin/env python3
"""Summarize a ChainScope knowledge graph."""
import json
import typer
import mcp_server

app = typer.Typer()


def _with_legacy_fields(data: dict) -> dict:
    """Keep older CLI JSON keys while using the MCP summary payload."""
    node_types = data.get("node_types", {})
    edge_relations = data.get("edge_relations", {})
    data.setdefault("modifiers", node_types.get("modifier", 0))
    data.setdefault("events", node_types.get("event", 0))
    data.setdefault("call_edges", edge_relations.get("calls", 0))
    data.setdefault("read_edges", edge_relations.get("reads_state", 0))
    data.setdefault("write_edges", edge_relations.get("writes_state", 0))
    return data


@app.command()
def summary(
    db: str = typer.Option("graph.db", help="Database path"),
    attack_surface: bool = typer.Option(False, "--attack-surface", help="Show attack surface analysis"),
    top: int = typer.Option(20, "--top", help="Maximum attack-surface entries to show"),
    exclude_research: bool = typer.Option(False, "--exclude-research", help="Exclude research-mode nodes"),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    data = json.loads(mcp_server.cs_summary(
        db=db,
        attack_surface=attack_surface,
        top=top,
        exclude_research=exclude_research,
    ))
    data = _with_legacy_fields(data)

    if "error" in data:
        typer.echo(data["error"], err=True)
        raise typer.Exit(1)

    if json_output:
        typer.echo(json.dumps(data, indent=2))
        return

    typer.echo(f"Graph Summary ({db}) [scope={data['query_scope']}]")
    typer.echo(f"  Files: {data['files']}")
    typer.echo(
        f"  Nodes: {data['nodes']} (functions={data['functions']}, state_vars={data['state_vars']}, "
        f"modifiers={data['modifiers']}, events={data['events']})"
    )
    typer.echo(
        f"  Edges: {data['edges']} (calls={data['call_edges']}, "
        f"reads={data['read_edges']}, writes={data['write_edges']})"
    )
    typer.echo(f"  State transitions: {data['transitions']}")

    if attack_surface and data.get("attack_surface"):
        typer.echo(f"\nAttack Surface ({len(data['attack_surface'])} entry points shown):")
        for entry in data["attack_surface"]:
            typer.echo(
                f"  {entry['label']} ({entry['file']}) - "
                f"reachable={entry['reachable_count']}, "
                f"state_writes={entry['state_writes']}"
            )


if __name__ == "__main__":
    app()
