#!/usr/bin/env python3
"""Summarize a ChainScope knowledge graph."""
import json
import typer
from core.schema import GraphDB
from collections import deque

app = typer.Typer()


def _load_metadata(raw: str | None) -> dict:
    try:
        return json.loads(raw or "{}")
    except (json.JSONDecodeError, TypeError):
        return {}


@app.command()
def summary(
    db: str = typer.Option("graph.db", help="Database path"),
    attack_surface: bool = typer.Option(False, "--attack-surface", help="Show attack surface analysis"),
    exclude_research: bool = typer.Option(False, "--exclude-research", help="Exclude research-mode nodes"),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    graph_db = GraphDB(db)
    conn = graph_db.get_connection()
    try:
        node_rows = conn.execute("SELECT id, type, file, metadata FROM nodes").fetchall()
        allowed_ids = set()
        type_counts = {
            "function": 0,
            "state_var": 0,
            "modifier": 0,
            "event": 0,
        }
        files = set()
        for row in node_rows:
            meta = _load_metadata(row["metadata"])
            if exclude_research and meta.get("source_kind") == "research":
                continue
            allowed_ids.add(row["id"])
            files.add(row["file"])
            if row["type"] in type_counts:
                type_counts[row["type"]] += 1
        nodes = len(allowed_ids)

        edge_rows = conn.execute("SELECT source, target, relation FROM edges").fetchall()
        filtered_edges = [r for r in edge_rows if r["source"] in allowed_ids and r["target"] in allowed_ids]
        edges = len(filtered_edges)
        call_edges = sum(1 for r in filtered_edges if r["relation"] == "calls")
        read_edges = sum(1 for r in filtered_edges if r["relation"] == "reads_state")
        write_edges = sum(1 for r in filtered_edges if r["relation"] == "writes_state")

        transition_rows = conn.execute("""
            SELECT st.function_id, n.metadata
            FROM state_transitions st
            LEFT JOIN nodes n ON st.function_id = n.id
        """).fetchall()
        transitions = 0
        for row in transition_rows:
            meta = _load_metadata(row["metadata"])
            if exclude_research and meta.get("source_kind") == "research":
                continue
            transitions += 1
    finally:
        conn.close()

    data = {
        "query_scope": "production_only" if exclude_research else "all_sources",
        "nodes": nodes, "edges": edges, "transitions": transitions,
        "functions": type_counts["function"], "state_vars": type_counts["state_var"],
        "modifiers": type_counts["modifier"], "events": type_counts["event"],
        "call_edges": call_edges, "read_edges": read_edges,
        "write_edges": write_edges, "files": len(files),
    }

    if attack_surface:
        adjacency: dict[str, list[str]] = {}
        for row in filtered_edges:
            if row["relation"] not in {"calls", "flows_to", "inherits"}:
                continue
            adjacency.setdefault(row["source"], []).append(row["target"])

        write_map: dict[str, int] = {}
        for row in filtered_edges:
            if row["relation"] == "writes_state":
                write_map[row["source"]] = write_map.get(row["source"], 0) + 1

        conn = graph_db.get_connection()
        try:
            externals = conn.execute("""
                SELECT id, label, file, signature, metadata
                FROM nodes
                WHERE type = 'function' AND visibility IN ('public', 'external')
            """).fetchall()
        finally:
            conn.close()

        surface = []
        for ext in externals:
            meta = _load_metadata(ext["metadata"])
            if exclude_research and meta.get("source_kind") == "research":
                continue
            if ext["id"] not in allowed_ids:
                continue
            reachable = {ext["id"]}
            queue = deque([ext["id"]])
            while queue:
                current = queue.popleft()
                for neighbor in adjacency.get(current, []):
                    if neighbor not in reachable:
                        reachable.add(neighbor)
                        queue.append(neighbor)
            write_count = sum(write_map.get(rid, 0) for rid in reachable)
            surface.append({
                "id": ext["id"],
                "label": ext["label"],
                "file": ext["file"],
                "signature": ext["signature"],
                "reachable_count": len(reachable),
                "state_writes": write_count,
                "source_context": meta.get("source_context", "production"),
            })
        surface.sort(key=lambda x: x["state_writes"], reverse=True)
        data["attack_surface"] = surface

    if json_output:
        typer.echo(json.dumps(data, indent=2))
        return

    typer.echo(f"Graph Summary ({db}) [scope={data['query_scope']}]")
    typer.echo(f"  Files: {data['files']}")
    typer.echo(f"  Nodes: {nodes} (functions={data['functions']}, state_vars={data['state_vars']}, "
               f"modifiers={data['modifiers']}, events={data['events']})")
    typer.echo(f"  Edges: {edges} (calls={call_edges}, reads={read_edges}, writes={write_edges})")
    typer.echo(f"  State transitions: {transitions}")

    if attack_surface and data.get("attack_surface"):
        typer.echo(f"\nAttack Surface ({len(data['attack_surface'])} entry points):")
        for entry in data["attack_surface"]:
            typer.echo(f"  {entry['label']} ({entry['file']}) — "
                       f"reachable={entry['reachable_count']}, "
                       f"state_writes={entry['state_writes']}")


if __name__ == "__main__":
    app()
