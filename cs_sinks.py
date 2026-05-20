#!/usr/bin/env python3
"""Map dangerous sinks and paths to them in a ChainScope knowledge graph."""
import json
import typer
from core.schema import GraphDB
from core.graph import Graph

app = typer.Typer()


def _load_metadata(raw: str | None) -> dict:
    try:
        return json.loads(raw or "{}")
    except (json.JSONDecodeError, TypeError):
        return {}


@app.command()
def sinks(
    db: str = typer.Option("graph.db", help="Database path"),
    sink_type: str = typer.Option(None, "--type", help="Filter by sink type (fund_transfer/delegate/self_destruct/cpi_transfer)"),
    external_only: bool = typer.Option(False, "--external-only", help="Only show paths from external/public functions"),
    exclude_research: bool = typer.Option(False, "--exclude-research", help="Exclude research-mode nodes"),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    graph = Graph(db)
    graph_db = GraphDB(db)
    conn = graph_db.get_connection()
    try:
        all_sinks = []
        for sink in graph.get_sinks_by_type(sink_type):
            meta = _load_metadata(sink.get("metadata"))
            if exclude_research and meta.get("source_kind") == "research":
                continue
            sink["source_context"] = meta.get("source_context", "production")
            all_sinks.append(sink)

        # For each sink, find which functions can reach it
        results = []
        for sink in all_sinks:
            meta = _load_metadata(sink.get("metadata", "{}"))
            sink_info = {
                "sink_id": sink["id"],
                "sink_label": sink["label"],
                "sink_type": meta.get("sink_type", "unknown"),
                "file": sink["file"],
                "source_context": sink.get("source_context", "production"),
                "paths_from": [],
            }

            # Find callers of this sink
            callers = conn.execute("""
                SELECT n.id, n.label, n.file, n.visibility, n.metadata
                FROM edges e JOIN nodes n ON e.source = n.id
                WHERE e.target = ? AND e.relation = 'calls'
            """, (sink["id"],)).fetchall()
            for caller in callers:
                caller = dict(caller)
                caller_meta = _load_metadata(caller.pop("metadata", None))
                if exclude_research and caller_meta.get("source_kind") == "research":
                    continue
                if external_only and caller.get("visibility") not in ("public", "external"):
                    continue
                sink_info["paths_from"].append({
                    "caller": caller["label"],
                    "file": caller["file"],
                    "visibility": caller.get("visibility", ""),
                    "source_context": caller_meta.get("source_context", "production"),
                })

            # Also check wrapper propagation
            wrappers = graph.propagate_sinks([sink["label"]])
            for w in wrappers:
                wrapper_row = conn.execute(
                    "SELECT visibility, metadata FROM nodes WHERE label = ? AND file = ?",
                    (w["wrapper_label"], w["file"])
                ).fetchone()
                wrapper_meta = _load_metadata(wrapper_row["metadata"]) if wrapper_row else {}
                if exclude_research and wrapper_meta.get("source_kind") == "research":
                    continue
                if external_only:
                    # Check visibility of wrapper
                    if wrapper_row and wrapper_row["visibility"] not in ("public", "external"):
                        continue
                sink_info["paths_from"].append({
                    "caller": w["wrapper_label"],
                    "file": w["file"],
                    "visibility": "wrapper",
                    "source_context": wrapper_meta.get("source_context", "production"),
                })

            results.append(sink_info)

        if json_output:
            typer.echo(json.dumps(results, indent=2))
            return

        if not results:
            typer.echo(f"No sinks found" + (f" of type '{sink_type}'" if sink_type else ""))
            return

        typer.echo(f"Sinks ({len(results)} found, scope={'production_only' if exclude_research else 'all_sources'}):")
        for sink_info in results:
            typer.echo(
                f"\n  {sink_info['sink_label']} [{sink_info['sink_type']}] "
                f"({sink_info['file']}) <{sink_info['source_context']}>"
            )
            if sink_info["paths_from"]:
                for p in sink_info["paths_from"]:
                    typer.echo(
                        f"    ← {p['caller']} ({p['file']}) [{p['visibility']}] <{p['source_context']}>"
                    )
            else:
                typer.echo(f"    (no direct callers found)")
    finally:
        conn.close()


if __name__ == "__main__":
    app()
