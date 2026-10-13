#!/usr/bin/env python3
"""Run every ChainScope surface scan on a graph and write the results as JSON.

This is the one-command replacement for hand-rolling an MCP harness. It runs
audit / hotspots / defi / unsafe / sinks / cross and writes
``<outdir>/<name>.json`` for each.

    python cs_surface.py graph.db --out surfaces/mygraph --top 30
    python cs_surface.py graph.db --only hotspots,sinks
"""
from __future__ import annotations

import sys
from pathlib import Path

_PARENT = str(Path(__file__).resolve().parent.parent)
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)


import json
import os

import typer

import mcp_server

app = typer.Typer()

_SURFACES = {
    "audit": lambda db, top: mcp_server.cs_audit(db=db, top=top),
    "hotspots": lambda db, top: mcp_server.cs_hotspots(db=db, top=top),
    "defi": lambda db, top: mcp_server.cs_defi(db=db),
    "unsafe": lambda db, top: mcp_server.cs_unsafe(db=db),
    "sinks": lambda db, top: mcp_server.cs_sinks(db=db, max_results=50, max_callers_per_sink=8),
    "cross": lambda db, top: mcp_server.cs_cross_summary(db=db, top=top),
}


@app.command()
def surface(
    db: str = typer.Argument("graph.db", help="Graph database path"),
    outdir: str = typer.Option("", "--out", help="Output directory (default: <db-stem>_surface)"),
    top: int = typer.Option(25, "--top", help="Top-N for audit/hotspots/cross"),
    only: str = typer.Option("", "--only", help="Comma-separated subset (audit,hotspots,defi,unsafe,sinks,cross)"),
    exclude_research: bool = typer.Option(False, "--exclude-research"),
    json_output: bool = typer.Option(False, "--json", help="Print a JSON index instead of a text summary"),
):
    if not os.path.exists(db):
        typer.echo(f"database not found: {db}", err=True)
        raise typer.Exit(1)
    out = outdir or (os.path.splitext(os.path.basename(db))[0] + "_surface")
    os.makedirs(out, exist_ok=True)

    names = [n.strip() for n in only.split(",") if n.strip()] or list(_SURFACES)
    index = {}
    for name in names:
        fn = _SURFACES.get(name)
        if fn is None:
            typer.echo(f"unknown surface: {name}", err=True)
            continue
        try:
            raw = fn(db, top)
            data = json.loads(raw)
        except Exception as exc:  # noqa: BLE001
            data = {"error": str(exc)}
        path = os.path.join(out, f"{name}.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=1)
        index[name] = {"path": path, "error": data.get("error")}
        if not json_output:
            if data.get("error"):
                typer.echo(f"  {name}: ERROR {data['error']}")
            else:
                summary = data.get("_summary") or {}
                counts = summary.get("categories") or list(data.keys())
                typer.echo(f"  {name}: wrote {path} ({counts})")

    if json_output:
        typer.echo(json.dumps(index, indent=2))


if __name__ == "__main__":
    app()
