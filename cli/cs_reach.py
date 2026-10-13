#!/usr/bin/env python3
"""Reachability from permissionless entry points to dangerous sinks.

Answers the question that matters for a first-pass triage:

    "Which externally-callable functions WITHOUT access control can reach a
     fund transfer / delegatecall / low-level call / selfdestruct?"

Unlike ``cs_sinks`` (which lists sinks and their callers) this walks the call
graph from every entry point and reports the *shortest path* to each sink type,
so you get an ordered worklist of entry -> sink chains to review.

    python cs_reach.py graph.db
    python cs_reach.py graph.db --sink-type fund_transfer --top 25
    python cs_reach.py graph.db --include-guarded      # show guarded entries too
"""
from __future__ import annotations

import sys
from pathlib import Path

_PARENT = str(Path(__file__).resolve().parent.parent)
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)


import json
import sqlite3
from collections import deque

import typer

import mcp_server

app = typer.Typer()

_SINK_PRIORITY = {
    "fund_transfer": 4,
    "delegate": 4,
    "self_destruct": 4,
    "low_level_call": 3,
    "static_call": 1,
}
_TRAVERSAL = ("calls", "flows_to", "delegatecall")


def _load(db_path: str, exclude_research: bool):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    guard_counts: dict[str, int] = {}
    for r in conn.execute("SELECT source FROM edges WHERE relation = 'guards'"):
        guard_counts[r["source"]] = guard_counts.get(r["source"], 0) + 1

    funcs: dict[str, dict] = {}
    sinks: dict[str, dict] = {}
    for r in conn.execute(
        "SELECT id, label, file, visibility, metadata FROM nodes WHERE type = 'function'"
    ):
        try:
            meta = json.loads(r["metadata"] or "{}")
        except Exception:  # noqa: BLE001
            meta = {}
        if exclude_research and mcp_server._is_research_metadata_raw(r["metadata"]):
            continue
        if meta.get("is_sink"):
            sinks[r["id"]] = {"id": r["id"], "label": r["label"],
                              "sink_type": meta.get("sink_type", "?"), "file": r["file"]}
        else:
            funcs[r["id"]] = {"id": r["id"], "label": r["label"], "file": r["file"],
                              "vis": r["visibility"], "meta": meta}

    adj: dict[str, list[str]] = {}
    for r in conn.execute(
        "SELECT source, target FROM edges WHERE relation IN (?, ?, ?)", _TRAVERSAL
    ):
        adj.setdefault(r["source"], []).append(r["target"])
    conn.close()
    return funcs, sinks, adj, guard_counts


def _shortest_sink_paths(start: str, sinks: dict, adj: dict, max_depth: int, sink_type: str):
    seen = {start}
    queue = deque([(start, [start])])
    found: list[tuple[str, list[str]]] = []
    while queue:
        cur, path = queue.popleft()
        if len(path) - 1 >= max_depth:
            continue
        for tgt in adj.get(cur, []):
            if tgt in seen:
                continue
            seen.add(tgt)
            if tgt in sinks:
                st = sinks[tgt]["sink_type"]
                if not sink_type or st == sink_type:
                    found.append((st, path + [tgt]))
                    continue
            queue.append((tgt, path + [tgt]))
    found.sort(key=lambda x: (-_SINK_PRIORITY.get(x[0], 0), len(x[1])))
    return found


@app.command()
def reach(
    db: str = typer.Argument("graph.db", help="Graph database path"),
    sink_type: str = typer.Option("", "--sink-type", help="Restrict to one sink type"),
    include_guarded: bool = typer.Option(False, "--include-guarded", help="Include entries that have access control"),
    max_depth: int = typer.Option(8, "--max-depth"),
    top: int = typer.Option(40, "--top", help="Max entries to report (0 = all)"),
    exclude_research: bool = typer.Option(False, "--exclude-research"),
    json_output: bool = typer.Option(False, "--json"),
):
    try:
        db_path = mcp_server._resolve_db(db)
    except Exception as exc:  # noqa: BLE001
        typer.echo(f"cannot open database: {exc}", err=True)
        raise typer.Exit(1)

    funcs, sinks, adj, guard_counts = _load(db_path, exclude_research)
    if not sinks:
        typer.echo("No sink nodes in graph (nothing to reach).")
        return

    labels = {fid: f["label"] for fid, f in funcs.items()}
    labels.update({sid: s["label"] for sid, s in sinks.items()})

    results = []
    for fid, f in funcs.items():
        if f["vis"] not in ("external", "public"):
            continue
        if f["meta"].get("view") or f["meta"].get("pure"):
            continue
        has_ac = mcp_server._has_access_control(f["meta"], guard_counts.get(fid, 0))
        if has_ac and not include_guarded:
            continue
        paths = _shortest_sink_paths(fid, sinks, adj, max_depth, sink_type)
        if paths:
            results.append({
                "entry": fid, "label": f["label"], "file": f["file"],
                "has_access_control": has_ac,
                "sinks": [{"sink_type": st, "path": [labels.get(x, x) for x in p]}
                          for st, p in paths[:3]],
            })

    results.sort(key=lambda r: (
        -max(_SINK_PRIORITY.get(s["sink_type"], 0) for s in r["sinks"]),
        len(r["sinks"][0]["path"]),
    ))
    if top:
        results = results[:top]

    if json_output:
        typer.echo(json.dumps({"entries": results, "sink_total": len(sinks)}, indent=2))
        return

    typer.echo(
        f"Permissionless-entry -> sink reachability: {len(results)} entries "
        f"(sinks={len(sinks)}, guarded_entries={'included' if include_guarded else 'excluded'})"
    )
    for r in results:
        guard = " [guarded]" if r["has_access_control"] else ""
        best = r["sinks"][0]
        typer.echo(f"\n  {r['label']} [{r['file']}]{guard}  -> {best['sink_type']}")
        typer.echo("      " + " -> ".join(best["path"]))
        for extra in r["sinks"][1:]:
            typer.echo(f"      also {extra['sink_type']}: " + " -> ".join(extra["path"]))


if __name__ == "__main__":
    app()
