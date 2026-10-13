#!/usr/bin/env python3
"""Semantic divergence between a *deployed* contract graph and a *repo* graph.

Motivation: for many bug-bounty targets the in-scope asset is the deployed
bytecode, and the repo HEAD can differ materially (guards removed, functions
added, storage reshaped). Auditing the repo when the deployed code differs
wastes effort. This module loads two ChainScope graphs and reports the
security-relevant deltas:

  * functions only in one side (added / removed)
  * changed access-control / guard modifiers
  * changed state-variable writes
  * changed dangerous sinks (fund transfer / delegatecall / low-level call)
  * state variables / struct fields only present on one side

The comparison keys functions by their qualified id suffix
``Contract.func(paramTypes)`` (stable across differing file roots) and sinks by
``(call_name, sink_type)`` (node ids embed a line number and are not stable).
"""
from __future__ import annotations

import json
import sqlite3


def _load_functions(db_path: str) -> dict:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    funcs: dict[str, dict] = {}
    for row in conn.execute(
        "SELECT id, label, file, visibility, signature, metadata "
        "FROM nodes WHERE type = 'function'"
    ):
        meta = {}
        try:
            meta = json.loads(row["metadata"] or "{}")
        except Exception:
            meta = {}
        # Sink nodes are synthetic; skip them as "functions".
        if meta.get("is_sink"):
            continue
        key = row["id"].split("::", 1)[-1]
        funcs[key] = {
            "id": row["id"],
            "label": row["label"],
            "file": row["file"],
            "visibility": row["visibility"],
            "signature": row["signature"],
            "modifiers": sorted(meta.get("modifiers") or []),
            "payable": bool(meta.get("payable")),
            "reads": set(),
            "writes": set(),
            "calls": set(),
            "sinks": set(),
        }

    by_id = {f["id"]: f for f in funcs.values()}
    rows = conn.execute(
        "SELECT e.source AS src, e.relation AS rel, e.attributes AS attrs, "
        "       n.label AS tlabel, n.metadata AS tmeta "
        "FROM edges e LEFT JOIN nodes n ON n.id = e.target "
        "WHERE e.relation IN ('reads_state', 'writes_state', 'calls')"
    )
    for e in rows:
        f = by_id.get(e["src"])
        if f is None:
            continue
        tlabel = e["tlabel"] or ""
        if e["rel"] == "reads_state":
            f["reads"].add(tlabel)
        elif e["rel"] == "writes_state":
            f["writes"].add(tlabel)
        else:  # calls
            f["calls"].add(tlabel)
            attrs = {}
            try:
                attrs = json.loads(e["attrs"] or "{}")
            except Exception:
                attrs = {}
            tmeta = {}
            try:
                tmeta = json.loads(e["tmeta"] or "{}")
            except Exception:
                tmeta = {}
            if tmeta.get("is_sink"):
                f["sinks"].add(f"{tlabel}:{tmeta.get('sink_type', '?')}")
    conn.close()
    return funcs


def _load_state_vars(db_path: str) -> set[str]:
    conn = sqlite3.connect(db_path)
    out = set()
    for row in conn.execute("SELECT label FROM nodes WHERE type = 'state_var'"):
        out.add(row[0])
    conn.close()
    return out


def _load_summary(db_path: str) -> dict:
    conn = sqlite3.connect(db_path)
    counts = {}
    for row in conn.execute("SELECT type, COUNT(*) AS n FROM nodes GROUP BY type"):
        counts[row[0]] = row[1]
    conn.close()
    return counts


def diff_graphs(deployed_db: str, repo_db: str, contract: str = "") -> dict:
    """Return a structured divergence report between two graph databases.

    If ``contract`` is given, only functions whose qualified key begins with
    ``<contract>.`` are compared (drops cross-contract noise).
    """
    dep = _load_functions(deployed_db)
    rep = _load_functions(repo_db)

    if contract:
        prefix = f"{contract}."
        dep = {k: v for k, v in dep.items() if k.startswith(prefix)}
        rep = {k: v for k, v in rep.items() if k.startswith(prefix)}

    dep_keys, rep_keys = set(dep), set(rep)
    common = sorted(dep_keys & rep_keys)

    changed_modifiers: list[dict] = []
    changed_writes: list[dict] = []
    changed_reads: list[dict] = []
    changed_sinks: list[dict] = []
    changed_payable: list[dict] = []

    for k in common:
        d, r = dep[k], rep[k]
        if d["modifiers"] != r["modifiers"]:
            changed_modifiers.append({
                "function": k, "file": r["file"],
                "deployed": d["modifiers"], "repo": r["modifiers"],
                "deployed_only": sorted(set(d["modifiers"]) - set(r["modifiers"])),
                "repo_only": sorted(set(r["modifiers"]) - set(d["modifiers"])),
            })
        if d["writes"] != r["writes"]:
            changed_writes.append({
                "function": k, "file": r["file"],
                "deployed": sorted(d["writes"]), "repo": sorted(r["writes"]),
            })
        if d["reads"] != r["reads"]:
            changed_reads.append({
                "function": k, "file": r["file"],
                "deployed": sorted(d["reads"]), "repo": sorted(r["reads"]),
            })
        if d["sinks"] != r["sinks"]:
            changed_sinks.append({
                "function": k, "file": r["file"],
                "deployed": sorted(d["sinks"]), "repo": sorted(r["sinks"]),
            })
        if d["payable"] != r["payable"]:
            changed_payable.append({
                "function": k, "file": r["file"],
                "deployed": d["payable"], "repo": r["payable"],
            })

    dep_sv = _load_state_vars(deployed_db)
    rep_sv = _load_state_vars(repo_db)

    report = {
        "summary": {
            "deployed_functions": len(dep),
            "repo_functions": len(rep),
            "common_functions": len(common),
            "deployed_nodes": _load_summary(deployed_db),
            "repo_nodes": _load_summary(repo_db),
        },
        "functions_only_in_deployed": sorted(dep_keys - rep_keys),
        "functions_only_in_repo": sorted(rep_keys - dep_keys),
        "changed_modifiers": changed_modifiers,
        "changed_payable": changed_payable,
        "changed_state_writes": changed_writes,
        "changed_state_reads": changed_reads,
        "changed_sinks": changed_sinks,
        "state_vars_only_in_deployed": sorted(dep_sv - rep_sv),
        "state_vars_only_in_repo": sorted(rep_sv - dep_sv),
    }
    report["has_divergence"] = bool(
        report["functions_only_in_deployed"]
        or report["functions_only_in_repo"]
        or changed_modifiers
        or changed_writes
        or changed_sinks
        or changed_payable
        or report["state_vars_only_in_deployed"]
        or report["state_vars_only_in_repo"]
    )
    return report


def format_report(report: dict, max_items: int = 40) -> str:
    """Human-readable rendering of a diff_graphs() report."""
    s = report["summary"]
    lines = [
        "Divergence report (deployed vs repo)",
        f"  deployed functions: {s['deployed_functions']} | repo functions: {s['repo_functions']} "
        f"| common: {s['common_functions']}",
    ]

    def _section(title: str, items: list, render) -> None:
        lines.append(f"\n{title} ({len(items)}):")
        if not items:
            lines.append("  (none)")
            return
        for it in items[:max_items]:
            lines.append("  " + render(it))
        if len(items) > max_items:
            lines.append(f"  ... {len(items) - max_items} more")

    _section("Functions only in DEPLOYED (removed from repo / deployed-only)",
             report["functions_only_in_deployed"], lambda x: x)
    _section("Functions only in REPO (added after deploy)",
             report["functions_only_in_repo"], lambda x: x)
    _section("Guard/modifier changes (review for removed access control)",
             report["changed_modifiers"],
             lambda x: f"{x['function']} [{x['file']}]\n"
                       f"      deployed={x['deployed']}  repo={x['repo']}")
    _section("Payable changes",
             report["changed_payable"],
             lambda x: f"{x['function']} [{x['file']}] deployed={x['deployed']} repo={x['repo']}")
    _section("State-write changes",
             report["changed_state_writes"],
             lambda x: f"{x['function']} [{x['file']}]\n"
                       f"      deployed={x['deployed']}\n      repo={x['repo']}")
    _section("Sink changes (fund transfer / delegatecall / low-level call)",
             report["changed_sinks"],
             lambda x: f"{x['function']} [{x['file']}] deployed={x['deployed']} repo={x['repo']}")
    _section("State vars only in DEPLOYED",
             report["state_vars_only_in_deployed"], lambda x: x)
    _section("State vars only in REPO",
             report["state_vars_only_in_repo"], lambda x: x)
    return "\n".join(lines)
