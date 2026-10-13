#!/usr/bin/env python3
"""Rank Sherlock bug bounty programs by scope, payout, and hunt intensity.

Usage:
    python -m cli sherlock list --sort bounty
    python -m cli sherlock list --refresh
    python -m cli sherlock list --json
"""
from __future__ import annotations

import sys
from pathlib import Path

_PARENT = str(Path(__file__).resolve().parent.parent)
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)

import json
import time
import typing
import urllib.request
import math
import re

import typer

app = typer.Typer()

_CACHE = Path(_PARENT) / ".chainsource" / "sherlock_programs.json"
_TTL = 24 * 3600
_API = "https://audits.sherlock.xyz/bug-bounties"


def _fetch_all() -> list[dict[str, typing.Any]]:
    req = urllib.request.Request(
        _API,
        headers={"User-Agent": "Mozilla/5.0 (ChainScope)", "Accept": "text/html"},
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        html = resp.read().decode("utf-8")
        
    pattern = r"\\\"id\\\":(\d+),.*?\\\"title\\\":\\\"(.*?)\\\".*?\\\"payout\\\":(\d+),.*?\\\"displayCurrency\\\":\\\"(.*?)\\\""
    matches = re.finditer(pattern, html)

    bounties = []
    seen = set()
    for m in matches:
        title = m.group(2).replace("\\\\u0026", "&").replace("\\u0026", "&")
        if title in seen:
            continue
        seen.add(title)
        
        bounties.append({
            "id": int(m.group(1)),
            "title": title,
            "max_bounty": int(m.group(3)),
            "currency": m.group(4)
        })
        
    return bounties


def _load(refresh: bool = False) -> list[dict[str, typing.Any]]:
    if not refresh and _CACHE.exists() and time.time() - _CACHE.stat().st_mtime < _TTL:
        cached = json.loads(_CACHE.read_text())
        if isinstance(cached, dict):
            return cached.get("programs", [])
        return cached
    programs = _fetch_all()
    _CACHE.parent.mkdir(parents=True, exist_ok=True)
    payload = {"fetched_at": int(time.time()), "programs": programs}
    _CACHE.write_text(json.dumps(payload))
    return programs


def _row(p: dict[str, typing.Any]) -> dict[str, typing.Any]:
    # The Sherlock index only publishes {currency, id, max_bounty, title}.
    # Status, report count and contest type are NOT in that payload, so they are
    # reported as None rather than invented. Hardcoding status="Active" and
    # reports=0 made every finished contest look live and uncompeted, which is
    # exactly the kind of fabricated field that wrecks target selection.
    return {
        "title": p.get("title", "Unknown"),
        "url": f"https://audits.sherlock.xyz/bug-bounties",
        "slug": p.get("title", "").lower().replace(" ", "-"),
        "rep": None,
        "max_bounty": float(p.get("max_bounty", 0.0)),
        "reports": None,
        "status": None,
        "type": None,
        "platform": "Sherlock",
        "sc": None,
        "fields_unavailable": [
            "status", "reports", "type", "sc",
        ],
        "raw": p,
    }


@app.command(name="list")
def list_programs(
    min_bounty: float = typer.Option(0, "--min-bounty", help="Min max-bounty in USD"),
    sort: str = typer.Option("bounty", "--sort", help="Sort by: bounty|type"),
    top: int = typer.Option(20, "--top", help="How many programs to list"),
    refresh: bool = typer.Option(False, "--refresh", help="Force re-fetch (ignore 24h cache)"),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    programs = _load(refresh)
    rows = [_row(p) for p in programs]
    rows = [r for r in rows if r["max_bounty"] >= min_bounty]
    
    if sort == "type":
        key = lambda r: r["type"]
    else:
        key = lambda r: r["max_bounty"]

    rows.sort(key=key, reverse=(sort == "bounty"))
    rows = rows[: int(top)]

    if not rows:
        typer.echo("No programs match the filters.", err=True)
        raise typer.Exit(1)
        
    if not json_output:
            typer.echo(f"{len(rows)} Sherlock program(s) match (max>={min_bounty:g}):")
            for r in rows:
                typer.echo(
                    f"  up to ${r['max_bounty']:>10,.0f}  {r['type']:>12s}  "
                    f"{r['title']}  {r['url']}"
                )
    if json_output:
        typer.echo(json.dumps(rows, indent=2))


@app.command(name="keizo")
def keizo_rank(
    min_bounty: float = typer.Option(0, "--min-bounty", help="Min max-bounty in USD"),
    sort: str = typer.Option("keizo", "--sort", help="Sort by: keizo|bounty"),
    top: int = typer.Option(10, "--top", help="How many programs to list"),
    refresh: bool = typer.Option(False, "--refresh", help="Force re-fetch (ignore 24h cache)"),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    programs = _load(refresh)
    rows = []
    for p in programs:
        row = _row(p)
        if row["max_bounty"] < min_bounty:
            continue
            
        payout = min(1.0, math.log10(1.0 + row["max_bounty"]) / 6.0)
        open_gate = 1.0
        fresh = 0.5 # Sherlock doesn't expose dates directly in this payload segment easily
        
        score = round(0.35 * fresh + 0.35 * payout + 0.30 * open_gate, 3)
        row["keizo"] = score
        row["signals"] = {"fresh": round(fresh, 3), "payout": round(payout, 3), "open_gate": open_gate}
        rows.append(row)

    rows.sort(key=lambda r: r["keizo"] if sort == "keizo" else r["max_bounty"], reverse=True)
    rows = rows[: int(top)]

    if not rows:
        typer.echo("No programs match the filters.", err=True)
        raise typer.Exit(1)
        
    if not json_output:
            typer.echo(f"Keizo ranking (Sherlock, max>={min_bounty:g}):")
            for r in rows:
                s = r["signals"]
                typer.echo(
                    f"  keizo={r['keizo']:.3f}  up to ${r['max_bounty']:>10,.0f}  "
                    f"{r['type']:>12s}  {r['title']}"
                )
                typer.echo(f"      fresh={s['fresh']:.2f} payout={s['payout']:.2f} open_gate={s['open_gate']:.0f}")
    if json_output:
        typer.echo(json.dumps(rows, indent=2))


if __name__ == "__main__":
    app()
