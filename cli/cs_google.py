#!/usr/bin/env python3
"""Rank Google Bug Bounty / VRP programs by scope, payout, and hunt intensity.

Google Bug Hunters hosts several VRP programs. This command catalogs them
so you can filter/sort targets:

    python -m cli google list --only-sc --sort bounty
    python -m cli google list --refresh
    python -m cli google list --json
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

import typer

app = typer.Typer()

_CACHE = Path(_PARENT) / ".chainsource" / "google_programs.json"
_TTL = 24 * 3600

# Publicly documented Google VRP programs (from bughunters.google.com,
# chromium.googlesource.com docs/security/vrp-faq.md, and the Security
# Engineering Blog).  The bughunters.google.com site is a Next.js SPA
# with no discoverable public API, so this catalog is curated from
# public documentation rather than fetched programmatically.
_GOOGLE_PROGRAMS: list[dict[str, typing.Any]] = [
    {
        "title": "Google VRP",
        "slug": "google-vrp",
        "url": "https://bughunters.google.com/program/google-vrp",
        "rep": None,
        "max_bounty": 31337.0,
        "reports": 0,
        "audit": False,
        "sc": False,
        "kyc": True,
        "poc": False,
        "fee": 0,
        "status": "Active",
        "type": "General",
        "platform": "Google",
    },
    {
        "title": "Chrome VRP",
        "slug": "chrome-vrp",
        "url": "https://bughunters.google.com/program/chrome-vrp",
        "rep": None,
        "max_bounty": 30000.0,
        "reports": 0,
        "audit": False,
        "sc": False,
        "kyc": True,
        "poc": False,
        "fee": 0,
        "status": "Active",
        "type": "Browser",
        "platform": "Chrome",
    },
    {
        "title": "Android VRP",
        "slug": "android-vrp",
        "url": "https://bughunters.google.com/program/android-vrp",
        "rep": None,
        "max_bounty": 200000.0,
        "reports": 0,
        "audit": False,
        "sc": False,
        "kyc": True,
        "poc": False,
        "fee": 0,
        "status": "Active",
        "type": "Mobile",
        "platform": "Android",
    },
    {
        "title": "Google Cloud VRP",
        "slug": "google-cloud-vrp",
        "url": "https://bughunters.google.com/program/google-cloud-vrp",
        "rep": None,
        "max_bounty": 31337.0,
        "reports": 0,
        "audit": False,
        "sc": False,
        "kyc": True,
        "poc": False,
        "fee": 0,
        "status": "Active",
        "type": "Cloud",
        "platform": "Google Cloud",
    },
    {
        "title": "OSS VRP",
        "slug": "oss-vrp",
        "url": "https://bughunters.google.com/program/oss-vrp",
        "rep": None,
        "max_bounty": 31337.0,
        "reports": 0,
        "audit": False,
        "sc": False,
        "kyc": False,
        "poc": False,
        "fee": 0,
        "status": "Active",
        "type": "Open Source",
        "platform": "Google",
    },
    {
        "title": "AI VRP",
        "slug": "ai-vrp",
        "url": "https://bughunters.google.com/program/ai-vrp",
        "rep": None,
        "max_bounty": 1000000.0,
        "reports": 0,
        "audit": False,
        "sc": False,
        "kyc": True,
        "poc": False,
        "fee": 0,
        "status": "Active",
        "type": "AI",
        "platform": "Google",
    },
]


def _fetch_all() -> list[dict[str, typing.Any]]:
    """Fetch Google VRP program data.

    The bughunters.google.com SPA has no public API endpoint.
    Falls back to the curated catalog above.  Override by passing
    --refresh to re-read the cached catalog.
    """
    return _GOOGLE_PROGRAMS


def _load(refresh: bool = False) -> list[dict[str, typing.Any]]:
    if not refresh and _CACHE.exists() and time.time() - _CACHE.stat().st_mtime < _TTL:
        cached = json.loads(_CACHE.read_text())
        if isinstance(cached, dict):
            return cached["programs"]
        return cached
    programs = _fetch_all()
    _CACHE.parent.mkdir(parents=True, exist_ok=True)
    payload = {"fetched_at": int(time.time()), "programs": programs}
    _CACHE.write_text(json.dumps(payload))
    return programs


def _row(p: dict[str, typing.Any]) -> dict[str, typing.Any]:
    return {
        "title": p["title"],
        "url": p["url"],
        "rep": p["rep"],
        "max_bounty": float(p["max_bounty"]),
        "reports": p["reports"],
        "type": p.get("type", ""),
        "platform": p.get("platform", ""),
        "kyc": p["kyc"],
        "poc": p["poc"],
        "sc": p.get("sc", False),
    }


@app.command(name="list")
def list_programs(
    min_bounty: float = typer.Option(0, "--min-bounty", help="Min max-bounty in USD"),
    only_sc: bool = typer.Option(False, "--only-sc", help="Only smart-contract scope programs"),
    sort: str = typer.Option("bounty", "--sort", help="Sort by: bounty|reports|type"),
    top: int = typer.Option(20, "--top", help="How many programs to list"),
    refresh: bool = typer.Option(False, "--refresh", help="Force re-fetch (ignore 24h cache)"),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    programs = _load(refresh)
    rows = [_row(p) for p in programs if float(p["max_bounty"] or 0) >= min_bounty]
    if only_sc:
        rows = [r for r in rows if r["sc"]]
    key = {"bounty": lambda r: r["max_bounty"], "reports": lambda r: r["reports"], "type": lambda r: r["type"]}[sort]
    rows.sort(key=key, reverse=True)
    rows = rows[: int(top)]

    if not rows:
        typer.echo("No programs match the filters.", err=True)
        raise typer.Exit(1)
    typer.echo(f"{len(rows)} Google VRP program(s) match (max>={min_bounty:g}):")
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
    """Rank Google VRP programs Keizo-style: thin-hunted + fresh + payout + open gate."""
    import math

    programs = _load(refresh)
    now = time.time()
    rows = []
    for p in programs:
        if float(p["max_bounty"] or 0) < min_bounty:
            continue
        row = _row(p)
        payout = min(1.0, math.log10(1.0 + float(p["max_bounty"])) / 6.0)
        open_gate = 1.0 if p["rep"] is None else 0.0
        thin_hunt = 1.0 / (1.0 + (p["reports"] or 0) / 100.0)
        score = round(0.35 * thin_hunt + 0.25 * payout + 0.20 * open_gate + 0.10 * (1.0 if p.get("sc") else 0.0), 3)
        row["keizo"] = score
        row["signals"] = {"thin_hunt": round(thin_hunt, 3), "payout": round(payout, 3), "open_gate": open_gate, "sc": 1.0 if p.get("sc") else 0.0}
        rows.append(row)

    rows.sort(key=lambda r: r["keizo"] if sort == "keizo" else r["max_bounty"], reverse=True)
    rows = rows[: int(top)]

    if not rows:
        typer.echo("No programs match the filters.", err=True)
        raise typer.Exit(1)
    typer.echo(f"Keizo ranking (Google VRP, max>={min_bounty:g}):")
    for r in rows:
        s = r["signals"]
        typer.echo(
            f"  keizo={r['keizo']:.3f}  up to ${r['max_bounty']:>10,.0f}  "
            f"{r['type']:>12s}  {r['title']}"
        )
        typer.echo(f"      thin={s['thin_hunt']:.2f} payout={s['payout']:.2f} open_gate={s['open_gate']:.0f} sc={s['sc']:.0f}")
    if json_output:
        typer.echo(json.dumps(rows, indent=2))


@app.command(name="triage")
def triage(
    slug: str = typer.Argument(..., help="Google VRP program slug (e.g. 'google-cloud-vrp')"),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Show details for a Google VRP program.

    The bughunters.google.com site is a SPA with no public API,
    so triage returns the catalog entry.  Actual scope/contract
    data requires manual browsing of the program page.
    """
    programs = _load()
    matches = [p for p in programs if p["slug"] == slug]
    if not matches:
        typer.echo(f"No Google VRP program with slug '{slug}' found.", err=True)
        raise typer.Exit(1)
    p = matches[0]
    typer.echo(f"Google VRP Program: {p['title']}")
    typer.echo(f"  URL: {p['url']}")
    typer.echo(f"  Type: {p.get('type', '')}")
    typer.echo(f"  Platform: {p.get('platform', '')}")
    typer.echo(f"  Max Bounty: ${float(p['max_bounty']):,.0f}")
    typer.echo(f"  KYC Required: {p['kyc']}")
    typer.echo(f"  PoC Required: {p['poc']}")
    typer.echo(f"  Status: {p['status']}")
    typer.echo(f"  Note: bughunters.google.com is a SPA; browse {p['url']} for scope details.")
    if json_output:
        typer.echo(json.dumps(p, indent=2))


if __name__ == "__main__":
    app()
