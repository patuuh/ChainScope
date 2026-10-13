#!/usr/bin/env python3
"""Rank Intigriti bug bounty programs by scope, payout, and hunt intensity.

Usage:
    python -m cli intigriti list --sort bounty
    python -m cli intigriti list --refresh
    python -m cli intigriti list --json
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

import typer

app = typer.Typer()

_CACHE = Path(_PARENT) / ".chainsource" / "intigriti_programs.json"
_TTL = 24 * 3600
_API = "https://app.intigriti.com/api/core/public/programs"


def _fetch_all() -> list[dict[str, typing.Any]]:
    req = urllib.request.Request(
        _API,
        headers={"User-Agent": "Mozilla/5.0 (ChainScope)", "Accept": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        data = json.load(resp)
    return data


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
    """Normalise one Intigriti program.

    Three things this previously faked, all corrected because a silently wrong
    signal is worse than a missing one:

    1. **Currency.** 140 of 188 Intigriti programs quote EUR (2 GBP). The old
       code multiplied by a hardcoded 1.05/1.25 and labelled the result as a USD
       figure, so a EUR program was silently mis-ranked against USD thresholds.
       The native amount and currency are now carried explicitly and no rate is
       invented; `max_bounty` is the raw native value, and `max_bounty_usd` is
       only populated for USD-quoted programs.
    2. **`reports` was hardcoded to 0** for every program. That fabricates a
       perfect thin-hunt signal for the whole platform — exactly the failure that
       made Starknet (27 real reports) look like the best target this session,
       except worse because it was manufactured. It is now `None` (unknown).
    3. **`sc` was hardcoded to False**, so no scope-type filtering was possible.
       The public API does not publish a scope type, so it is `None` (unknown)
       rather than a false "not a smart contract".
    """
    raw_max = p.get("maxBounty") or {}
    raw_min = p.get("minBounty") or {}
    currency = (raw_max.get("currency") or raw_min.get("currency") or "").upper() or None
    value = float(raw_max.get("value") or 0)
    return {
        "title": p.get("name", "Unknown"),
        "url": f"https://app.intigriti.com/programs/{p.get('companyHandle', '')}/{p.get('handle', '')}",
        "slug": p.get("handle", ""),
        "program_id": p.get("programId"),
        "company": p.get("companyName"),
        "rep": None,                     # Intigriti has no public rep gate
        "max_bounty": value,              # NATIVE value, unconverted
        "currency": currency,
        "max_bounty_usd": value if currency == "USD" else None,
        "min_bounty": float(raw_min.get("value") or 0),
        "tac_required": p.get("tacRequired"),
        "two_factor": p.get("twoFactorRequired"),
        "reports": None,                 # unknown, never 0
        "audit_status": "unknown",       # never "unaudited"
        "status": "Active" if p.get("status") in (3, 4) else "Paused",
        "created_at": p.get("createdAt"),
        "last_updated_at": p.get("lastUpdatedAt"),
        "last_submission_at": p.get("lastSubmissionAt"),
        "type": p.get("industry", ""),
        "platform": "Intigriti",
        "sc": None,                      # unknown, not False
        "raw": p,
    }


@app.command(name="list")
def list_programs(
    min_bounty: float = typer.Option(0, "--min-bounty", help="Min max-bounty in the NATIVE quoted currency (not converted)"),
    sort: str = typer.Option("bounty", "--sort", help="Sort by: bounty|type"),
    top: int = typer.Option(20, "--top", help="How many programs to list"),
    refresh: bool = typer.Option(False, "--refresh", help="Force re-fetch (ignore 24h cache)"),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    programs = _load(refresh)
    rows = [
        _row(p)
        for p in programs
        if str(p.get("status", "")) in ("3", "4", "3.0") or p.get("status") in (3, 4)
    ]
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
            typer.echo(f"{len(rows)} Intigriti program(s) match (max>={min_bounty:g}):")
            for r in rows:
                typer.echo(
                    f"  up to ${r['max_bounty']:>10,.0f}  {r['type']:>12s}  "
                    f"{r['title']}  {r['url']}"
                )
    if json_output:
        typer.echo(json.dumps(rows, indent=2))


@app.command(name="keizo")
def keizo_rank(
    min_bounty: float = typer.Option(0, "--min-bounty", help="Min max-bounty in the NATIVE quoted currency (not converted)"),
    sort: str = typer.Option("keizo", "--sort", help="Sort by: keizo|bounty"),
    top: int = typer.Option(10, "--top", help="How many programs to list"),
    refresh: bool = typer.Option(False, "--refresh", help="Force re-fetch (ignore 24h cache)"),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    programs = _load(refresh)
    now = time.time()
    rows = []
    for p in programs:
        if p.get("status") not in (3, 4):
            continue
            
        row = _row(p)
        if row["max_bounty"] < min_bounty:
            continue
            
        payout = min(1.0, math.log10(1.0 + row["max_bounty"]) / 6.0)
        open_gate = 1.0
        
        updated_at = p.get("lastUpdatedAt") or p.get("createdAt") or now
        age_days = (now - updated_at) / (24 * 3600)
        fresh = max(0.0, 1.0 - (age_days / 365.0))
        
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
            typer.echo(f"Keizo ranking (Intigriti, max>={min_bounty:g}):")
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


@app.command(name="meta")
def show_meta(
    slug: str = typer.Argument(..., help="Program handle, e.g. 'doccle'"),
):
    """One program: reward (native currency), status, and what Intigriti does NOT publish."""
    hit = next((_row(p) for p in _load() if p["handle"] == slug), None)
    if hit is None:
        typer.echo(f"not in public catalog: {slug}", err=True)
        raise typer.Exit(1)
    cur = hit["currency"] or "?"
    typer.echo(f"{hit['title']}  ({slug})")
    typer.echo(f"  max reward   : {hit['max_bounty']:,.0f} {cur}   (native, unconverted)")
    typer.echo(f"  min reward   : {hit['min_bounty']:,.0f} {cur}")
    typer.echo(f"  company      : {hit['company']}")
    typer.echo(f"  status       : {hit['status']}")
    typer.echo(f"  ToS accept   : {hit['tac_required']}   2FA: {hit['two_factor']}")
    typer.echo(f"  industry     : {hit['type']}")
    if hit["currency"] != "USD":
        typer.echo(
            f"  ! quoted in {cur}. Amounts are NOT converted to USD - a stale FX\n"
            f"    rate would mis-rank against USD-denominated programs on other platforms."
        )
    typer.echo(
        "  rep gate     : unknown (not published)\n"
        "  reports      : unknown (not published)\n"
        "  scope type   : unknown (not published)\n"
        "  audit status : unknown <- absence of data is NOT evidence of no audit"
    )


@app.command(name="scope")
def show_scope(
    slug: str = typer.Argument(..., help="Program handle"),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """In-scope addresses/repos from the program page.

    KNOWN LIMIT: the Intigriti program page is a client-rendered SPA with no
    public scope endpoint (checked /api/core/public/programs/<id> and /scope),
    both of which return HTML, not JSON. This fails loudly rather than
    reporting zero addresses.
    """
    hit = next((p for p in _load() if p["handle"] == slug), None)
    if hit is None:
        typer.echo(f"not in public catalog: {slug}", err=True)
        raise typer.Exit(1)
    url = _row(hit)["url"]
    try:
        req = urllib.request.Request(
            url, headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/140"}
        )
        with urllib.request.urlopen(req, timeout=45) as resp:
            raw = resp.read().decode("utf-8", "ignore")
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        typer.echo(f"program page unavailable: {exc}", err=True)
        raise typer.Exit(1)
    addrs = sorted(set(re.findall(r"0x[a-fA-F0-9]{40}", raw)))
    repos = sorted(set(re.findall(r"https?://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", raw)))
    if not addrs and not repos:
        typer.echo(
            f"{slug}: page is client-rendered; Intigriti publishes no public scope\n"
            "  endpoint. Read the in-scope assets off the program page directly.\n"
            "  This is a platform limit, not an empty result."
        )
        raise typer.Exit(1)
    typer.echo(f"{slug}: {len(addrs)} address(es), {len(repos)} repo(s)")
    for a in addrs:
        typer.echo(f"  {a}")
    for r in repos:
        typer.echo(f"  repo: {r}")
    if json_output:
        typer.echo(json.dumps({"slug": slug, "addresses": addrs, "repos": repos}, indent=2))
