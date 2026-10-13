#!/usr/bin/env python3
"""Scan Immunefi programs and rank a thin-audit shortlist.

This is the target-selection engine for bug bounty hunting. Instead of spending time on
heavily-audited majors, it ranks programs by the proxy signals of where UNKNOWN bugs live:

    - fresh in-scope smart-contract assets (recently added / recently deployed),
    - on the chain(s) you can actually fork (mainnet / Base / Arbitrum),
    - "reachable" (on-chain, not a private / deployments-only repo).

The output feeds straight into ``cs_fetch`` (index deployed source) + the graph queries
(``cs_trace`` / ``cs_cross`` / ``cs_summary --attack-surface``).

    python cs_scan.py --recent-since 2025-06-01 --top 20
    python cs_scan.py --slugs "etherfi ondofinance olympus" --json
"""
from __future__ import annotations

import sys
from pathlib import Path

_PARENT = str(Path(__file__).resolve().parent.parent)
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)


import re
import typing
import urllib.request

import typer

from core.cs_discover import fetch_assets

app = typer.Typer()

_REACHABLE_HOSTS = ("etherscan.io", "basescan.org", "arbiscan.io")


def _scan_one(slug: str, recent_since: str) -> dict[str, typing.Any]:
    try:
        assets = fetch_assets(slug)
    except Exception as exc:  # noqa: BLE001
        return {"slug": slug, "error": str(exc)}
    reachable = [a for a in assets if any(h in a["url"] for h in _REACHABLE_HOSTS)]
    recent = [a for a in reachable if a["addedAt"] >= recent_since]
    return {
        "slug": slug,
        "assets": len(assets),
        "reachable": len(reachable),
        "recent": len(recent),
        "newest": max((a["addedAt"] for a in recent), default=""),
    }


def _all_slugs() -> list[str]:
    with urllib.request.urlopen(urllib.request.Request(
        "https://immunefi.com/bug-bounty/", headers={"User-Agent": "Mozilla/5.0"}
    ), timeout=30) as resp:
        raw = resp.read().decode("utf-8", "ignore")
    seen: set[str] = set()
    return [s for s in re.findall(r'/bug-bounty/([a-z0-9][a-z0-9\-]*)/', raw)
            if not (s in seen or seen.add(s))]


@app.command()
def scan(
    recent_since: str = typer.Option("2025-06-01", "--recent-since", help="'Recent' cutoff (YYYY-MM-DD)"),
    top: int = typer.Option(20, "--top", help="How many thin-audit programs to list"),
    slugs: str = typer.Option("", "--slugs", help="Comma/space list to scan (defaults to all discovered)"),
    workers: int = typer.Option(16, "--workers", help="Concurrent fetches"),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    top = int(top)
    workers = int(workers)
    slug_list = [s for s in slugs.replace(",", " ").split() if s] if slugs else _all_slugs()

    results: list[dict[str, typing.Any]] = []
    if workers > 1:
        from concurrent.futures import ThreadPoolExecutor, as_completed
        with ThreadPoolExecutor(max_workers=workers) as pool:
            for fut in as_completed([pool.submit(_scan_one, s, recent_since) for s in slug_list]):
                results.append(fut.result())
    else:
        for s in slug_list:
            results.append(_scan_one(s, recent_since))

    results.sort(key=lambda r: (r.get("recent", 0), r.get("newest", "")), reverse=True)
    good = [r for r in results if r.get("recent", 0) > 0]

    if not good:
        typer.echo(f"No program has recent reachable in-scope smart-contract assets (>= {recent_since}).", err=True)
        raise typer.Exit(1)

    typer.echo(f"Scanned {len(slug_list)} program(s). Thin-audit shortlist "
               f"(reachable in-scope smart-contract assets added >= {recent_since}):")
    for r in good[:top]:
        typer.echo(
            f"  {r['slug']:22} recent_mainnet_sc={r['recent']:3}  newest_add={r['newest'][:10]}  "
            f"(total=[{r['assets']}, reachable={r['reachable']}])"
        )
    if json_output:
        typer.echo(__import__("json").dumps(good, indent=2))


if __name__ == "__main__":
    app()
