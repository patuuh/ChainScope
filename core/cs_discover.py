#!/usr/bin/env python3
"""Discover recently-added in-scope smart-contract assets for an Immunefi bounty program.

This closes the "target discovery" gap: ChainScope can index any local repo, but it can't
tell you *what* to index. This tool scans a program's Immunefi scope page and lists the
in-scope smart-contract assets (with the date they were added), so you can pick the
freshest (least-audited) targets and feed them straight to ``cs_fetch`` / ``cs_build``.

    python cs_discover.py etherfi --recent-since 2025-01-01
    python cs_discover.py magpiexyz --json
"""
from __future__ import annotations

import sys
from pathlib import Path

_PARENT = str(Path(__file__).resolve().parent.parent)
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)


import json
import re
import urllib.request
import typing

import typer

app = typer.Typer()

_SCOPE_URL = "https://immunefi.com/bug-bounty/{slug}/scope/"


def _escaped_json_to_text(raw: str) -> str:
    """Undo the double-encoding used to embed JSON in the scope page."""
    return raw.replace('\\\\"', '"').replace('\\\\', '\\').replace('\\"', '"')


_FIELD = re.compile(r'\\?"([a-zA-Z0-9_]+)\\?":\\?"((?:[^"\\]|\\.)*)\\?"')


def _field(obj: str, key: str) -> str:
    """Extract a string field value from an escaped asset object (tolerant of `\\"`)."""
    m = re.search(r'\\?"' + re.escape(key) + r'\\?":\\?"((?:[^"\\]|\\.)*?)\\?"', obj)
    if not m:
        return ""
    return m.group(1).replace('\\"', '"').replace('\\\\', '\\')


def fetch_assets(slug: str, timeout: int = 30) -> list[dict[str, typing.Any]]:
    req = urllib.request.Request(
        _SCOPE_URL.format(slug=slug), headers={"User-Agent": "Mozilla/5.0"}
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        raw = resp.read().decode("utf-8", "ignore")

    # The scope page serialises each asset as a flat JSON object (with escaped quotes).
    # Match flat brace objects only (no nested braces) like the working manual extractor.
    objects = set(re.findall(r'\{[^{}]*?\}', raw))
    seen: set[str] = set()
    assets: list[dict[str, typing.Any]] = []
    for obj in objects:
        if "smart_contract" not in obj:
            continue
        url = _field(obj, "url")
        added = _field(obj, "addedAt")
        desc = _field(obj, "description") or _field(obj, "name")
        if not url or url in seen:
            continue
        seen.add(url)
        if ("scan.io/address" in url or "scan.com/address" in url or "github.com" in url):
            assets.append({
                "url": url,
                "addedAt": added[:10],
                "description": desc,
                "chain": url.split("/")[2].split(".")[0],
            })
    return assets


@app.command()
def discover(
    slug: str = typer.Argument(..., help="Immunefi program slug (e.g. 'etherfi', 'magpiexyz')"),
    recent_since: str = typer.Option(None, "--recent-since", help="Only show assets added on/after this date (YYYY-MM-DD)"),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    assets = fetch_assets(slug)

    if recent_since:
        assets = [a for a in assets if a["addedAt"][:10] >= recent_since]
        assets.sort(key=lambda a: a["addedAt"])

    if not assets:
        typer.echo(f"No in-scope smart-contract assets parsed for '{slug}'. "
                   "(The page may be fully client-rendered; check the raw response.)", err=True)
        raise typer.Exit(1)

    for a in assets:
        host = a["url"].split("/")[2] if "://" in a["url"] else a["url"]
        typer.echo(f"{a['addedAt'][:10]:12} {host:18} {a['description'] or a['url'][:30]}")

    if json_output:
        typer.echo(json.dumps(assets, indent=2))

    typer.echo(f"\n{len(assets)} in-scope smart-contract asset(s). Feed a contract to "
               "cs_fetch for graph-backed targeting.")


if __name__ == "__main__":
    app()
