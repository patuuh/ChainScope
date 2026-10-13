#!/usr/bin/env python3
"""Study what pays - the BountySkiller idea, adapted to crypto.

Wesley Thijs' `BountySkiller` pulls recently-disclosed reports to show which bug classes are
actually landing. For crypto the equivalent signal is the exploit feed: what is getting hit
right now. `cs_pays` aggregates the rekt.news incidents into the classes/chains/projects
currently landing, so a hunt can bias toward them (bridge/replay, access control, accounting
desync, governance, key/RNG, ...).

    python cs_pays.py                 # recent incidents + class frequency
    python cs_pays.py --limit 20      # more incidents
    python cs_pays.py --json          # machine-readable

Complements cs_watch (which tells you *where* to hunt) with *what* is paying.
"""
from __future__ import annotations

import sys
from pathlib import Path

_PARENT = str(Path(__file__).resolve().parent.parent)
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)


import collections
import json
import re
import typing
import urllib.parse
import urllib.request

import typer

app = typer.Typer()

# tag labels that are noise rather than a class/chain/project
_NOISE = {"rekt"}


def _get(url: str, timeout: int = 30) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8", "ignore")


def _incidents(raw: str) -> list[dict[str, typing.Any]]:
    """Extract (title, slug, date, tags) for each incident block on the rekt.news home page."""
    # split on the per-incident anchors: href="/<slug>" near a "##### [Title]"
    blocks = re.split(r'(?=<h5[^>]*>)', raw)
    out: list[dict[str, typing.Any]] = []
    for b in blocks:
        m = re.search(r'<h5[^>]*>\s*<a[^>]*href="/([a-z0-9-]+)"[^>]*>(.*?)</a>', b, re.S)
        if not m:
            continue
        slug, title = m.group(1), re.sub(r"<[^>]+>", "", m.group(2)).strip()
        d = re.search(r"((?:Mon|Tues|Wednes|Thurs|Fri|Satur|Sun)day, [A-Z][a-z]+ \d{1,2}, 202\d)", b)
        tags = [urllib.parse.unquote(t.replace("+", " "))
                for t in re.findall(r"/\?tag=([A-Za-z0-9+%._-]+)", b)]
        out.append({"slug": slug, "title": title, "date": d.group(1) if d else None,
                    "tags": [t for t in tags if t.lower() not in _NOISE]})
    return out


@app.command()
def pays(
    limit: int = typer.Option(12, "--limit", help="How many recent incidents to show"),
    json_output: bool = typer.Option(False, "--json", help="Print JSON"),
):
    try:
        raw = _get("https://rekt.news/")
    except Exception as exc:  # noqa: BLE001
        typer.echo(f"cs_pays: could not reach rekt.news ({exc})", err=True)
        raise typer.Exit(1)

    incidents = _incidents(raw)

    freq: collections.Counter[str] = collections.Counter()
    for inc in incidents:
        for t in inc["tags"]:
            freq[t] += 1

    if json_output:
        typer.echo(json.dumps({"incidents": incidents, "tag_frequency": freq.most_common()},
                              indent=2))
        return

    typer.echo("=== what is getting hit (rekt.news, most recent) ===")
    for inc in incidents[:limit]:
        tags = ", ".join(inc["tags"])
        typer.echo(f"- {inc['date'] or '?':<26} {inc['title'][:46]:<46} [{tags}]")
    typer.echo("")
    typer.echo("=== class / chain / project frequency (this page) ===")
    for tag, n in freq.most_common(25):
        typer.echo(f"  {n:>2}x  {tag}")
    typer.echo("")
    typer.echo("Bias your next hunt toward the top classes (bridge/replay, access control,")
    typer.echo("accounting desync, oracle, governance, key/RNG). cs_watch says where; cs_pays says what.")


if __name__ == "__main__":
    app()
