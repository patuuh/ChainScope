#!/usr/bin/env python3
"""Bugcrowd program module.

Bugcrowd exposes a public catalog at `engagements.json` (paginated, 24/page),
which is richer than its `/programs` HTML: it carries `maxReward`,
`scopeRank` and `accessStatus` per program. There is no per-program JSON API
without a session, so metadata beyond these fields is scraped from the brief
page.

What this platform does NOT expose publicly, and what that means:

  * **no reputation gate** - unlike HackenProof, so `--max-rep` is a no-op here
  * **no submission-fee field** - treat as unknown rather than free
  * **no report count** - so there is no thin-hunt proxy at all, which is the
    same limitation that made the report count misleading on HackenProof
  * **no audit metadata** - `meta` scrapes the brief page and reports
    `audit_status: "unknown"` unless an audit link is actually present

That last point is deliberate. Across a 9-program engagement, every attempt to
infer audit coverage from a platform field was falsified: Immunefi reports
`audits: []` for GMX, Chainlink, Arbitrum and Wormhole, all heavily audited,
and every HackenProof smart-contract program returns `audit: false`. So this
module never claims a program is unaudited.
"""
from __future__ import annotations

import sys
from pathlib import Path

_PARENT = str(Path(__file__).resolve().parent.parent)
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)


import json
import math
import re
import time
import typing
import urllib.error
import urllib.request

import typer

app = typer.Typer()

_INDEX = "https://bugcrowd.com/engagements.json?page={page}"
_BRIEF = "https://bugcrowd.com{brief}"
_PAGE_SIZE = 24
_CACHE = Path(_PARENT) / ".chainsource" / "bugcrowd_programs.json"
_TTL = 24 * 3600
_UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36"
_RETRY = 4


def _get(url: str, timeout: int = 45) -> str:
    last: Exception | None = None
    for attempt in range(_RETRY):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": _UA, "Accept": "application/json,text/html"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.read().decode("utf-8", "ignore")
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            last = exc
            time.sleep(1.5 * (attempt + 1))
    raise RuntimeError(f"failed to fetch {url}: {last}")


def _money(text: typing.Any) -> float:
    """Parse a Bugcrowd reward string into a float.

    Observed shapes: `"$150 - $5,000"`, `"Up to $5,000"`, `"Points - $3,000"`,
    and plain numbers. Always take the **upper** bound — a ranker's ceiling
    should reflect the best-case payout, and taking the floor is what made
    Celer read as $200k when the real ceiling was $200k against a $2M tier
    claim elsewhere in the same payload.
    """
    if text is None:
        return 0.0
    if isinstance(text, (int, float)):
        return float(text)
    s = str(text).replace(",", "").replace("$", "")
    nums = re.findall(r"\d+(?:\.\d+)?", s)
    return float(nums[-1]) if nums else 0.0


def _row(e: dict[str, typing.Any]) -> dict[str, typing.Any]:
    rs = e.get("rewardSummary") or {}
    slug = (e.get("briefUrl") or "").rstrip("/").split("/")[-1]
    return {
        "slug": slug,
        "project": e.get("name") or slug,
        "tagline": e.get("tagline"),
        "url": f"https://bugcrowd.com/engagements/{slug}",
        "brief_url": e.get("briefUrl"),
        "max_bounty": max(
            _money(rs.get("maxReward")),
            _money(rs.get("hint")),
            _money(rs.get("compensationSummary")),
        ),
        "min_bounty": _money(rs.get("minReward")),
        "reward_summary": rs.get("summary"),
        "scope_rank": e.get("scopeRank"),
        "access": e.get("accessStatus"),
        "banned": bool(e.get("isBanned")),
        "demo": bool(e.get("isDemo")),
        "private": bool(e.get("isPrivate")),
        "service": e.get("serviceLevel"),
        "kind": (e.get("productEngagementType") or {}).get("label"),
        "industry": e.get("industryName"),
        "ends_at": e.get("endsAt"),
        # Deliberately honest about what Bugcrowd does not publish:
        "rep_req": None,
        "fee": None,
        "reports": None,
        "audit_status": "unknown",
        "poc": None,
    }


def _load(refresh: bool = False) -> list[dict[str, typing.Any]]:
    cached: list[dict[str, typing.Any]] = []
    fresh = False
    if _CACHE.exists():
        try:
            payload = json.loads(_CACHE.read_text())
            cached = payload.get("programs", [])
            fresh = (time.time() - _CACHE.stat().st_mtime) < _TTL
        except (json.JSONDecodeError, OSError):
            cached = []
    if not refresh and fresh and cached:
        return cached

    first = json.loads(_get(_INDEX.format(page=0)))
    total = int((first.get("paginationMeta") or {}).get("totalCount") or 0)
    pages = max(1, math.ceil(total / _PAGE_SIZE)) if total else 1
    raw: list[dict[str, typing.Any]] = list(first.get("engagements") or [])
    for p in range(1, pages):
        try:
            raw.extend(json.loads(_get(_INDEX.format(page=p))).get("engagements") or [])
        except RuntimeError:
            break  # partial catalog beats no catalog

    seen: set[str] = set()
    out: list[dict[str, typing.Any]] = []
    for e in raw:
        r = _row(e)
        if not r["slug"] or r["slug"] in seen or r["banned"] or r["demo"]:
            continue
        seen.add(r["slug"])
        out.append(r)
    _CACHE.parent.mkdir(parents=True, exist_ok=True)
    _CACHE.write_text(json.dumps({"fetched_at": int(time.time()), "programs": out}))
    return out


# Explorer host -> chain spec, for deploy_source in the triage pipeline.
_HOST_CHAINS = {
    "etherscan.io": "1", "arbiscan.io": "42161", "basescan.org": "8453",
    "optimistic.etherscan.io": "10", "polygonscan.com": "137", "bscscan.com": "56",
    "snowtrace.io": "43114", "ftmscan.com": "250", "lineascan.build": "59144",
    "scrollscan.com": "534352", "cronoscan.com": "25", "explorer.zkevm.cronos.org": "388",
    "explorer.morphl2.io": "2818", "hyperevmscan.io": "999", "beratrai.com": "80094",
    "unichain.org": "130", "monadscan.com": "143", "mantlescan.xyz": "5000",
    "seitrace.com": "1329", "rpc.plasma.to": "9745", "explorer.corn.protocol": "9900",
}
_SKIP_HOSTS = {
    "bugcrowd.com", "github.com", "discord.com", "twitter.com", "x.com", "t.me",
    "docs.bugcrowd.com", "media.licdn.com", "gitlab.com", "medium.com",
}


@app.command(name="list")
def list_programs(
    min_bounty: float = typer.Option(0, "--min-bounty", help="Min max-reward in USD"),
    max_rank: int = typer.Option(5, "--max-rank", help="Max scope rank (1 = largest)"),
    top: int = typer.Option(20, "--top", help="How many to list"),
    refresh: bool = typer.Option(False, "--refresh", help="Ignore 24h cache"),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """List public Bugcrowd programs."""
    rows = [p for p in _load(refresh) if p["max_bounty"] >= min_bounty]
    if max_rank:
        rows = [p for p in rows if not p["scope_rank"] or p["scope_rank"] <= max_rank]
    rows.sort(key=lambda p: p["max_bounty"], reverse=True)
    rows = rows[: int(top)]
    if not rows:
        typer.echo("No programs matched.", err=True)
        raise typer.Exit(1)
    if not json_output:
            typer.echo(f"{len(rows)} Bugcrowd program(s):")
            for p in rows:
                rank = p["scope_rank"] or "?"
                typer.echo(
                    f"  ${p['max_bounty']:>10,.0f}  rank={rank:<3} {str(p['access'] or ''):<6} "
                    f"{(p['project'] or '')[:44]}"
                )
            typer.echo(
                "\n  ! Bugcrowd publishes no reputation gate, submission fee, report count or\n"
                "     audit metadata publicly. audit_status is 'unknown' for every program -\n"
                "     verify audit coverage by hand before reading code."
            )
    if json_output:
        typer.echo(json.dumps(rows, indent=2))


@app.command(name="keizo")
def keizo_rank(
    min_bounty: float = typer.Option(0, "--min-bounty", help="Min max-reward in USD"),
    top: int = typer.Option(20, "--top", help="How many to list"),
    refresh: bool = typer.Option(False, "--refresh", help="Ignore 24h cache"),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Rank Bugcrowd programs.

    With no report count and no audit field, the only honest signals are
    reward ceiling and scope rank (1 = the largest programs on the platform).
    A thin-hunt term is deliberately omitted rather than faked.
    """
    rows = [p for p in _load(refresh) if p["max_bounty"] >= min_bounty]
    for p in rows:
        payout = min(1.0, math.log10(1.0 + p["max_bounty"]) / 6.0)
        rank = p["scope_rank"] or 5
        breadth = 1.0 / max(1.0, float(rank))
        p["keizo"] = round(0.65 * payout + 0.35 * breadth, 3)
        p["signals"] = {"payout": round(payout, 3), "scope_breadth": round(breadth, 3)}
    rows.sort(key=lambda p: p["keizo"], reverse=True)
    rows = rows[: int(top)]
    if not rows:
        typer.echo("No programs matched.", err=True)
        raise typer.Exit(1)
    if not json_output:
            typer.echo(f"Keizo ranking (Bugcrowd, min=${min_bounty:,.0f}):")
            for p in rows:
                s = p["signals"]
                typer.echo(
                    f"  keizo={p['keizo']:.3f}  ${p['max_bounty']:>10,.0f}  rank={p['scope_rank'] or '?'}  "
                    f"{p['project'][:40]}"
                )
                typer.echo(f"        payout={s['payout']:.2f} breadth={s['scope_breadth']:.2f}  {p['url']}")
            typer.echo(
                "\n  ! no thin-hunt signal exists on Bugcrowd (no report count), and no audit\n"
                "     field exists. Verify coverage by hand - do not read code first."
            )
    if json_output:
        typer.echo(json.dumps(rows, indent=2))


@app.command(name="meta")
def show_meta(
    slug: str = typer.Argument(..., help="Program slug, e.g. 'wyze' or 'etoro-mbb-og'"),
):
    """One program: reward, rank, access, and any audit reference found on the brief page."""
    hit = next((p for p in _load() if p["slug"] == slug), None)
    if hit is None:
        typer.echo(f"not in public catalog: {slug}", err=True)
        raise typer.Exit(1)
    typer.echo(f"{hit['project']}  ({slug})")
    typer.echo(f"  max reward   : ${hit['max_bounty']:,.0f}   (summary: {hit['reward_summary']})")
    typer.echo(f"  scope rank   : {hit['scope_rank']}")
    typer.echo(f"  access       : {hit['access']}")
    typer.echo(f"  service      : {hit['service']}  kind: {hit['kind']}")
    typer.echo(f"  industry     : {hit['industry']}")
    typer.echo(f"  rep gate     : {hit['rep_req']}   submission fee: {hit['fee']}")
    try:
        raw = _get(_BRIEF.format(brief=hit["brief_url"] or f"/engagements/{slug}"))
    except RuntimeError as exc:
        typer.echo(f"  brief page unavailable: {exc}", err=True)
        return
    firms = sorted({
        f for f in ("Spearbit", "Sigma Prime", "Zellic", "Ackee", "0xLaw", "Trail of Bits",
                    "OpenZeppelin", "Nethermind", "ChainSecurity", "Cantina", "Code4rena",
                    "Hackenproof", "Halborn", "Secure3", "Kudelski", "Consensys")
        if f.lower() in raw.lower()
    })
    urls = sorted({u for u in re.findall(r"https?://[^\s\"'<>]{0,80}audit[^\s\"'<>]{0,60}", raw, re.I)})
    typer.echo(f"  audit firms on page : {firms if firms else 'none detected'}")
    typer.echo(f"  audit urls on page  : {urls[:3] if urls else 'none'}")
    typer.echo("  audit status        : unknown  <- absence of a link is NOT evidence of no audit")


@app.command(name="scope")
def show_scope(
    slug: str = typer.Argument(..., help="Program slug"),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """In-scope contract addresses and code repos from the brief page."""
    hit = next((p for p in _load() if p["slug"] == slug), None)
    if hit is None:
        typer.echo(f"not in public catalog: {slug}", err=True)
        raise typer.Exit(1)
    try:
        raw = _get(_BRIEF.format(brief=hit["brief_url"] or f"/engagements/{slug}"))
    except RuntimeError as exc:
        typer.echo(f"brief page unavailable: {exc}", err=True)
        raise typer.Exit(1)
    addrs: dict[str, dict[str, str]] = {}
    for host, addr in re.findall(
        r"https?://([A-Za-z0-9.-]+)/(?:address|token|account)/(0x[a-fA-F0-9]{40})", raw
    ):
        if host.lower() in _SKIP_HOSTS:
            continue
        addrs.setdefault(addr.lower(), {"chain": _HOST_CHAINS.get(host.lower(), host.lower()),
                                        "address": addr, "host": host.lower()})
    repos = sorted(set(re.findall(r"https?://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", raw)))
    if not addrs and not repos:
        typer.echo(
            f"{slug}: brief page is client-rendered; Bugcrowd exposes no public scope\n"
            "  endpoint (checked /scope/, /api/v1/engagements/, and the RSC bundle -\n"
            "  only auth/session routes). Copy the in-scope addresses from the brief page\n"
            "  and pass them to `bugcrowd triage` via a local scope.json, or read them\n"
            "  off the brief directly. This is a platform limit, not a silent empty result."
        )
        raise typer.Exit(1)
    typer.echo(f"{slug}: {len(addrs)} in-scope address(es), {len(repos)} repo(s)")
    for a in addrs.values():
        typer.echo(f"  {a['chain']:>28}:{a['address']}   ({a['host']})")
    for r in repos:
        typer.echo(f"  repo: {r}")
    if json_output:
        typer.echo(json.dumps({"slug": slug, "addresses": list(addrs.values()), "repos": repos}, indent=2))


@app.command(name="triage")
def triage(
    slug: str = typer.Argument(..., help="Program slug"),
    max_fetch: int = typer.Option(12, "--max-fetch", help="Max in-scope addresses to fetch+index"),
    timeout: int = typer.Option(200, "--timeout", help="Graph build timeout seconds"),
):
    """Automated pipeline: scope -> fetch deployed sources -> build graph -> hotspots.

    Stops at hotspot ranking. Verdict and PoC remain manual.
    """
    import subprocess
    from core import deploy_source

    hit = next((p for p in _load() if p["slug"] == slug), None)
    if hit is None:
        typer.echo(f"not in public catalog: {slug}", err=True)
        raise typer.Exit(1)
    try:
        raw = _get(_BRIEF.format(brief=hit["brief_url"] or f"/engagements/{slug}"))
    except RuntimeError as exc:
        typer.echo(f"brief page unavailable: {exc}", err=True)
        raise typer.Exit(1)
    addrs: dict[str, dict[str, str]] = {}
    for host, addr in re.findall(
        r"https?://([A-Za-z0-9.-]+)/(?:address|token|account)/(0x[a-fA-F0-9]{40})", raw
    ):
        if host.lower() in _SKIP_HOSTS:
            continue
        addrs.setdefault(addr.lower(), {"chain": _HOST_CHAINS.get(host.lower(), host.lower()),
                                        "address": addr, "host": host.lower()})
    selected = list(addrs.values())[: int(max_fetch)]
    typer.echo(f"{slug}: {len(addrs)} in-scope address(es); fetching {len(selected)}.")
    out = f".chainsource/bugcrowd-{slug}"
    specs = [f"{a['chain']}:{a['address']}" for a in selected]
    results = deploy_source.fetch_many(specs, base_out=out) if specs else []
    ok = [r for r in results if "error" not in r]
    for r in results:
        if "error" in r:
            typer.echo(f"  [err] {r.get('spec')}: {r['error']}", err=True)
        else:
            typer.echo(f"  [ok] {r['chain']}:{r['address']} files={r['files']}")
    if not ok:
        typer.echo("No sources fetched; stopping here.", err=True)
        raise typer.Exit(1)
    db = f"bugcrowd-{slug}.db"
    subprocess.run(
        [sys.executable, "-m", "cli", "surface", "surface", db, "--top", "25", "--json"],
        check=False, capture_output=True,
    )
    typer.echo(
        "Next: read flagged functions, adjudicate against the brief's own scope list and\n"
        "published audits, and require a fork PoC before any write-up."
    )


if __name__ == "__main__":
    app()
