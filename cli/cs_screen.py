#!/usr/bin/env python3
"""Cross-platform bug-bounty screener (Immunefi + HackenProof).

Why this exists
---------------
Across a 2026-09-28/30 session, nine programs were triaged and none yielded a
submittable finding. The root cause was target selection, not effort: the
signal used to rank candidates (`audits[]` on Immunefi) does not record audit
*coverage* - only whether a program chose to fill in a field. GMX, Chainlink,
Wormhole and Arbitrum all report zero while being among the most reviewed
codebases in web3. That mis-signal repeatedly surfaced mature programs, which
is the worst place to look for a novel Critical.

This screener exists to make that failure mode explicit rather than silent:

  * It NEVER asserts a program is unaudited. Absence of evidence is reported as
    `unknown`, never as `no`.
  * `audit` flags on BOTH platforms are shown but explicitly marked unreliable
    (every HackenProof program returns False, so the flag does not discriminate).
  * The one genuinely reliable thin-hunt signal available without network calls
    is the **report count**: a program with few reports has had less attention.
  * Every shortlisted row is emitted as a VERIFICATION TASK, not a verdict.

Usage
-----
    python -m cli screen --top 20
    python -m cli screen --platform hackenproof --min-bounty 100000
    python -m cli screen --json
"""
from __future__ import annotations

import sys
from pathlib import Path

_PARENT = str(Path(__file__).resolve().parent.parent)
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)

import json
import typing

import typer

app = typer.Typer()

# Platforms that are known to carry unreliable audit metadata. Kept explicit so
# the caveat travels with the data rather than living only in the notes.
AUDIT_FLAG_RELIABLE = {"immunefi": False, "hackenproof": False}
AUDIT_FLAG_CAVEAT = {
    "immunefi": "audits[] is empty for GMX/Chainlink/Arbitrum/Wormhole, all heavily audited",
    "hackenproof": "audit=False for all 15 smart-contract programs in the current catalog; does not discriminate",
}


def _norm(v: typing.Any) -> float:
    try:
        return float(v or 0)
    except (TypeError, ValueError):
        return 0.0


def _immunefi_rows() -> list[dict[str, typing.Any]]:
    try:
        from cli import cs_immune as m
    except Exception:
        return []
    out: list[dict[str, typing.Any]] = []
    try:
        progs = m._load(refresh=False)
    except Exception:
        return []
    for p in progs:
        try:
            r = m._row(p)
        except Exception:
            continue
        if not r.get("max_bounty"):
            continue
        out.append(
            {
                "platform": "immunefi",
                "slug": r.get("slug"),
                "project": r.get("project") or r.get("slug"),
                "url": r.get("url"),
                "ceiling": _norm(r.get("max_bounty")),
                "rep_req": None,                      # Immunefi has no rep gate
                "reports": None,                      # not published
                "fee": None,                          # pay-to-submit varies; not in payload
                "poc": bool(r.get("poc")),
                "kyc": bool(r.get("kyc")),
                "primacy_critical": r.get("primacy_critical"),
                "audit_flag": r.get("audit_evidence"),
                "audit_detail": (r.get("audit_firms") or [])[:4],
                "launched": r.get("launch_date"),
                "updated": r.get("updated_date"),
            }
        )
    return out


def _hackenproof_rows(top: int = 120) -> list[dict[str, typing.Any]]:
    try:
        from cli import cs_hacken as m
    except Exception:
        return []
    progs = []
    try:
        progs = m._load(refresh=False)[:top]
    except Exception:
        return []
    out: list[dict[str, typing.Any]] = []
    for p in progs:
        # `sc` is derived from labels.types (the API has no stored flag), same as
        # cs_hacken._row. Reading a stored `sc` key silently returns nothing.
        labels = p.get("labels") or {}
        if "smart contract" not in (labels.get("types") or []):
            continue
        mb = _norm(p.get("max_bounty"))
        if mb <= 0:
            continue
        out.append(
            {
                "platform": "hackenproof",
                "slug": p.get("slug"),
                "project": p.get("title") or p.get("slug"),
                "url": p.get("url"),
                "ceiling": mb,
                "rep_req": p.get("rep"),
                # the API field is submitted_reports, not reports (silent n/a if wrong)
                "reports": p.get("submitted_reports"),
                "fee": _norm(p.get("fee")),
                "poc": bool(p.get("poc")),
                "kyc": bool(p.get("kyc")),
                "primacy_critical": None,             # HackenProof uses its own model
                "audit_flag": bool(p.get("audit")),
                "audit_detail": p.get("audit_program") or "",
                "launched": None,
                "updated": None,
            }
        )
    return out


def _bugcrowd_rows() -> list[dict[str, typing.Any]]:
    """Bugcrowd: catalog only. No rep gate, fee, report count or audit field."""
    try:
        from cli import cs_bugcrowd as m
        progs = m._load(refresh=False)
    except Exception:
        return []
    out = []
    for p in progs:
        if not p.get("max_bounty"):
            continue
        out.append({
            "platform": "bugcrowd",
            "slug": p.get("slug"),
            "project": p.get("project"),
            "url": p.get("url"),
            "ceiling": float(p.get("max_bounty") or 0),
            "rep_req": p.get("rep_req"),
            "reports": p.get("reports"),
            "fee": p.get("fee"),
            "poc": p.get("poc"),
            "kyc": None,
            "primacy_critical": None,
            "audit_flag": p.get("audit_status") not in (None, "unknown"),
            "audit_detail": p.get("reward_summary"),
            "launched": None,
            "updated": None,
            "scope_rank": p.get("scope_rank"),
        })
    return out


def _thin_hunt(reports: typing.Any, ceiling: float) -> float:
    """Reliable signal: few reports relative to ceiling = less attention.

    Programs with no published count (Immunefi) get a neutral 0.5 rather than a
    flattering score -- absence of a report count is not evidence of a thin hunt.
    """
    if reports is None:
        return 0.5
    try:
        r = float(reports)
    except (TypeError, ValueError):
        return 0.5
    if r <= 0:
        return 1.0
    # 50 reports -> ~1.0 ; 2000 reports -> ~0.05
    return max(0.0, min(1.0, 50.0 / r))


def _freshness(launched: typing.Any, updated: typing.Any) -> float | None:
    """Prefer launch date over 'last updated'.

    Updating a program page is not new code. Launching one is. Where no launch
    date is published the field is None (unknown) rather than guessed.
    """
    for v in (launched, updated):
        if not v or len(str(v)) < 10:
            continue
        y = int(str(v)[:4])
        if 2015 <= y <= 2100:
            return y
    return None


def screen_rows(
    platform: str = "all",
    min_bounty: float = 0.0,
    rep_max: int = 80,
    require_free: bool = False,
) -> list[dict[str, typing.Any]]:
    rows: list[dict[str, typing.Any]] = []
    if platform in ("all", "immunefi"):
        rows += _immunefi_rows()
    if platform in ("all", "hackenproof"):
        rows += _hackenproof_rows()
    if platform in ("all", "bugcrowd"):
        rows += _bugcrowd_rows()

    out: list[dict[str, typing.Any]] = []
    for r in rows:
        if r["ceiling"] < min_bounty:
            continue
        if r["rep_req"] is not None and r["rep_req"] > rep_max:
            continue
        if require_free and r["fee"]:
            continue
        year = _freshness(r.get("launched"), r.get("updated"))
        thin = _thin_hunt(r.get("reports"), r["ceiling"])
        # payout: log scale, saturating around 1M
        import math

        payout = min(1.0, math.log10(1.0 + r["ceiling"]) / 6.0)
        # Programs with no published report count cannot be ranked on thin-hunt,
        # so give the neutral 0.5 and let payout/breadth decide. Inventing a thin
        # signal is what misled this session five times.
        breadth = 0.0
        if r.get("scope_rank"):
            breadth = 1.0 / max(1.0, float(r["scope_rank"]))
        score = round(
            0.40 * thin + 0.30 * payout + 0.15 * breadth
            + 0.15 * (1.0 if not r["audit_flag"] else 0.0),
            3,
        )
        r["score"] = score
        r["thin_hunt"] = round(thin, 3)
        r["launch_year"] = year
        r["scope_breadth"] = round(breadth, 3)
        r["audit_status"] = "unknown"  # never asserts "unaudited"
        out.append(r)
    out.sort(key=lambda x: x["score"], reverse=True)
    return out


@app.command(name="run")
def run(
    platform: str = typer.Option("all", "--platform",
        help="all | immunefi | hackenproof | bugcrowd | intigriti | sherlock | google"),
    min_bounty: float = typer.Option(0, "--min-bounty", help="Min ceiling in USD"),
    rep_max: int = typer.Option(80, "--rep-max", help="Max reputation requirement"),
    require_free: bool = typer.Option(False, "--require-free", help="Only free-to-submit programs"),
    top: int = typer.Option(20, "--top", help="How many to show"),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Shortlist targets ACROSS platforms, for audit verification before any code reading."""
    rows = screen_rows(platform, min_bounty, rep_max, require_free)
    if not rows:
        typer.echo("No programs matched.", err=True)
        raise typer.Exit(1)

    typer.echo(f"  {len(rows)} candidate(s) across platforms.\n")
    typer.echo(f"  {'score':>5} {'thin':>5} {'ceil':>10} {'rep':>4} {'rpts':>5} {'plat':>11}  program")
    typer.echo("  " + "-" * 92)
    for r in rows[:top]:
        rep = "-" if r["rep_req"] is None else str(r["rep_req"])
        rpts = "n/a" if r["reports"] is None else str(r["reports"])
        yr = r["launch_year"] or "?"
        typer.echo(
            f"  {r['score']:>5.3f} {r['thin_hunt']:>5.2f} ${r['ceiling']:>9,.0f} {rep:>4} {rpts:>5} "
            f"{r['platform']:>11}  {(r['project'] or '')[:40]} (launch {yr})"
        )

    typer.echo("\n  !  audit coverage is UNKNOWN for every row - the audit flags on both")
    typer.echo("     platforms are unreliable (see AUDIT_FLAG_CAVEAT). This list is a")
    typer.echo("     prompt to verify, not a ranking of unaudited code. Verify by hand:")
    typer.echo("     1. read the program page for audit links (Immunefi renders these in HTML)")
    typer.echo("     2. search '<project> audit' for reports, incl. security/ repos")
    typer.echo("     3. only then read code; and require a fork PoC before any write-up")
    typer.echo(f"\n     immunefi : {AUDIT_FLAG_CAVEAT['immunefi']}")
    typer.echo(f"     hackenproof: {AUDIT_FLAG_CAVEAT['hackenproof']}")
    if json_output:
        typer.echo(json.dumps(rows[:top], indent=2, default=str))


if __name__ == "__main__":
    app()
