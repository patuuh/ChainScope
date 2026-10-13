"""`python -m cli gate` - pre-reading admissibility screen for a bounty target."""
from __future__ import annotations

import json
import typing as t
from pathlib import Path

import typer

from core.cs_gate import gate_programs, gate_repo
from core import deploy_source

app = typer.Typer(help="Screen targets for admissibility before reading any code.")


@app.command(name="repo")
def gate_repo_cmd(
    path: str = typer.Argument(..., help="Path to a local git repository"),
    audit_date: str = typer.Option("", "--audit-date", help="Override audit baseline (ISO date)"),
    audits_dir: str = typer.Option("", "--audits-dir", help="Extra directory holding audit reports (separate corpus repo)"),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Gate a single local repository: audit baseline, uncovered delta, reachability."""
    extra = [d.strip() for d in audits_dir.split(",") if d.strip()] if audits_dir else None
    result = gate_repo(Path(path), audit_date=audit_date or None, audits_dir=extra)
    if json_output:
        typer.echo(json.dumps(result, indent=2))
        return
    _print_repo(result)


@app.command(name="program")
def gate_program_cmd(
    slug: str = typer.Argument(..., help="Program slug, e.g. gamma"),
    repos: str = typer.Option("", "--repos", help="Comma-separated local repo paths for this program"),
    check_sources: bool = typer.Option(False, "--check-sources", help="Probe in-scope addresses for Sourcify-verified source"),
    max_addresses: int = typer.Option(10, "--max-addresses", help="How many addresses to probe"),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Gate a program: requires retrievable source (check 1) plus repo gates."""
    from cli.cs_immune import _scope

    local = [p.strip() for p in repos.split(",") if p.strip()]
    addrs: list[str] = []
    scope_error = None
    try:
        scope = _scope(slug)
        addrs = [f"{a['chain']}:{a['address']}" for a in scope.get("addresses", [])]
        remote_repos = scope.get("repos", []) or []
    except Exception as exc:  # noqa: BLE001
        scope_error = str(exc)
        remote_repos = []

    coverage = None
    if check_sources and addrs:
        coverage = deploy_source.coverage(addrs, limit=max_addresses)

    if local:
        result = gate_programs([{"name": slug, "repos": local, "addresses": addrs}])[0]
    else:
        result = {
            "name": slug,
            "verdict": "REJECT",
            "blockers": ["NO_LOCAL_REPO"],
            "repos": [],
            "remote_repos": remote_repos,
        }

    result["scope"] = {
        "in_scope_addresses": len(addrs),
        "remote_repos": remote_repos,
        "error": scope_error,
    }
    if coverage is not None:
        result["source_coverage"] = coverage
        verified = len(coverage.get("verified", []))
        if not local and verified == 0:
            result["verdict"] = "REJECT"
            result["blockers"] = list(result["blockers"]) + ["NO_RETRIEVABLE_SOURCE"]
        elif not local and verified:
            result["verdict"] = "NEEDS_DEPLOYED_REVIEW"
            result["blockers"] = list(result["blockers"]) + ["NO_LOCAL_REPO_BUT_VERIFIED_SOURCE"]

    if json_output:
        typer.echo(json.dumps(result, indent=2))
        return
    typer.echo(f"{slug}: {result['verdict']}")
    typer.echo(f"  scope: {len(addrs)} address(es), {len(remote_repos)} remote repo(s)"
               + (f"  [scope error: {scope_error}]" if scope_error else ""))
    for g in result.get("repos", []):
        _print_repo(g, indent="  ")
    cov = result.get("source_coverage")
    if cov:
        typer.echo(f"  sourcify: {len(cov.get('verified', []))} verified / "
                   f"{len(cov.get('unverified', []))} unverified / "
                   f"{len(cov.get('unreachable', []))} unreachable")
    for b in result.get("blockers", []):
        typer.echo(f"  BLOCKER {b}")


def _print_repo(g: dict, indent: str = "") -> None:
    typer.echo(f"{indent}{Path(g['repo']).name}: {g['verdict']}")
    typer.echo(f"{indent}  audits={g['audit_count']}  baseline={g.get('baseline_used')} "
               f"(detected={g.get('latest_audit_detected')})"
               + ("  [LOW CONFIDENCE]" if g.get("baseline_low_confidence") else "")
               + ("  [overridden]" if g.get("baseline_overridden") else ""))
    for a in g.get("audits", [])[:6]:
        firm = a.get("firm") or "-"
        typer.echo(f"{indent}    {str(a.get('date')):<12} {firm:<14} {a['file']}")
    typer.echo(f"{indent}  uncovered .sol files: {g['delta_files']}  {g.get('reachability', {}).get('totals')}")
    for pf in g.get("reachability", {}).get("files", []):
        for f in pf["permissionless"][:6]:
            typer.echo(f"{indent}    PERMISSIONLESS {pf['path']}:{pf['last_change']}  {f['name']}")
    for w in g.get("warnings", []):
        typer.echo(f"{indent}  WARNING {w}")
    for b in g.get("blockers", []):
        typer.echo(f"{indent}  BLOCKER {b}")


if __name__ == "__main__":
    app()