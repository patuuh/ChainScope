#!/usr/bin/env python3
"""Report security-relevant divergence between a deployed contract and a repo.

For many bug-bounty targets the in-scope asset is the *deployed* contract while
the repository HEAD can differ materially (guards removed, functions added,
storage reshaped). ``cs_divergence`` fetches the Sourcify-verified deployed
source, builds a graph for it, builds a graph for the repo, and reports the
deltas that matter for security review:

    functions added/removed, guard/modifier changes, state-write changes,
    sink (fund-transfer/delegatecall) changes, and state-var differences.

Examples:
    python cs_divergence.py 534352:0x7Ca0b75E67E33c0014325B739A8d019C4FE445F0 --repo ../EtherFi/cash-v3
    python cs_divergence.py 1:0xCd5fE23C85820F7B72D0926FC9b05b43E359b7ee --repo ../Immunefi/weeth-xc --json
    # reuse already-built graphs (fast):
    python cs_divergence.py 1:0x... --repo ./repo --deployed-db dep.db --repo-db repo.db
"""
from __future__ import annotations

import sys
from pathlib import Path

_PARENT = str(Path(__file__).resolve().parent.parent)
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)


import json
import os
import tempfile

import typer

import mcp_server
from core import deploy_source
from core.divergence import diff_graphs, format_report

app = typer.Typer()

CACHE_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".chainsource")


@app.command()
def divergence(
    spec: str = typer.Argument(..., help="chain:address of the deployed contract (e.g. 534352:0x...)"),
    repo: str = typer.Option(..., "--repo", help="Path to the source repository to compare against"),
    deployed_db: str = typer.Option("", "--deployed-db", help="Reuse an existing deployed graph instead of building"),
    repo_db: str = typer.Option("", "--repo-db", help="Reuse an existing repo graph instead of building"),
    out: str = typer.Option("", "--out", help="Write the JSON report to this path"),
    json_output: bool = typer.Option(False, "--json", help="Output JSON"),
    contract: str = typer.Option("", "--contract", help="Only compare functions of this contract (e.g. CashModuleCore)"),
    max_items: int = typer.Option(40, "--max-items", help="Max items per section in text output"),
    timeout_seconds: int = typer.Option(0, "--timeout-seconds", help="Per-build timeout (0 = no limit)"),
    include_research: bool = typer.Option(False, "--include-research", help="Index scripts/tests too"),
):
    try:
        label, addr = spec.rsplit(":", 1)
        chain = deploy_source.chain_id(label)
    except Exception as exc:  # noqa: BLE001
        typer.echo(f"bad spec: {exc}", err=True)
        raise typer.Exit(1)

    tmpdir = tempfile.mkdtemp(prefix="cs_divergence_")

    # 1) Deployed graph
    if deployed_db:
        dep_db = deployed_db
    else:
        src_dir = os.path.join(CACHE_ROOT, str(chain), addr.lower())
        if not os.path.isdir(src_dir) or not any(os.scandir(src_dir)):
            typer.echo(f"Fetching verified source for {chain}:{addr} ...")
            try:
                deploy_source.fetch_sourcify_source(chain, addr, src_dir)
            except Exception as exc:  # noqa: BLE001
                typer.echo(f"source fetch failed: {exc}", err=True)
                raise typer.Exit(1)
        dep_db = os.path.join(tmpdir, "deployed.db")
        typer.echo("Building deployed graph ...")
        res = json.loads(mcp_server.cs_build(
            repo_path=src_dir, db=dep_db, lang="",
            include_research=include_research,
            timeout_seconds=timeout_seconds, max_failure_examples=5,
        ))
        if "error" in res:
            typer.echo(res["error"], err=True)
            raise typer.Exit(1)
        typer.echo(f"  deployed: {res['nodes']} nodes, {res['edges']} edges")

    # 2) Repo graph
    if repo_db:
        rep_db = repo_db
    else:
        rep_db = os.path.join(tmpdir, "repo.db")
        typer.echo(f"Building repo graph for {repo} ...")
        res = json.loads(mcp_server.cs_build(
            repo_path=repo, db=rep_db, lang="",
            include_research=include_research,
            timeout_seconds=timeout_seconds, max_failure_examples=5,
        ))
        if "error" in res:
            typer.echo(res["error"], err=True)
            raise typer.Exit(1)
        typer.echo(f"  repo: {res['nodes']} nodes, {res['edges']} edges")

    report = diff_graphs(dep_db, rep_db, contract=contract)
    report["deployed"] = {"chain": chain, "address": addr, "db": dep_db}
    report["repo"] = {"path": repo, "db": rep_db}

    if out:
        with open(out, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2)
        typer.echo(f"wrote {out}")

    if json_output:
        typer.echo(json.dumps(report, indent=2))
        return

    typer.echo("")
    typer.echo(format_report(report, max_items=max_items))
    if not report["has_divergence"]:
        typer.echo(
            "\nNo security-relevant divergence detected "
            "(deployed and repo match at graph granularity)."
        )


if __name__ == "__main__":
    app()
