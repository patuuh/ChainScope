#!/usr/bin/env python3

import sys
from pathlib import Path

_PARENT = str(Path(__file__).resolve().parent.parent)
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)

"""Fetch Sourcify-verified deployed source for a contract and build a ChainScope graph.

This closes the "private / deployments-only repo" gap: many in-scope targets only expose
a deployed (Sourcify-verified) contract. Use a chain:address spec (chain can be a numeric
id, an explorer host like ``etherscan.io``, or a name like ``base``/``arb``/``hyperevm``):

    python cs_fetch.py 1:0x1234... --db graph.db
    python cs_fetch.py base:0xabcd... etherscan.io:0x1234... --db base.db
"""
import json
import typer

from core import deploy_source

app = typer.Typer()


@app.command()
def fetch(
    specs: str = typer.Argument(..., help="chain:address spec(s), space or comma separated (e.g. '1:0x... base:0x...')"),
    db: str = typer.Option("graph.db", help="Output database path"),
    out: str = typer.Option(".chainsource", help="Directory to materialise fetched source under"),
    keep_source: bool = typer.Option(False, "--keep-source", help="Leave the fetched source dir on disk"),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    spec_list = [s for s in specs.replace(",", " ").split() if s]

    results = deploy_source.fetch_many(spec_list, base_out=out)

    ok = [r for r in results if "error" not in r]
    bad = [r for r in results if "error" in r]

    for r in ok:
        typer.echo(
            f"[ok] {r['chain']}:{r['address']} match={r['match']} "
            f"verifiedAt={r['verifiedAt'] or '?'} files={r['files']}"
        )
        try:
            import mcp_server
            data = json.loads(mcp_server.cs_build(
                repo_path=r["out_dir"],
                db=db,
                lang="solidity",
                include_research=False,
                timeout_seconds=0,
                max_failure_examples=5,
            ))
            typer.echo(
                f"    graph: {data['nodes']} nodes, {data['edges']} edges, "
                f"{data['files_indexed']}/{data['files_considered']} files, "
                f"confidence={data['confidence']['score']} ({data['confidence']['tier']})"
            )
        except Exception as exc:  # noqa: BLE001
            typer.echo(f"    graph build failed: {exc}", err=True)
    for r in bad:
        typer.echo(f"[err] {r['spec']}: {r['error']}", err=True)

    if json_output:
        typer.echo(json.dumps(results, indent=2))
    typer.echo(f"ok={len(ok)} errors={len(bad)}")
    if bad:
        raise typer.Exit(1)


if __name__ == "__main__":
    app()
