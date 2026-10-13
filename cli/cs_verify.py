#!/usr/bin/env python3
"""Shinobi verification CLI (Phase 5): kill-test triage candidates + PoC shells.

    python cs_verify.py status sandbox                      # candidates + kill-test summary
    python cs_verify.py kill sandbox <finding_id>          # full checklist for one candidate
    python cs_verify.py poc sandbox <finding_id>           # PoC shell (curl/bash)
    python cs_verify.py pass sandbox <finding_id>          # mark confirmed (show severity ladder)

Kill-test rules (ChainScope policy): listed impact + defensible $ today;
permissionless; intended-design; PoC rule; duplicates; in-scope; MFA; read vs write.
"""
from __future__ import annotations

import sys
from pathlib import Path

_PARENT = str(Path(__file__).resolve().parent.parent)
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)


import json

import typer

from shinobi import verify as verify_mod
from shinobi.store import Store

app = typer.Typer()
_db = Store()


class _Commands:
    @staticmethod
    def _rows(slug: str) -> list[dict]:
        return [r for r in _db.list_findings(slug) if r.get("status") == "triage"]

    @staticmethod
    def _one(slug: str, finding_id: str) -> dict:
        for r in _Commands._rows(slug):
            if r.get("id") == finding_id or str(r.get("id", "")).startswith(finding_id):
                return r
        typer.echo(f"cs_verify: no triage candidate '{finding_id}' for {slug}", err=True)
        raise typer.Exit(1)

    @staticmethod
    def status(slug: str) -> None:
        rec = _db.get_program(slug)
        if not rec:
            typer.echo(f"cs_verify: no program '{slug}'", err=True)
            raise typer.Exit(1)
        rows = _Commands._rows(slug)
        if not rows:
            typer.echo(f"no triage candidates for {slug} (run cs_prowl first)")
            return
        typer.echo(f"{len(rows)} triage candidates:")
        for r in rows:
            kt = verify_mod.kill_test(rec, r)
            typer.echo(f"- {r['id'][:8]} [{r['vuln_class']}] {r['title'][:70]}")
            typer.echo(f"    {kt.summary()}")

    @staticmethod
    def kill(slug: str, finding_id: str) -> None:
        rec = _db.get_program(slug)
        row = _Commands._one(slug, finding_id)
        kt = verify_mod.kill_test(rec, row)
        typer.echo(f"## {row['title']}")
        for check_id, verdict, note in kt.checks:
            typer.echo(f"  [{verdict.upper():<6}] {check_id}: {note}")
        typer.echo(f"==> {kt.verdict}")

    @staticmethod
    def poc(slug: str, finding_id: str) -> None:
        row = _Commands._one(slug, finding_id)
        typer.echo(verify_mod.build_poc(row))

    @staticmethod
    def pass_(slug: str, finding_id: str) -> None:
        row = _Commands._one(slug, finding_id)
        _db.update_finding(row["id"], status="confirmed", severity="candidate",
                           poc=verify_mod.build_poc(row))
        typer.echo(f"marked confirmed: {row['id'][:8]}")
        typer.echo("severity: derive from impact + the program severity table, then: "
                   "cs_verify severity <slug> <id> --sev high")


@app.command()
def verify(
    action: str = typer.Argument("status", help="status|kill|poc|pass"),
    slug: str = typer.Argument("", help="program slug"),
    finding_id: str = typer.Argument("", help="finding id (prefix ok)"),
    sev: str = typer.Option("", "--sev", help="severity to assign when 'pass'"),
):
    """Kill-test an engine candidate and build its PoC."""
    C = _Commands
    if action == "status":
        C.status(slug)
    elif action == "kill":
        C.kill(slug, finding_id)
    elif action == "poc":
        C.poc(slug, finding_id)
    elif action == "pass":
        C.pass_(slug, finding_id)
    else:
        typer.echo(f"cs_verify: unknown action '{action}'", err=True)
        raise typer.Exit(1)


if __name__ == "__main__":
    app()