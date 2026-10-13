#!/usr/bin/env python3
"""Shinobi report CLI (Phase 6).

    python cs_report.py list sandbox                       # confirmed findings
    python cs_report.py write sandbox <finding_id>        # one report (markdown)
    python cs_report.py bundle sandbox                    # bundle all confirmed
    python cs_report.py find sandbox --full               # findings table (all statuses)

Outputs go to stdout; pipe to a file to save.
"""
from __future__ import annotations

import sys
from pathlib import Path

_PARENT = str(Path(__file__).resolve().parent.parent)
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)


import pathlib

import typer

from shinobi import report as report_mod
from shinobi.store import Store

app = typer.Typer()
_db = Store()


class _Commands:
    @staticmethod
    def _program(slug: str) -> dict:
        rec = _db.get_program(slug)
        if not rec:
            typer.echo(f"cs_report: no program '{slug}'", err=True)
            raise typer.Exit(1)
        return rec

    @staticmethod
    def _confirmed(slug: str) -> list[dict]:
        return [r for r in _db.list_findings(slug) if r.get("status") == "confirmed"]

    @staticmethod
    def list(slug: str) -> None:
        rows = _Commands._confirmed(slug)
        if not rows:
            typer.echo(f"no confirmed findings for {slug} (cs_verify pass first)")
            return
        for r in rows:
            typer.echo(f"- {r['id'][:8]} [{r['severity'] or 'candidate'}] {r['title'][:70]}")

    @staticmethod
    def write(slug: str, finding_id: str) -> None:
        rec = _Commands._program(slug)
        row = next((r for r in _Commands._confirmed(slug)
                    if r["id"].startswith(finding_id)), None)
        if not row:
            typer.echo(f"cs_report: no confirmed finding '{finding_id}' for {slug}", err=True)
            raise typer.Exit(1)
        typer.echo(report_mod.render_report(rec, [row]))

    @staticmethod
    def bundle(slug: str) -> None:
        rec = _Commands._program(slug)
        rows = _Commands._confirmed(slug)
        if not rows:
            typer.echo(f"no confirmed findings for {slug} (cs_verify pass first)")
            return
        typer.echo(report_mod.bundle_summary(rec, rows))
        for row in rows:
            typer.echo("\n" + "=" * 70 + "\n")
            typer.echo(report_mod.render_report(rec, [row]))


@app.command()
def report(
    action: str = typer.Argument("list", help="list|write|bundle"),
    slug: str = typer.Argument("", help="program slug"),
    finding_id: str = typer.Argument("", help="finding id (prefix ok)"),
):
    """Render submission-ready markdown reports from confirmed findings."""
    C = _Commands
    if action == "list":
        C.list(slug)
    elif action == "write":
        C.write(slug, finding_id)
    elif action == "bundle":
        C.bundle(slug)
    else:
        typer.echo(f"cs_report: unknown action '{action}'", err=True)
        raise typer.Exit(1)


if __name__ == "__main__":
    app()