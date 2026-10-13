#!/usr/bin/env python3
"""Shinobi testing-engine CLI (Phase 4).

    python cs_prowl.py run leather --role anonymous --role user      # triage run
    python cs_prowl.py run sandbox                                   # quick anonymous
    python cs_prowl.py findings sandbox                              # stored candidates
    python cs_prowl.py chains sandbox                                # chain plans
    python cs_prowl.py rolldiff sandbox --role user --role admin     # IDOR seed
    python cs_prowl.py status sandbox                                # recent engine activity

The engine only touches in-scope surfaces; every request is guarded.
"""
from __future__ import annotations

import sys
from pathlib import Path

_PARENT = str(Path(__file__).resolve().parent.parent)
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)


import json

import typer

from shinobi import engine as eng
from shinobi import scope as scope_mod
from shinobi.store import Store

app = typer.Typer()
_db = Store()


class _Commands:
    @staticmethod
    def _scope(slug: str) -> scope_mod.ProgramScope:
        rec = _db.get_program(slug)
        if not rec:
            typer.echo(f"cs_prowl: no program '{slug}'", err=True)
            raise typer.Exit(1)
        return scope_mod.scope_from_program_record(rec)

    @staticmethod
    def run(slug: str, roles: list[str], limit: int, max_tests: int,
            transport: str) -> None:
        roles = list(dict.fromkeys(roles)) or ["anonymous"]
        scope_obj = _Commands._scope(slug)
        factory = None
        if transport == "browser":
            from shinobi.browser import BrowserSession
            def factory(role: str) -> BrowserSession:  # noqa: E306
                return BrowserSession(scope_obj, _db, role=role)
        elif transport != "httpx":
            typer.echo(f"cs_prowl: unknown transport '{transport}'", err=True)
            raise typer.Exit(1)
        engine = eng.Engine(scope_obj, _db, roles=roles,
                            session_factory=factory)
        try:
            outcomes = engine.run(max_tests=max_tests)
        except Exception as exc:  # noqa: BLE001
            typer.echo(f"cs_prowl: engine failed: {exc}", err=True)
            raise typer.Exit(1)
        signal = [o for o in outcomes if o.verdict.label != "benign"]
        typer.echo(f"tested {len(outcomes)} (roles={roles}); "
                   f"{len(signal)} signalling")
        for o in signal[:limit]:
            typer.echo(f"- [{o.payload_class}] {o.verdict.label} {o.method} "
                       f"{o.endpoint}?{o.param} ({o.role}): {o.verdict.reason}")

    @staticmethod
    def findings(slug: str, limit: int) -> None:
        rows = [r for r in _db.list_findings(slug) if r.get("status") == "triage"]
        if not rows:
            typer.echo(f"no engine candidates for {slug}")
            return
        typer.echo(f"{len(rows)} engine candidates:")
        for r in rows[:limit]:
            typer.echo(f"- [{r['vuln_class']}] {r['title']}")

    @staticmethod
    def chains(slug: str) -> None:
        _Commands._scope(slug)
        rows = [r for r in _db.list_findings(slug) if r.get("status") == "triage"]
        candidates: list[eng.TestOutcome] = []
        for r in rows:
            ev = r.get("evidence") or {}
            if isinstance(ev, str):
                try:
                    ev = json.loads(ev)
                except ValueError:
                    ev = {}
            candidates.append(eng.TestOutcome(
                endpoint=ev.get("endpoint") or r.get("title", ""),
                method=ev.get("method", "GET"), param=ev.get("param", ""),
                payload_class=ev.get("class") or r.get("vuln_class", ""),
                payload=ev.get("payload", ""), role=ev.get("role", "anonymous"),
                profile=None, verdict=eng.Verdict("interesting", "", [])))
        plans = eng.plan_chains(candidates)
        if not plans:
            typer.echo(f"no chain plans for {slug}")
            return
        for p in plans:
            typer.echo(f"## {p['seed']}")
            for step in p["steps"]:
                typer.echo(f"  - {step}")
            typer.echo(f"  impact: {p['impact']}")

    @staticmethod
    def rolldiff(slug: str, roles: list[str]) -> None:
        scope_obj = _Commands._scope(slug)
        try:
            results = eng.role_diff(scope_obj, _db, roles=roles)
        except Exception as exc:  # noqa: BLE001
            typer.echo(f"cs_prowl: role-diff failed: {exc}", err=True)
            raise typer.Exit(1)
        if not results:
            typer.echo("no broken-object-access seeds")
            return
        for r in results:
            typer.echo(f"- {r['method']} {r['url']}?{r['param']}")
            typer.echo(f"    footprints: {json.dumps(r['footprints'])}")
            typer.echo(f"    -> {r['note']}")

    @staticmethod
    def status(slug: str) -> None:
        acts = _db.list_activities(slug, limit=25)
        if not acts:
            typer.echo(f"no engine activity for {slug}")
            return
        for a in acts[:25]:
            typer.echo(f"- {a['ts']} {a['actor']} {a['verb']} {a['target']}")


@app.command()
def prowl(
    action: str = typer.Argument("run", help="run|findings|chains|rolldiff|status"),
    slug: str = typer.Argument("", help="program slug"),
    roles: list[str] = typer.Option(["anonymous"], "--role", help="role(s) to test with"),
    limit: int = typer.Option(30, "--limit", help="max rows/outcomes printed"),
    max_tests: int = typer.Option(800, "--max-tests", help="engine request budget"),
    transport: str = typer.Option("httpx", "--transport", help="httpx|browser session transport"),
):
    """Shinobi testing engine: triage payloads, role-diff, chain plans."""
    C = _Commands
    if action == "run":
        C.run(slug, roles, limit, max_tests, transport)
    elif action == "findings":
        C.findings(slug, limit)
    elif action == "chains":
        C.chains(slug)
    elif action == "rolldiff":
        C.rolldiff(slug, roles)
    elif action == "status":
        C.status(slug)
    else:
        typer.echo(f"cs_prowl: unknown action '{action}'", err=True)
        raise typer.Exit(1)


if __name__ == "__main__":
    app()