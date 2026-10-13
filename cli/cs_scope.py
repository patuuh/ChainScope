#!/usr/bin/env python3
"""Scope + guardrails for the Shinobi engine (Phase 1 of the Shinobi layer).

Records a program's scope (in-scope assets, out-of-scope rules, rewards,
eligibility) in the shinobi store and builds the guardrail set that every
dynamic request is checked against. Nothing gets touched without an
authorised scope.

    python cs_scope.py fetch leather --platform immunefi   # pull from platform
    python cs_scope.py add --name X --host host.com ...    # hand-roll a scope
    python cs_scope.py list                                # scopes on file
    python cs_scope.py show leather                        # detail + rules
    python cs_scope.py authorize https://app.leather.io --slug leather
    python cs_scope.py keygen                              # Fernet key for creds
    python cs_scope.py rm leather                          # remove a scope
"""
from __future__ import annotations

import sys
from pathlib import Path

_PARENT = str(Path(__file__).resolve().parent.parent)
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)


import json
import os
import pathlib
import typing

import typer

from shinobi import program as prog
from shinobi import scope as scope_mod
from shinobi.store import Store

app = typer.Typer()


def _key_path() -> pathlib.Path:
    return pathlib.Path(
        os.environ.get("CHAINSCOPE_DATA_DIR", "~/.chainscope")).expanduser() / "enc.key"


def _print_json(payload: typing.Any) -> None:
    typer.echo(json.dumps(payload, indent=2, default=str))


class _Commands:
    """Namespace so the single shim command can dispatch to helpers."""

    @staticmethod
    def fetch(slug: str, platform: str) -> None:
        try:
            rec = (prog.fetch_immunefi(slug) if platform == "immunefi"
                   else prog.fetch_hackenproof(slug))
        except Exception as exc:  # noqa: BLE001
            typer.echo(f"cs_scope: fetch failed: {exc}", err=True)
            raise typer.Exit(1)
        store = Store()
        pid = store.upsert_program(rec)
        sc = scope_mod.scope_from_program_record(rec)
        typer.echo(f"saved {slug} (id={pid})")
        if rec.get("max_bounty"):
            typer.echo(f"max bounty: ${rec['max_bounty']:,}")
        typer.echo(sc.describe())
        el = rec.get("eligibility", {})
        if el.get("paused"):
            typer.echo("program is PAUSED - do not run the engine against it")
        if el.get("poc_required"):
            typer.echo("rule: PoC required for all severities")

    @staticmethod
    def add(name: str, hosts: str, slug: str, prefixes: str,
            oos: str, max_bounty: int) -> None:
        store = Store()
        in_scope: list[dict] = []
        for h in [x.strip() for x in hosts.split(",") if x.strip()]:
            if not h.startswith("http"):
                h = "https://" + h
            path = h.split("://", 1)[-1].split("/", 1)[1] if "/" in h.split("://", 1)[-1] else ""
            in_scope.append({"url": h, "type": "websites_and_applications",
                             "description": "", "added": "",
                             "host": scope_mod.hostname(h),
                             "kind": "prefix" if path and path.rstrip("/") else "host"})
        for p in [x.strip() for x in prefixes.split(",") if x.strip()]:
            host, _, path = p.partition(":")
            if not host:
                continue
            in_scope.append({"url": f"https://{host}/{path.lstrip('/')}",
                             "type": "websites_and_applications", "description": "",
                             "added": "", "host": host, "kind": "prefix"})
        rec = {
            "slug": slug or name, "name": name, "platform": "manual", "url": "",
            "max_bounty": max_bounty, "rewards": [], "in_scope": in_scope,
            "oos": [{"desc": o.strip()} for o in oos.split(",") if o.strip()],
            "rules": [],
            "eligibility": {"paused": False, "poc_required": False, "kyc": False,
                            "rep_required": None, "notes": "manual"},
        }
        if in_scope:
            store.upsert_program(rec)
            typer.echo(f"saved {rec['slug']} with {len(in_scope)} asset(s)")
        else:
            typer.echo("cs_scope: no in-scope hosts given", err=True)
            raise typer.Exit(1)

    @staticmethod
    def list() -> None:
        recs = Store().list_programs()
        if not recs:
            typer.echo("no programs yet: cs_scope fetch <slug>")
            return
        for r in recs:
            n = len(r.get("in_scope") or [])
            typer.echo(f"- {r['slug']:<24} {r.get('platform',''):<11} "
                       f"${r['max_bounty'] or 0:,}  {n} assets")

    @staticmethod
    def show(slug: str) -> None:
        rec = Store().get_program(slug)
        if not rec:
            typer.echo(f"cs_scope: no program '{slug}'", err=True)
            raise typer.Exit(1)
        sc = scope_mod.scope_from_program_record(rec)
        typer.echo(sc.describe())
        if rec.get("rewards"):
            typer.echo("rewards:")
            for r in rec["rewards"]:
                typer.echo(f"  {r['severity']:<8} ${r.get('min', 0):,} - ${r.get('max', 0):,}")
        el = rec.get("eligibility") or {}
        typer.echo("eligibility: " + json.dumps(
            {k: v for k, v in el.items() if k != "notes"}, default=str))
        if rec.get("oos"):
            typer.echo("out-of-scope:")
            for o in rec["oos"][:12]:
                typer.echo(f"  - {o.get('desc', o)}")
        if rec.get("rules"):
            typer.echo("rules:")
            for r in rec["rules"][:12]:
                typer.echo(f"  - {r[:160]}")

    @staticmethod
    def authorize(url: str, slug: str) -> None:
        store = Store()
        if slug:
            rec = store.get_program(slug)
            if not rec:
                typer.echo(f"cs_scope: no program '{slug}'", err=True)
                raise typer.Exit(1)
            sc = scope_mod.scope_from_program_record(rec)
            if sc.authorized(url):
                typer.echo(f"authorised by {slug}")
            else:
                typer.echo(f"REFUSED by {slug}")
            return
        for r in store.list_programs():
            if scope_mod.scope_from_program_record(r).authorized(url):
                typer.echo(f"authorised by {r['slug']}")
                return
        typer.echo("NOT authorised by any program")

    @staticmethod
    def keygen() -> None:
        try:
            from cryptography.fernet import Fernet
        except ImportError as exc:  # noqa: BLE001
            typer.echo("cs_scope: cryptography not installed "
                       "(pip install cryptography)", err=True)
            raise typer.Exit(1)
        key = Fernet.generate_key().decode()
        kp = _key_path()
        kp.write_text(key + "\n")
        os.chmod(kp, 0o600)
        typer.echo(f"wrote key to {kp} (chmod 600). Set CHAINSCOPE_KEY to override.")

    @staticmethod
    def rm(slug: str) -> None:
        Store().delete_program(slug)
        typer.echo(f"deleted {slug}")


@app.command()
def scope(
    action: str = typer.Argument("list", help="fetch|add|list|show|authorize|keygen|rm"),
    slug: str = typer.Argument("", help="program slug (fetch/show/rm/authorize--slug)"),
    url: str = typer.Argument("", help="URL to check (authorize)"),
    platform: str = typer.Option("immunefi", "--platform", help="immunefi | hackenproof"),
    name: str = typer.Option("", "--name", help="display name (add)"),
    hosts: str = typer.Option("", "--host", help="comma-separated in-scope hosts (add)"),
    prefixes: str = typer.Option("", "--prefix", help="comma-separated host:path prefixes (add)"),
    oos: str = typer.Option("", "--oos", help="comma-separated out-of-scope prefixes (add)"),
    max_bounty: int = typer.Option(0, "--max-bounty", help="max bounty USD (add)"),
):
    """Shinobi scope + guardrail manager."""
    a = (action or "list").lower()
    C = _Commands
    if a == "fetch":
        C.fetch(slug or name, platform)
    elif a == "add":
        C.add(name, hosts, slug, prefixes, oos, max_bounty)
    elif a == "list":
        C.list()
    elif a == "show":
        C.show(slug)
    elif a == "authorize":
        C.authorize(url, slug)
    elif a == "keygen":
        C.keygen()
    elif a == "rm":
        C.rm(slug)
    else:
        typer.echo(f"cs_scope: unknown action '{a}'", err=True)
        raise typer.Exit(1)


if __name__ == "__main__":
    app()