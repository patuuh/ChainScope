#!/usr/bin/env python3
"""Auth + MFA wizard for the Shinobi engine (Phase 2).

Stores encrypted test-account credentials per program/role and manages the
login + session lifecycle (httpx form-login first, Playwright SSO fallback).

    python cs_auth.py add-credential leather user alice@x.com 'pw!' --totp-secret JBSWY3DPEHPK3PXP
    python cs_auth.py add-credential leather admin  admin@x.com 'pw2' --imap imaps://me:pw@mail.example:993/INBOX
    python cs_auth.py list leather
    python cs_auth.py login leather user            # establish a session
    python cs_auth.py login leather admin --headed  # watch the SSO flow
    python cs_auth.py sessions leather              # active cookie jars
    python cs_auth.py logout leather user

Requires CHAINSCOPE_KEY or a key written by `cs_scope keygen`.
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

from shinobi import scope as scope_mod
from shinobi.auth import RoleAuth
from shinobi.store import Store

app = typer.Typer()


class _Commands:
    @staticmethod
    def _scope(slug: str) -> scope_mod.ProgramScope:
        rec = Store().get_program(slug)
        if not rec:
            typer.echo(f"cs_auth: no program '{slug}' (cs_scope fetch <slug> first)",
                       err=True)
            raise typer.Exit(1)
        return scope_mod.scope_from_program_record(rec)

    @staticmethod
    def add_credential(slug: str, role: str, username: str, password: str,
                       totp_secret: str, imap_url: str) -> None:
        if not username or not password:
            typer.echo("cs_auth: username and password required", err=True)
            raise typer.Exit(1)
        scope_obj = _Commands._scope(slug)
        auth = RoleAuth(Store(), scope_obj, role=role)
        extra: dict[str, str] = {}
        otp_method = None
        if totp_secret:
            otp_method = "totp"
        if imap_url:
            otp_method = "imap"
        cid = auth.add_credentials(username, password,
                                   totp_secret=totp_secret or None,
                                   extra={"imap": imap_url} if imap_url else None)
        typer.echo(f"stored {slug}/{role} ({username}) id={cid} "
                   f"otp={otp_method or 'none'}")

    @staticmethod
    def list(slug: str) -> None:
        creds = Store().list_credentials(slug)
        if not creds:
            typer.echo(f"no credentials for {slug}")
            return
        for c in creds:
            typer.echo(f"- {c['role']:<10} {c['username']:<24} "
                       f"label={c.get('label') or '-'}")

    @staticmethod
    def login(slug: str, role: str, headed: bool) -> None:
        scope_obj = _Commands._scope(slug)
        auth = RoleAuth(Store(), scope_obj, role=role)
        try:
            cookies = auth.login(headed=headed)
        except Exception as exc:  # noqa: BLE001
            typer.echo(f"cs_auth: login failed: {exc}", err=True)
            raise typer.Exit(1)
        typer.echo(f"logged in {slug}/{role}: "
                   f"{len(cookies)} cookies persisted "
                   f"({', '.join(list(cookies)[:5]) or 'none'})")

    @staticmethod
    def sessions(slug: str) -> None:
        from shinobi.store import Store as S
        store = S()
        # sessions are keyed by role; pull directly from the store session rows
        import sqlite3
        conn = sqlite3.connect(store._path)
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT role, status, created_at, last_seen_at FROM sessions"
            " WHERE program_id=? ORDER BY last_seen_at DESC", (slug,)).fetchall()
        if not rows:
            typer.echo(f"no sessions for {slug}")
            return
        for r in rows:
            typer.echo(f"- {r['role']:<10} {r['status']:<10} "
                       f"seen={r['last_seen_at']}")
        conn.close()

    @staticmethod
    def logout(slug: str, role: str) -> None:
        scope_obj = _Commands._scope(slug)
        RoleAuth(Store(), scope_obj, role=role).logout()
        typer.echo(f"logged out {slug}/{role}")


@app.command()
def auth(
    action: str = typer.Argument("list", help="add-credential|list|login|sessions|logout"),
    slug: str = typer.Argument("", help="program slug"),
    role: str = typer.Argument("", help="role: user|admin|ops|..." ),
    username: str = typer.Argument("", help="username/email of the test account"),
    password: str = typer.Argument("", help="password of the test account"),
    totp_secret: str = typer.Option("", "--totp-secret", help="base32 TOTP secret"),
    imap: str = typer.Option("", "--imap", help="imap://user:pw@host:port/folder"),
    headed: bool = typer.Option(False, "--headed", help="show the browser"),
):
    """Auth + MFA wizard: encrypted creds, TOTP/email OTP, login wizard."""
    C = _Commands
    if action == "add-credential":
        C.add_credential(slug, role, username, password, totp_secret, imap)
    elif action == "list":
        C.list(slug)
    elif action == "login":
        C.login(slug, role, headed)
    elif action == "sessions":
        C.sessions(slug)
    elif action == "logout":
        C.logout(slug, role)
    else:
        typer.echo(f"cs_auth: unknown action '{action}'", err=True)
        raise typer.Exit(1)


if __name__ == "__main__":
    app()