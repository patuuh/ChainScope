#!/usr/bin/env python3
"""Pull a program's PRIOR AUDITS (the "audits already made") and grep the reports.

This closes the biggest pre-submission gap: audited/known/intended issues are ineligible, and a
prior audit report can either (a) already flag the exact finding (-> OOS as "unfixed audit issue")
or (b) document the behaviour as intended/accepted (-> "by design"). Before investing in a target
or submitting, run this to know what the auditors already looked at.

    python cs_audits.py olympus                      # list prior audits for the program
    python cs_audits.py olympus --grep setTreasuryBorrower   # grep the audit PDFs for the target fn
    python cs_audits.py termstructurelabs --grep burnToAToken

It reads the Immunefi "Previous Audits" links from the program's information page; if the page just
links an external audits page (e.g. Olympus -> docs), it follows that and parses the audit table.
Reports are downloaded once (cached) and searched with pdftotext. Requires `pdftotext`.
"""
from __future__ import annotations

import sys
from pathlib import Path

_PARENT = str(Path(__file__).resolve().parent.parent)
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)


import pathlib
import re
import shutil
import subprocess
import typing
import urllib.parse
import urllib.request

import typer

app = typer.Typer()


def _get(url: str, timeout: int = 40) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8", "ignore")


def _pdf_links(html: str) -> list[str]:
    # capture pdf links from a docs/info page (github, storage.googleapis, /assets/files, ...)
    out: list[str] = []
    for m in re.finditer(r'href="([^"]+\.pdf[^"]*)"', html):
        u = m.group(1)
        if u.startswith("/"):
            # relative to the page origin - caller passes origin
            continue
        if u not in out:
            out.append(u)
    for m in re.finditer(r"(https?://[^\s\"'<>]+\.pdf)", html):
        u = m.group(1)
        if u not in out:
            out.append(u)
    return out


def _fetch_audit_pages(slug: str) -> list[str]:
    """Return the list of pages likely to contain audit report links (info page + any audits docs page)."""
    info = _get(f"https://immunefi.com/bug-bounty/{slug}/information/")
    pages: list[str] = []
    # any href that looks like an audits docs page (markdown/security/audits, /audits, external docs)
    for m in re.finditer(r'href="([^"]*audit[^"]*)"', info, re.I):
        u = m.group(1)
        if u.startswith("/") and "bug-bounty" not in u:
            # relative to immunefi.com - skip (usually nav)
            continue
        if u not in pages and (".pdf" not in u):
            pages.append(u)
    # also capture any inline pdf links on the info page itself
    return pages


def _grep_pdf(url: str, pattern: str, cache_dir: pathlib.Path) -> list[str]:
    name = re.sub(r"[^A-Za-z0-9._-]", "_", urllib.parse.urlparse(url).path).replace("_pdf", ".pdf")
    target = cache_dir / name
    if not target.exists() or target.stat().st_size < 1000:
        with urllib.request.urlopen(url, timeout=60) as resp:
            target.write_bytes(resp.read())
    txt = cache_dir / (target.stem + ".txt")
    if not txt.exists():
        p = shutil.which("pdftotext")
        if not p:
            return ["(pdftotext not installed - install poppler-utils)"]
        subprocess.run([p, str(target), str(txt)], check=False)
    if not txt.exists():
        return []
    text = txt.read_text(errors="ignore")
    hits = []
    for m in re.finditer(pattern, text, re.I):
        line = text.count("\n", 0, m.start()) + 1
        ctx = text[max(0, m.start() - 140):m.start() + 160].replace("\n", " ")
        hits.append(f"    L{line}: ...{ctx[:240]}...")
        if len(hits) >= 6:
            break
    return hits


@app.command()
def audits(
    slug: str = typer.Argument(..., help="Immunefi program slug (e.g. olympus, termstructurelabs)"),
    grep: typing.Optional[str] = typer.Option(None, "--grep", help="regex to search the audit PDFs"),
    cache: str = typer.Option("", "--cache", help="dir to cache downloaded audit PDFs"),
):
    try:
        pages = _fetch_audit_pages(slug)
    except Exception as exc:  # noqa: BLE001
        typer.echo(f"could not fetch info page: {exc}", err=True)
        raise typer.Exit(1)
    typer.echo(f"[{slug}] candidate audit-link pages: {pages}")

    links: list[str] = []
    info = _get(f"https://immunefi.com/bug-bounty/{slug}/information/")
    links += _pdf_links(info)
    for p in pages:
        try:
            links += _pdf_links(_get(p))
        except Exception:  # noqa: BLE001
            continue
    links = sorted(set(links))
    typer.echo(f"[{slug}] audit report links found: {len(links)}")
    for l in links:
        typer.echo(f"  {l}")

    if grep:
        cache_dir = pathlib.Path(cache) if cache else pathlib.Path("/tmp") / "cs_audits" / slug
        cache_dir.mkdir(parents=True, exist_ok=True)
        print(f"\n=== grep '{grep}' across {len(links)} audit reports (cached in {cache_dir}) ===")
        for l in links:
            print(f"  -> {urllib.parse.urlparse(l).path.split('/')[-1]}")
            for hit in _grep_pdf(l, grep, cache_dir):
                print(hit)
            print()


if __name__ == "__main__":
    app()
