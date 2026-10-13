#!/usr/bin/env python3
"""Shinobi active-exploration CLI (Phase 3).

    python cs_active.py probe crawl leather --depth 2
    python cs_active.py probe crawl leather --start https://app.leather.io --headed
    python cs_active.py probe apis leather
    python cs_active.py probe surfaces leather
    python cs_active.py probe graphql leather https://api.leather.io/graphql
    python cs_active.py probe tech https://app.leather.io

Crawl results + discovered endpoints are stored as `surfaces` rows in the
Shinobi DB (used later by the testing engine).
"""
from __future__ import annotations

import sys
from pathlib import Path

_PARENT = str(Path(__file__).resolve().parent.parent)
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)


import json
import urllib.parse
import urllib.request

import typer

from shinobi import probe as probe_mod
from shinobi import scope as scope_mod
from shinobi.store import Store

app = typer.Typer()
_db = Store()


class _Commands:
    @staticmethod
    def _scope(slug: str) -> scope_mod.ProgramScope:
        rec = _db.get_program(slug)
        if not rec:
            typer.echo(f"cs_active: no program '{slug}' (cs_scope fetch <slug> first)",
                       err=True)
            raise typer.Exit(1)
        return scope_mod.scope_from_program_record(rec)

    @staticmethod
    def crawl(slug: str, start: list[str], depth: int, headed: bool,
              limit: int, deadline: int) -> None:
        scope_obj = _Commands._scope(slug)
        crawler = probe_mod.Crawler(scope_obj, _db, depth=depth,
                                    headless=not headed, max_pages=limit,
                                    deadline=deadline)
        try:
            result = crawler.run(start_urls=start or None)
        except Exception as exc:  # noqa: BLE001
            typer.echo(f"cs_active: crawl failed: {exc}", err=True)
            raise typer.Exit(1)
        api = sum(1 for s in _db.list_surfaces(slug) if s["kind"] == "api")
        web = sum(1 for s in _db.list_surfaces(slug) if s["kind"] == "web")
        net = sum(1 for s in _db.list_surfaces(slug) if s["kind"] == "network")
        typer.echo(f"crawled {len(result.pages)} pages / {len(result.bundles)} "
                   f"JS bundles / {len(result.requests)} requests")
        typer.echo(f"surfaces stored: {web} web, {api} api, {net} network")
        typer.echo("tech: " + json.dumps(result.tech, default=str)[:400])

    @staticmethod
    def apis(slug: str) -> None:
        rows = [s for s in _db.list_surfaces(slug) if s["kind"] == "api"]
        if not rows:
            typer.echo(f"no API surfaces for {slug} (run: cs_active probe crawl {slug})")
            return
        for row in rows:
            typer.echo(f"- {row['method'] or '*':<5} {row['url']}")

    @staticmethod
    def surfaces(slug: str, kind: str, limit: int) -> None:
        rows = _db.list_surfaces(slug)
        if kind:
            rows = [r for r in rows if r["kind"] == kind]
        if not rows:
            typer.echo(f"no surfaces for {slug} (kind={kind or 'all'})")
            return
        typer.echo(f"{len(rows)} surfaces (limit {limit}):")
        for row in rows[:limit]:
            typer.echo(f"- {row['kind']:<8} {row['method'] or '*':<5} {row['url']} "
                       f"auth={row['auth_required']}")

    @staticmethod
    def graphql(slug: str, url: str) -> None:
        _Commands._scope(slug)  # validate program exists
        scope_obj = _Commands._scope(slug)
        if not scope_obj.authorized(url):
            typer.echo(f"cs_active: {url} is out of scope for {slug}", err=True)
            raise typer.Exit(1)
        from shinobi.net import GuardedSession
        session = GuardedSession(scope_obj, _db)
        schema = probe_mod.graphql_introspect(
            lambda u, **kw: session.post(u, **kw), url)
        if not schema:
            typer.echo(f"no GraphQL schema at {url}")
            return
        names = [t.get("name") for t in schema["types"][:60]]
        typer.echo(json.dumps({"query": schema["query_type"],
                               "mutation": schema["mutation_type"],
                               "types": names}, indent=2))

    @staticmethod
    def prune(slug: str) -> None:
        """Drop surfaces that are obviously not real endpoints: JS template
        literals or paths that embed a foreign hostname after the program host."""
        from shinobi.probe import HOSTNAME_HEAD_RE, host_seg_looks_host
        rows = _db.list_surfaces(slug)
        bad: list[str] = []
        for r in rows:
            url = r["url"]
            host = scope_mod.hostname(url)
            path = urllib.parse.urlsplit(url).path.lstrip("/")
            first = path.split("/")[0] if path else ""
            if "${" in url or "{" in url:
                bad.append(r["id"])
            elif first and host_seg_looks_host(first):
                bad.append(r["id"])
            elif path and "." in first and first not in ("v1", "v2", "v3", "v1.0"):
                bad.append(r["id"])
        removed = _db.delete_surfaces(slug, bad)
        typer.echo(f"pruned {removed} of {len(rows)} surfaces for {slug}")

    @staticmethod
    def tech(url: str) -> None:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                html = resp.read(400000).decode("utf-8", "ignore")
                headers = {k.lower(): v for k, v in resp.headers.items()}
        except Exception as exc:  # noqa: BLE001
            typer.echo(f"cs_active: fetch failed: {exc}", err=True)
            raise typer.Exit(1)
        frameworks = [name for name, pats in probe_mod.DOM_MARKERS
                      if any(p in html for p in pats)]
        typer.echo(json.dumps({
            "server": headers.get("server"),
            "powered": headers.get("x-powered-by"),
            "generator": headers.get("x-generator"),
            "csp_prefix": (headers.get("content-security-policy") or "")[:200],
            "frameworks": frameworks,
        }, indent=2))


@app.command()
def active(
    action: str = typer.Argument("surfaces", help="crawl|apis|surfaces|graphql|tech"),
    slug: str = typer.Argument("", help="program slug (or URL for tech)"),
    url: str = typer.Argument("", help="endpoint URL (graphql/tech)"),
    start: list[str] = typer.Option([], "--start", help="starting URL (repeatable)"),
    depth: int = typer.Option(2, "--depth", help="crawl depth"),
    headed: bool = typer.Option(False, "--headed", help="show the browser"),
    kind: str = typer.Option("", "--kind", help="surface kind filter: web|api|network"),
    limit: int = typer.Option(100, "--limit", help="max surfaces printed / pages crawled"),
    deadline: int = typer.Option(150, "--deadline", help="crawl time budget (seconds)"),
):
    """Shinobi active exploration: crawl + map + fingerprint + API surface."""
    C = _Commands
    if action == "crawl":
        C.crawl(slug, start, depth, headed, limit, deadline)
    elif action == "apis":
        C.apis(slug)
    elif action == "surfaces":
        C.surfaces(slug, kind, limit)
    elif action == "graphql":
        C.graphql(slug, url)
    elif action == "prune":
        C.prune(slug)
    elif action == "tech":
        C.tech(url or slug)
    else:
        typer.echo(f"cs_active: unknown action '{action}'", err=True)
        raise typer.Exit(1)


if __name__ == "__main__":
    app()