#!/usr/bin/env python3
"""Minimal Jira adapter for Shinobi findings (Phase 7).

Ships confirmed findings from the Shinobi DB into Jira so a triage board can
track them. Uses env:

    JIRA_BASE     e.g. https://your.atlassian.net
    JIRA_EMAIL    account email for Basic auth
    JIRA_TOKEN    API token
    JIRA_PROJECT  project key (default: SHIN)
    JIRA_ISSUETYPE default: Bug

CLI:
    python jira_adapter.py sync <slug>                 # confirmed findings -> Jira (idempotent by summary)
    python jira_adapter.py create <slug> <finding_id>  # single new issue

Nothing here phones home except the configured Jira instance.
"""
from __future__ import annotations

import base64
import json
import os
import sys
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from shinobi.report import render_report
from shinobi.store import Store


def _auth() -> str:
    return "Basic " + base64.b64encode(
        f"{os.environ.get('JIRA_EMAIL', '')}:{os.environ.get('JIRA_TOKEN', '')}".encode()
    ).decode()


def _base() -> str:
    return os.environ.get("JIRA_BASE", "").rstrip("/")


def _api(path: str, method: str = "GET", payload: dict | None = None) -> dict:
    if not _base():
        raise SystemExit("JIRA_BASE is not set")
    req = urllib.request.Request(
        f"{_base()}/rest/api/2{path}", method=method,
        headers={"Authorization": _auth(), "Content-Type": "application/json"})
    body = json.dumps(payload).encode() if payload is not None else None
    try:
        with urllib.request.urlopen(req, body, timeout=30) as resp:
            text = resp.read().decode()
            return json.loads(text) if text else {}
    except urllib.error.HTTPError as exc:
        detail = ""
        try:
            detail = exc.read().decode()[:500]
        except Exception:  # noqa: BLE001
            pass
        raise SystemExit(f"Jira API {exc.code}: {detail}") from None


def _upsert(summary: str, description: str, project: str) -> None:
    existing = _api(f"/search?jql=summary~\"{summary[:60]}\"&maxResults=1")
    if existing.get("total"):
        key = existing["issues"][0]["key"]
        _api(f"/issue/{key}", "PUT", {"fields": {"description": description}})
        print(f"updated {key}")
        return
    issue = _api("/issue", "POST", {
        "fields": {
            "project": {"key": project},
            "summary": summary[:250],
            "description": description[:20000],
            "issuetype": {"name": os.environ.get("JIRA_ISSUETYPE", "Bug")},
        }})
    print(f"created {issue.get('key')}")


def sync(slug: str) -> None:
    project = os.environ.get("JIRA_PROJECT", "SHIN")
    store = Store()
    rec = store.get_program(slug)
    if not rec:
        raise SystemExit(f"unknown program {slug}")
    rows = [r for r in store.list_findings(slug) if r.get("status") == "confirmed"]
    if not rows:
        print(f"no confirmed findings for {slug}")
        return
    for r in rows:
        body = render_report(rec, [r])
        _upsert(r["title"][:200], body, project)


def create(slug: str, finding_id: str) -> None:
    project = os.environ.get("JIRA_PROJECT", "SHIN")
    rec = Store().get_program(slug)
    if not rec:
        raise SystemExit(f"unknown program {slug}")
    row = next((r for r in Store().list_findings(slug)
                if r.get("id", "").startswith(finding_id)), None)
    if not row:
        raise SystemExit(f"no finding {finding_id} for {slug}")
    _upsert(row["title"][:200], render_report(rec, [row]), project)


if __name__ == "__main__":
    if len(sys.argv) < 3:
        raise SystemExit(__doc__)
    action, slug = sys.argv[1], sys.argv[2]
    if action == "sync":
        sync(slug)
    elif action == "create":
        create(slug, sys.argv[3])
    else:
        raise SystemExit(f"unknown action {action}")