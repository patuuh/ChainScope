#!/usr/bin/env python3
"""Watch for NEWLY-OPENED fresh-code audit competitions and notify.

This is the "out-of-the-box" companion to ``cs_scan``/``cs_target``: those hunt *existing*
Immunefi bug bounties (which are audited majors). Fresh, thin-audit code that the Keizo
method favours usually appears as *time-boxed audit competitions* (Code4rena, Sherlock,
Cantina, Immunefi audit-competitions). ``cs_watch`` polls those sources, remembers which
contests it has already reported, and notifies when a NEW one opens so you can audit it
inside its window before it is flooded with findings.

    python cs_watch.py --once                 # check now, notify on new opens, exit
    python cs_watch.py --interval 1800        # poll every 30 minutes (default 30m)
    python cs_watch.py --json                 # print the detected set as JSON

Notifications: webhook (Discord/Slack/Telegram) or SMTP email via ``core/notify``; if
neither is configured it appends to ~/.chainscope/notifications.log and prints.

State is persisted in ~/.chainscope/watch_state.json so a new contest is only reported once.
"""
from __future__ import annotations

import sys
from pathlib import Path

_PARENT = str(Path(__file__).resolve().parent.parent)
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)


import contextlib
import datetime
import html
import json
import os
import pathlib
import re
import socket
import sys
import time
import typing
import urllib.error
import urllib.request

import typer

from core import notify

app = typer.Typer()

# statuses we treat as "accepting audits right now" (per-source normalised)
_OPEN = ("live", "active", "open", "in progress", "in_progress", "registration", "register")

_STATE_FILE = str(pathlib.Path.home() / ".chainscope" / "watch_state.json")

# "catalog" sources list many ongoing programs at once (bounties, not time-boxed contests);
# baseline them silently on first sight so only programs appearing afterwards are surfaced.
_CATALOG_SOURCES = ("hackenproof", "immunefi-bounty", "sherlock-bounty")
_CATALOG_BASELINE = "__catalog_baseline__"


def _get(url: str, timeout: int = 30) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8", "ignore")


def _is_open(status: str) -> bool:
    return any(k in status.lower() for k in _OPEN)


def _doh_resolve(host: str) -> list[str]:
    """Resolve `host` to IPv4 addresses via Cloudflare DoH, bypassing a local resolver that
    may sinkhole/block it (some networks return a documentation address for such hosts)."""
    try:
        req = urllib.request.Request(
            f"https://1.1.1.1/dns-query?name={host}&type=A",
            headers={"accept": "application/dns-json", "User-Agent": "Mozilla/5.0"},
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8", "ignore"))
        return [a["data"] for a in data.get("Answer", []) if a.get("type") == 1]
    except Exception:  # noqa: BLE001
        return []


@contextlib.contextmanager
def _pin_host(host: str, ip: str):
    """Temporarily resolve `host` to `ip` at the socket layer (TLS SNI / Host header stay the
    real hostname, so the connection is valid; only the resolved address is overridden)."""
    original = socket.getaddrinfo

    def patched(h, *args, **kwargs):
        return original(ip if h == host else h, *args, **kwargs)

    socket.getaddrinfo = patched  # type: ignore[assignment]
    try:
        yield
    finally:
        socket.getaddrinfo = original  # type: ignore[assignment]


def _get_hackenproof_api(url: str, host: str, timeout: int = 30) -> str:
    try:
        return _get(url, timeout)
    except Exception:
        # Local DNS likely blocks `host`; retry with a DoH-resolved, socket-pinned address.
        ips = _doh_resolve(host)
        if not ips:
            raise
        with _pin_host(host, ips[0]):
            return _get(url, timeout)


def _fetch_immunefi() -> list[dict[str, typing.Any]]:
    raw = _get("https://immunefi.com/audit-competition/")
    out: list[dict[str, typing.Any]] = []
    # Collect positions of every slug link and every "Live ... remaining" marker, then a slug is
    # Live only if a live-marker immediately follows its link (i.e. its own card is live).
    slug_pos = [(m.start(), m.group(1)) for m in re.finditer(r'audit-competition/([a-z0-9][a-z0-9\-]+)', raw)]
    live_pos = [m.start() for m in re.finditer(r'Live</span>|<span[^>]*>Live<', raw)]
    # a "Live ... remaining" marker belongs to the competition whose link immediately follows it
    live_slugs: set[str] = set()
    for lp in live_pos:
        following = [pos for pos, _ in slug_pos if lp < pos <= lp + 3000]
        if following:
            live_slugs.add(dict(slug_pos)[min(following)])
    for pos, slug in slug_pos:
        status = "Live" if slug in live_slugs else "ended"
        title = re.sub(r'[-_]', ' ', slug).strip().title()
        m = re.search(r'audit-competition/%s[^"]*"[^>]*>\s*([^<>{]{3,70})' % re.escape(slug), raw)
        if m:
            title = m.group(1).strip() or title
        out.append({"slug": slug, "name": title, "status": status, "source": "immunefi"})
    # collapse duplicate slugs
    return {c["slug"]: c for c in out}.values()


def _fetch_code4rena() -> list[dict[str, typing.Any]]:
    raw = _get("https://code4rena.com/audits")
    out: list[dict[str, typing.Any]] = []
    # The page embeds the authoritative "Active" / "Upcoming" contest arrays. Pull those as JSON
    # and use them as the source of truth (avoids false positives from unrelated page JSON).
    for key in ("Active", "Upcoming", "Report in progress", "Completed"):
        m = re.search(re.escape('"%s":[' % key), raw)
        if not m:
            continue
        start = m.end() - 1
        depth, i = 0, start
        while i < len(raw):
            c = raw[i]
            if c == "[":
                depth += 1
            elif c == "]":
                depth -= 1
                if depth == 0:
                    break
            i += 1
        arr = raw[start:i + 1]
        try:
            contests = json.loads(arr)
        except Exception:  # noqa: BLE001
            continue
        for c in contests:
            if isinstance(c, dict) and c.get("title"):
                out.append({"slug": re.sub(r'[^a-z0-9]+', '-', c["title"].lower()).strip('-'),
                            "name": c["title"], "status": key, "source": "code4rena"})
    return out


def _fetch_sherlock() -> list[dict[str, typing.Any]]:
    raw = _get("https://audits.sherlock.xyz/contests")
    out: list[dict[str, typing.Any]] = []
    for m in re.finditer(r'([A-Za-z0-9][A-Za-z0-9 .\-&;]{3,40})\s*<[^>]*>\s*(Active|Open|Live|Upcoming|Judging)', raw):
        status = m.group(2).strip()
        out.append({"slug": re.sub(r'[^a-z0-9]+', '-', m.group(1).lower()).strip('-'),
                    "name": m.group(1).strip(), "status": status, "source": "sherlock"})
    return out


def _fetch_cantina() -> list[dict[str, typing.Any]]:
    raw = _get("https://cantina.xyz/competitions")
    out: list[dict[str, typing.Any]] = []
    for m in re.finditer(r'([A-Za-z0-9][A-Za-z0-9 .\-&;]{3,40})\s*<[^>]*>\s*(Live|Open|Active|Upcoming)', raw):
        status = m.group(2).strip()
        out.append({"slug": re.sub(r'[^a-z0-9]+', '-', m.group(1).lower()).strip('-'),
                    "name": m.group(1).strip(), "status": status, "source": "cantina"})
    return out


def _fetch_hackenproof() -> list[dict[str, typing.Any]]:
    """Fetch the full HackenProof catalog via the public API (the /programs HTML only lists a
    subset and hides the DualDefense/audit programs). Only surface programs the account can
    actually submit to: Active and with min_reputation_points <= HACKENPROOF_MAX_REP (default
    80, which profile completion alone reaches)."""
    max_rep = int(os.environ.get("HACKENPROOF_MAX_REP", "80") or 80)
    try:
        raw = _get_hackenproof_api(
            "https://dashboard.hackenproof.com/api/v1/programs?per_page=200",
            "dashboard.hackenproof.com",
        )
        data = json.loads(raw)
        progs = data.get("programs", data if isinstance(data, list) else [])
    except Exception:  # noqa: BLE001
        # dashboard API unreachable (e.g. DNS-blocked on some networks); fall back to the
        # public page, which lists only the featured bounties (no rep/DualDefense metadata).
        raw = _get("https://hackenproof.com/programs")
        out = []
        for m in re.finditer(r'<a[^>]*href="/programs/([a-z0-9][a-z0-9\-]*)"[^>]*>(.*?)</a>', raw, re.S):
            slug = m.group(1)
            name = html.unescape(re.sub(r'<[^>]+>', '', m.group(2))).strip() or slug
            out.append({"slug": slug, "name": name, "status": "open", "source": "hackenproof",
                        "rep": None, "dd": False})
        return {c["slug"]: c for c in out}.values()
    out: list[dict[str, typing.Any]] = []
    for p in progs:
        slug = p.get("slug")
        if not slug:
            continue
        status = p.get("status")
        if isinstance(status, dict):
            status = status.get("name")
        if (status or "").lower() != "active":
            continue
        rep = p.get("min_reputation_points")
        rep = 0 if rep is None else rep
        if rep > max_rep:
            continue
        out.append({
            "slug": slug,
            "name": p.get("title") or slug,
            "status": "open",
            "source": "hackenproof",
            "rep": rep,
            "dd": bool(p.get("dual_defence")),
        })
    return {c["slug"]: c for c in out}.values()


def _fetch_codehawks() -> list[dict[str, typing.Any]]:
    """Cyfrin CodeHawks audit competitions (fresh, time-boxed Solidity contests). SvelteKit +
    tRPC; the competitions list comes from the public tRPC endpoint."""
    raw = _get("https://codehawks.cyfrin.io/trpc/competitions.getCompetitions?batch=1&input=%7B%7D")
    data = json.loads(raw)
    if isinstance(data, list) and data and isinstance(data[0], dict) and "result" in data[0]:
        data = data[0]["result"].get("data")
    now = datetime.datetime.now(datetime.timezone.utc)
    out: list[dict[str, typing.Any]] = []
    for c in data or []:
        slug = c.get("urlSlug") or c.get("id")
        if not slug:
            continue
        status = "open"
        try:
            end = c.get("endDate")
            start = c.get("startDate")
            e = datetime.datetime.fromisoformat(str(end).replace("Z", "+00:00")) if end else None
            s = datetime.datetime.fromisoformat(str(start).replace("Z", "+00:00")) if start else None
            if e and now > e:
                status = "ended"
            elif s and now < s:
                status = "upcoming"
        except Exception:  # noqa: BLE001
            pass
        out.append({"slug": f"codehawks-{slug}", "name": c.get("name") or slug,
                    "status": status, "source": "codehawks"})
    return out


def _fetch_immunefi_bounties() -> list[dict[str, typing.Any]]:
    """Ongoing Immunefi bug bounties (not audit competitions). Immunefi has no reputation
    gate, so a newly-listed bounty is immediately submittable. The index lists every bounty,
    so this source is baselined like the others."""
    raw = _get("https://immunefi.com/bug-bounty/")
    out: list[dict[str, typing.Any]] = []
    # The full bounty list lives in the Next.js flight payload (not just the visible anchors).
    for m in re.finditer(r'/bug-bounty/([a-z0-9][a-z0-9\-]+)/information/', raw):
        slug = m.group(1)
        out.append({"slug": f"immunefi-bounty-{slug}", "name": slug.replace("-", " ").title(),
                    "status": "live", "source": "immunefi-bounty"})
    return {c["slug"]: c for c in out}.values()


def _fetch_sherlock_bounties() -> list[dict[str, typing.Any]]:
    """Ongoing Sherlock bug bounties (not contests)."""
    raw = _get("https://audits.sherlock.xyz/bug-bounties")
    out: list[dict[str, typing.Any]] = []
    for m in re.finditer(r'/bug-bounties/(\d+)', raw):
        bid = m.group(1)
        out.append({"slug": f"sherlock-bounty-{bid}", "name": f"Sherlock Bug Bounty #{bid}",
                    "status": "live", "source": "sherlock-bounty"})
    return {c["slug"]: c for c in out}.values()


def _load_seen() -> set[str]:
    try:
        with open(_STATE_FILE) as fh:
            return set(json.load(fh).get("seen", []))
    except Exception:  # noqa: BLE001
        return set()


def _save_seen(seen: set[str]) -> None:
    p = pathlib.Path(_STATE_FILE)
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "w") as fh:
        json.dump({"seen": sorted(seen)}, fh, indent=2)


def _detect() -> list[dict[str, typing.Any]]:
    detected: list[dict[str, typing.Any]] = []
    errors: list[str] = []
    for name, fn in (("immunefi", _fetch_immunefi), ("code4rena", _fetch_code4rena),
                     ("sherlock", _fetch_sherlock), ("cantina", _fetch_cantina),
                     ("hackenproof", _fetch_hackenproof),
                     ("immunefi-bounty", _fetch_immunefi_bounties),
                     ("sherlock-bounty", _fetch_sherlock_bounties),
                     ("codehawks", _fetch_codehawks)):
        try:
            detected.extend(fn())
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{name}: {exc}")
    return detected, errors


@app.command()
def watch(
    once: bool = typer.Option(False, "--once", help="Run a single check and exit"),
    interval: int = typer.Option(1800, "--interval", help="Poll interval in seconds (default 30m)"),
    json_output: bool = typer.Option(False, "--json", help="Print the detected set as JSON"),
    state: str = typer.Option(_STATE_FILE, "--state", help="State file for seen contests"),
):
    seen = _load_seen()
    while True:
        opened, errors = _detect()
        # Baseline: the first time we observe the hackenproof source, record its whole current
        # program set silently (so existing programs don't flood the "new launch" inbox). Only
        # slugs that appear AFTER this baseline are surfaced as fresh.
        catalog_items = [c for c in opened if c.get("source") in _CATALOG_SOURCES and c.get("slug")]
        if catalog_items and _CATALOG_BASELINE not in seen:
            for c in catalog_items:
                seen.add(c["slug"])
            seen.add(_CATALOG_BASELINE)
            _save_seen(seen)
        open_contests = [c for c in opened if c.get("slug") and _is_open(c.get("status") or "")]
        fresh = [c for c in open_contests if c["slug"] not in seen]

        def _label(c: dict[str, typing.Any]) -> str:
            extra = ""
            if c.get("source") == "hackenproof":
                rep = c.get("rep")
                extra = (f" rep<={rep}" if rep is not None else "") + (" [DualDefense]" if c.get("dd") else "")
            return f"- {c['name']} [{c['source']}] ({c.get('status') or '?'}){extra}"

        names = "\n".join(_label(c) for c in fresh)
        if fresh:
            for c in fresh:
                seen.add(c["slug"])
            _save_seen(seen)
            subject = f"New audit competition open: {len(fresh)}"
            body = (
                f"New fresh-code audit competition(s) detected:\n{names}\n\n"
                "Open the source repo and run cs_fetch/cs_target immediately - these windows "
                "are short and findings flood in fast."
            )
            notify.notify(subject, body)
        elif os.environ.get("NOTIFY_HEARTBEAT", "").strip() not in ("", "0", "false"):
            open_list = ";\n".join(f"- {c['name']} [{c['source']}]" for c in opened if _is_open(c.get("status") or ""))
            notify.local(
                "cs_watch - still watching",
                f"cs_watch is alive (polling every interval).\nOpen right now: {sum(1 for c in opened if _is_open(c.get('status') or ''))}"
                + (f"\n{open_list}" if open_list else "\n(none open)"),
            )
        summary = (
            f"[cs_watch] open now: {sum(1 for c in opened if _is_open(c.get('status') or ''))}"
            f" | new since last: {len(fresh)}"
        )
        if json_output:
            print(json.dumps({"open": opened, "new": fresh, "errors": errors}, indent=2))
        else:
            print(summary)
            if fresh:
                print(names)
            if errors:
                print("  (sources skipped: " + "; ".join(errors) + ")", file=sys.stderr)
        if once:
            break
        time.sleep(interval)


if __name__ == "__main__":
    app()
