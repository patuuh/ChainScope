"""Fetch program scope records from bounty platforms.

Currently supported:
  * Immunefi  - /bug-bounty/<slug>/information/ (Next.js flight payload)
  * HackenProof - program page (HTML; used by cs_watch catalog, re-parsed here)

Each fetcher returns a plain dict in the shape `store.upsert_program` expects:
    slug, name, platform, url, max_bounty,
    rewards    - [{severity, min, max, note}]
    in_scope   - [{url, type, description, kind}]   (kind: host | prefix | oos)
    oos        - [{desc}]                            (off-scope descriptions)
    rules      - [str]
    eligibility- {poc_required, kyc, rep_required, paused, notes}
"""
from __future__ import annotations

import html
import re
import typing
import urllib.request

_TIMEOUT = 45

_USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
    " (KHTML, like Gecko) Chrome/131 Safari/537.36"
)


def _fetch(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
    with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
        return resp.read().decode("utf-8", "ignore")


def _flight_payload(raw: str) -> str:
    """Extract and un-escape the first Next.js flight-data payload string."""
    i0 = raw.find('self.__next_f.push([1,"')
    if i0 < 0:
        return ""
    j0 = i0 + len('self.__next_f.push([1,"')
    out: list[str] = []
    k = j0
    while k < len(raw):
        c = raw[k]
        if c == "\\":
            out.append(raw[k + 1])
            k += 2
            continue
        if c == '"':
            break
        out.append(c)
        k += 1
    return "".join(out)


def _all_flight_payloads(raw: str) -> str:
    parts: list[str] = []
    for m in re.finditer(r'self\.__next_f\.push\(\[1,"(.*?)"\]\n?\);?', raw, re.S):
        seg = m.group(1)
        out: list[str] = []
        k = 0
        while k < len(seg):
            c = seg[k]
            if c == "\\":
                out.append(seg[k + 1])
                k += 2
                continue
            out.append(c)
            k += 1
        parts.append("".join(out))
    return "\n".join(parts)


def fetch_immunefi(slug: str) -> dict:
    """Fetch a program from Immunefi and normalise it into a store record."""
    url = f"https://immunefi.com/bug-bounty/{slug}/information/"
    raw = _fetch(url)
    c = _all_flight_payloads(raw)
    txt = re.sub(r"<script.*?</script>", " ", raw, flags=re.S)
    txt = re.sub(r"<[^>]+>", " ", txt)
    txt = re.sub(r"\s+", " ", html.unescape(txt))

    def text_cast(v: str) -> typing.Any:
        if v == "true":
            return True
        if v == "false":
            return False
        if v.isdigit():
            return int(v)
        return v

    def first(pattern: str, group: int = 1, cast=text_cast) -> typing.Any:
        m = re.search(pattern, c or txt)
        return cast(m.group(group)) if m else None

    name = first(r'"projectName":"([^"]+)"') or slug
    max_bounty = first(r'"maxBounty":(\d+)', cast=int)

    assets: list[dict] = []
    for m in re.finditer(
            r'\{"id":"\d+","url":"([^"]+)","type":"([^"]+)"[^}]*?"description":"([^"]*)"'
            r'[^}]*?"addedAt":"([^"]+)"', c):
        aurl, atype, adesc, aadded = m.groups()
        host = re.sub(r"^https?://", "", aurl).split("/")[0]
        path = aurl.split("://", 1)[-1].split("/", 1)[1] if "/" in aurl.split("://", 1)[-1] else ""
        assets.append({"url": aurl, "type": atype, "description": adesc,
                       "added": aadded, "host": host,
                       "kind": "prefix" if path and path.rstrip("/") else "host"})
    if not assets:
        for m in re.finditer(r'"url":"([^"]+)","type":"([^"]+)"', c):
            aurl, atype = m.groups()
            assets.append({"url": aurl, "type": atype, "description": "",
                           "added": "", "host": re.sub(r"^https?://", "", aurl).split("/")[0],
                           "kind": "host"})

    oos_lines = [l.strip() for l in txt.split(".") if "ut of scope" in l or "not in scope" in l]
    rules = [l.strip() for l in txt.split(".") if any(k in l for k in (
        "PoC", "Proof of Concept", "Responsible Publication", "Eligibility",
        "Prohibited", "Safe Harbor", "Primacy of Impact"))][:12]

    rewards: list[dict] = []
    # rewards from visible text "Threat Level ... Critical Max: ... Min: ..."
    rblock = re.search(r"Rewards by Threat Level(.*?)(Primacy of Impact|$)",
                       txt, re.S)
    if rblock:
        for level, th_max, th_min in re.findall(
                r"(Critical|High|Medium|Low)\s+Max:\s*\$([\d,]+)\s+Min:\s*\$([\d,]+)",
                rblock.group(1)):
            rewards.append({"severity": level.lower(),
                            "max": int(th_max.replace(",", "")),
                            "min": int(th_min.replace(",", ""))})

    paused = bool(re.search(r"Paused\b", txt, re.I)) and not bool(re.search(r"Live\b", txt))
    poc_required = bool(re.search(
        r"Proof of Concept[^.]*always required|POC[^.]*required", txt, re.I))
    kyc = bool(re.search(r"KYC[^.]*required|identity verification", txt, re.I))

    return {
        "slug": slug, "name": name, "platform": "immunefi", "url": url,
        "max_bounty": max_bounty,
        "rewards": rewards,
        "in_scope": assets,
        "oos": [{"desc": o} for o in oos_lines[:10]],
        "rules": rules,
        "eligibility": {
            "paused": paused, "poc_required": poc_required, "kyc": kyc,
            "rep_required": first(r'"minimumReputationLevel":"([^"]+)"'),
            "notes": txt[:4000],
        },
    }


def fetch_hackenproof(slug: str) -> dict:
    """Fetch a program from HackenProof (public program page)."""
    url = f"https://hackenproof.com/programs/{slug}"
    raw = _fetch(url)
    txt = re.sub(r"<script.*?</script>", " ", raw, flags=re.S)
    txt = re.sub(r"<[^>]+>", " ", txt)
    txt = re.sub(r"\s+", " ", html.unescape(txt))

    assets: list[dict] = []
    for m in re.finditer(r'href="(https?://[^"]+)"', raw):
        u = html.unescape(m.group(1))
        if any(gd in u for gd in ("hackenproof.com", "hproof-static", "nuxt",
                                  "google", "apple.com", "play.google.com",
                                  "discord", "telegram", "twitter.x", "x.com")):
            continue
        host = re.sub(r"^https?://", "", u).split("/")[0]
        assets.append({"url": u, "type": "websites_and_applications",
                       "description": "", "added": "", "host": host, "kind": "host"})

    live = bool(re.search(r"Live", txt)) and not bool(re.search(r"Paused", txt, re.I))
    rewards: list[dict] = []
    for m in re.finditer(
            r"(Critical|High|Medium|Low)\s*\$([\d,]+)\s*-\s*\$([\d,]+)", txt):
        sev, lo, hi = m.groups()
        rewards.append({"severity": sev.lower(), "min": int(lo.replace(",", "")),
                        "max": int(hi.replace(",", ""))})
    rep = re.search(r"(\d+) reputation points?", txt, re.I)
    poc = bool(re.search(r"POC required|Proof of Concept required", txt, re.I))
    return {
        "slug": slug, "name": re.search(r"Company:\s*([^\n]+)", txt).group(1).strip() if re.search(r"Company:\s*([^\n]+)", txt) else slug,
        "platform": "hackenproof", "url": url,
        "max_bounty": max((r.get("max") or 0 for r in rewards), default=None),
        "rewards": rewards,
        "in_scope": assets,
        "oos": [],
        "rules": [],
        "eligibility": {"paused": not live, "poc_required": poc,
                        "kyc": False,
                        "rep_required": rep.group(1) if rep else None,
                        "notes": txt[:4000]},
    }