#!/usr/bin/env python3
"""Rank Immunefi bug-bounty programs by freshness, payout, and audit load.

This is the Immunefi counterpart to `cli/cs_hacken.py`. Immunefi has no
public JSON API, so the catalog and per-program metadata are recovered from the
React Server Component payload embedded in each program page.

    python -m cli immune list --min-bounty 100000 --top 20
    python -m cli immune list --fresh-scope --json
    python -m cli immune keizo --top 15
    python -m cli immune scope aera
    python -m cli immune triage aera --max-fetch 12

Immunefi differs from HackenProof in ways that shape the filters:
  * no reputation gate and no public report count, so those filters do not
    exist here (`keizo` re-weights the available signals accordingly);
  * `primacy` is `primacy_of_rules` (unlisted assets ineligible) or
    `primacy_of_impact` (broader), which materially changes what is worth
    hunting -- both are exposed;
  * every program publishes an `audits[]` array, which is the dedup surface
    most likely to make a finding ineligible. It is surfaced per program.
"""
from __future__ import annotations

import sys
from pathlib import Path

_PARENT = str(Path(__file__).resolve().parent.parent)
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)


import html as _html
import json
import math
import re
import time
import typing
import urllib.error
import urllib.request

import typer

from core.cs_audit_baseline import baseline, corpus_for, summarise

app = typer.Typer()

_INDEX = "https://immunefi.com/bug-bounty/"
_PAGE = "https://immunefi.com/bug-bounty/{slug}/information/"
_CACHE = Path(_PARENT) / ".chainsource" / "immune_programs.json"
_CACHE_VERSION = 2  # bump when _row() gains new inputs; old caches lack _seg/_raw
_TTL = 24 * 3600

# --- submission policy ------------------------------------------------------
# Engagement rules, not facts about the world: we only submit to programs that
# charge nothing to file a report, and chase a Critical tier up to $1M.
#
# The fee rule is free on Immunefi, so it excludes nothing and costs us nothing.
# The ceiling is what was doing damage: at $100k it removed every serious Solidity
# program, and the residue was small or formally verified (Silo runs 74 Certora
# specs and ships 10 audit reports). Raised to $1M so the hunt targets match the
# reward - a Critical is the only tier worth anything anywhere in the submittable
# set, so the ceiling has to reach programs where Criticals actually live.
#
# Two programs were lost to this before it was enforced: a $250 filing fee
# (Midas/Sherlock 122) and a $250k pool (Stacks) that was Rust regardless.
SUBMISSION_FEE_MAX_USD = 0
MAX_SUBMITTABLE_BOUNTY_USD = 1_000_000.0

# Severity floor. Where a Medium pays less than this, a High or Medium is not
# worth the hunt and the target has to be a Critical - so it is recorded per
# program rather than left as tribal knowledge. A $100k pool where Critical is
# the top tier and Medium is a rounding error is a Critical-only target, and
# reading it as "a $100k opportunity" is how effort gets spent on High findings
# that pay almost nothing.
MIN_MEDIUM_PAYOUT_USD = 10_000.0
_UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36"
_RETRY = 4


def _get(url: str, timeout: int = 45) -> str:
    """GET with bounded retries.

    Immunefi serves its pages chunked and dropped the connection mid-read more
    than once while building this module, so both transport errors and
    mid-body read failures (`IncompleteRead`) are retried before giving up.
    """
    import http.client

    last: Exception | None = None
    for attempt in range(_RETRY):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": _UA, "Accept": "text/html"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.read().decode("utf-8", "ignore")
        except (
            urllib.error.URLError,
            http.client.HTTPException,
            TimeoutError,
            OSError,
        ) as exc:
            last = exc
            time.sleep(1.5 * (attempt + 1))
    raise RuntimeError(f"failed to fetch {url}: {last}")


def _unescape(raw: str) -> str:
    """Turn the RSC payload's escaped JSON back into ordinary JSON text."""
    # RSC embeds JSON as a JS string literal: \" -> ", \\ -> \", \n -> newline
    out = raw.replace('\\\\"', '"').replace('\\\\\\"', '"')
    out = out.replace('\\"', '"').replace("\\n", "\n").replace("\\t", "\t")
    out = out.replace("\\\\", "\\")
    return out


def _scalars(seg: str, key: str) -> typing.Any:
    """Pull one JSON scalar (string/number/bool/null) for `key` out of `seg`.

    Whole-blob ``json.loads`` is unreliable on RSC payloads: asset descriptions
    carry raw tabs and invalid escapes that make strict JSON fail. Every field
    we need is a simple scalar, so field extraction is both simpler and more
    robust than parsing the object.
    """
    m = re.search(r'"{key}":\s*("(?:[^"\\]|\\.)*"|-?\d+(?:\.\d+)?|true|false|null)'.format(key=re.escape(key)), seg)
    if not m:
        return None
    tok = m.group(1)
    if tok.startswith('"'):
        return tok[1:-1]
    if tok == "true":
        return True
    if tok == "false":
        return False
    if tok == "null":
        return None
    try:
        return int(tok) if re.fullmatch(r"-?\d+", tok) else float(tok)
    except ValueError:
        return None


_SCALARS = (
    "slug", "project", "maxBounty", "launchDate", "updatedDate", "kyc",
    "networkType", "proofOfConceptType", "primacy", "pausedAt", "endDate",
    "attackTimeInterval", "reductionPercentage", "kycLevel", "contentfulId",
)


def _audits(seg: str) -> list[dict[str, typing.Any]]:
    """Extract the published `audits[]` array (the dedup surface)."""
    out: list[dict[str, typing.Any]] = []
    for m in re.finditer(
        r'\{[^{}]*?"auditor":\s*("(?:[^"\\]|\\.)*"|null).*?\}', seg
    ):
        blob = m.group(0)
        out.append({
            "auditor": _scalars(blob, "auditor"),
            "date": _scalars(blob, "date"),
            "url": _scalars(blob, "url"),
        })
    return out


def _program_block(raw: str, slug: str) -> dict[str, typing.Any] | None:
    """Pull the `bounty` object out of a program page's RSC payload.

    The payload is an escaped JS string literal in which every JSON quote
    appears as `\\"`, so we unescape first, then read the scalars we need out of
    the `bounty` object. Strict ``json.loads`` on the whole object is not used:
    asset-description prose in the same object contains raw tabs and invalid
    escapes that break strict parsing while the numeric fields remain valid.
    """
    text = _unescape(raw)
    idx = text.find('"bounty":{')
    if idx < 0:
        return None
    start = text.index("{", idx)
    depth = 0
    in_str = False
    esc = False
    end = len(text)
    for i in range(start, min(start + 400_000, len(text))):
        ch = text[i]
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                end = i + 1
                break
    seg = text[start:end]
    if '"slug"' not in seg:
        return None
    obj: dict[str, typing.Any] = {k: _scalars(seg, k) for k in _SCALARS}
    obj["_seg"] = seg
    obj["_raw"] = text
    obj["audits"] = _audits(seg)
    # knownIssues is an array; count its top-level entries.
    ki = seg.find('"knownIssues":')
    obj["knownIssues"] = 0
    if ki >= 0:
        rest = seg[ki + len('"knownIssues":') :]
        if rest.lstrip().startswith("["):
            inner = rest[rest.index("[") + 1 :]
            depth = 1
            count = 0
            for ch in inner:
                if ch == "{":
                    depth += 1
                    if depth == 2:
                        count += 1
                elif ch == "}":
                    depth -= 1
                    if depth == 1:
                        break
            obj["knownIssues"] = count
    return obj


def _catalog() -> list[str]:
    raw = _get(_INDEX, timeout=60)
    # Slugs are NOT lowercase-only: `1inch-SmartContracts` is a real program slug
    # and was invisible while the class was [a-z0-9]. That silently dropped the
    # largest 1inch program ($500k) from the catalog.
    slugs = set(re.findall(r"/bug-bounty/([A-Za-z0-9][A-Za-z0-9_-]{2,60})/", raw))
    slugs -= {
        "list", "information", "scope", "resources", "submit-bug",
        "bug-bounty", "help", "learn", "sign-up", "sign-in",
    }
    return sorted(slugs)


def _program(slug: str) -> dict[str, typing.Any] | None:
    try:
        raw = _get(_PAGE.format(slug=slug))
    except RuntimeError:
        return None
    obj = _program_block(raw, slug)
    if obj is None:
        return None
    obj["_slug"] = slug
    # liveness travels with the program record so every consumer sees it, rather
    # than requiring each caller to re-fetch the page to discover a program is
    # paused - which is how paused programs kept reaching the front of triage
    obj["status"] = _program_status(raw)
    return obj


def _load(refresh: bool = False) -> list[dict[str, typing.Any]]:
    """Return cached program metadata, fetching only what is missing."""
    cached: dict[str, dict[str, typing.Any]] = {}
    fresh_enough = False
    if _CACHE.exists():
        try:
            payload = json.loads(_CACHE.read_text())
            if payload.get("version") == _CACHE_VERSION:
                cached = {p["_slug"]: p for p in payload.get("programs", []) if "_slug" in p}
            else:
                cached = {}  # stale shape: _seg/_raw absent, evidence would be wrong
            fresh_enough = (time.time() - _CACHE.stat().st_mtime) < _TTL
        except (json.JSONDecodeError, OSError):
            cached = {}
    if not refresh and fresh_enough and cached:
        return list(cached.values())

    slugs = _catalog()
    # The index page is scraped by regex and is NOT a complete listing of every
    # program (it paginates/lazy-loads), so `_catalog()` can legitimately return
    # a SUBSET on any given fetch. Treat it as additive, never authoritative:
    # union it with what we already hold, otherwise a partial fetch silently
    # deletes every other program from the cache on write-back.
    if refresh and cached:
        slugs = sorted(set(slugs) | set(cached))
    else:
        slugs = sorted(set(slugs) | set(cached))
    out: list[dict[str, typing.Any]] = []
    missing = [s for s in slugs if refresh or s not in cached]
    for slug in slugs:
        if slug in missing:
            prog = _program(slug)
            if prog:
                out.append(prog)
        else:
            out.append(cached[slug])
    _CACHE.parent.mkdir(parents=True, exist_ok=True)
    # Preserve anything previously cached that we did not re-derive this pass.
    keep = {p["_slug"]: p for p in out if isinstance(p, dict) and p.get("_slug")}
    for slug, prog in cached.items():
        keep.setdefault(slug, prog)
    _CACHE.write_text(json.dumps({"version": _CACHE_VERSION, "fetched_at": int(time.time()), "programs": list(keep.values())}))
    return list(keep.values())


def _iso_epoch(value: typing.Any) -> float:
    """Parse an ISO-8601 timestamp (Immunefi's format) into epoch seconds.

    The RSC payload carries `updatedDate`/`launchDate` as strings such as
    "2026-09-09T13:05:59.009Z", NOT epoch millis. Parsing them as a float threw
    and silently defaulted `updated` to 0, which zeroed the freshness signal for
    every program and made the whole keizo ranking meaningless. Handles both
    formats so a future payload change degrades rather than breaks.
    """
    if value is None or value == "":
        return 0.0
    if isinstance(value, (int, float)):
        v = float(value)
        return v / 1000.0 if v > 1e11 else v
    text = str(value).strip()
    try:
        return float(text) / (1000.0 if float(text) > 1e11 else 1.0)
    except (TypeError, ValueError):
        pass
    from datetime import datetime, timezone

    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00")).replace(
            tzinfo=datetime.fromisoformat(text.replace("Z", "+00:00")).tzinfo or timezone.utc
        ).timestamp()
    except (TypeError, ValueError):
        return 0.0


# Payout formats seen in the wild:
#   "Up to USD $2,000,000"        (celer)
#   "USD $50,000 - USD $250,000"   (lombard-finance, range with dash)
#   "USD $15,000 to USD $30,000"  (lombard-finance legacy list, range with "to")
#   "USD $100,000"                 (single)
# The ceiling for ranking is the UPPER bound of whichever applies.
_TIER_RE = (
    r'"level"\s*:\s*"(Critical|High|Medium|Low|Informational)"\s*,\s*"payout"\s*:\s*'
    r'"(?:Up to )?USD \$([\d,]+)(?:\s*(?:to|-)\s*(?:USD \$)?([\d,]+))?"'
)


def _tiers(seg: str) -> dict[str, dict[str, typing.Any]]:
    """Parse the per-severity reward table.

    Two bugs this fixes:
      1. `maxBounty` is not the ceiling. Celer reported 200,000 while its Critical
         tier is 2,000,000 - a 10x understatement that mis-ranked targets.
      2. Payouts may be RANGES ("USD $50,000 - USD $250,000"). The first capture
         group is the floor, so taking it as the ceiling under-reports by 5x.
    """
    found: dict[str, dict[str, typing.Any]] = {}
    for m in re.finditer(_TIER_RE, seg):
        level = m.group(1)
        lo = float(m.group(2).replace(",", ""))
        hi = float((m.group(3) or m.group(2)).replace(",", ""))
        # legacy_*_rewards is listed FIRST and is stale; the current list comes
        # later, so last-wins is correct here (inverse of the naive assumption).
        found[level] = {"floor": lo, "payout": hi, "primacy": None}
    for m in re.finditer(
        r'"primacy"\s*:\s*"(primacy_of_impact|primacy_of_rules)"\s*,\s*"severity"\s*:\s*"(Critical|High|Medium|Low)"',
        seg,
    ):
        prim, sev = m.group(1), m.group(2).title()
        if sev in found:
            found[sev]["primacy"] = prim
    return found


def _known_issues_count(value: typing.Any) -> int:
    """knownIssues arrives as an int in some payloads and a JSON array in others
    (e.g. "[]" or []). Never let a representation difference crash the ranking."""
    if value is None or value == "":
        return 0
    if isinstance(value, bool):
        return 0
    if isinstance(value, int):
        return value
    if isinstance(value, list):
        return len(value)
    if isinstance(value, str):
        text = value.strip()
        if text.isdigit():
            return int(text)
        if text.startswith("["):
            inner = text.strip("[]").strip()
            return 0 if not inner else inner.count("{")
    return 0


# Audit firms commonly cited in published reports. Presence of any of these in the
# program payload is evidence the surface has been externally reviewed, which is a
# far better dedup signal than the `audits[]` field (see _audit_evidence).
_AUDIT_FIRMS = (
    "paladin", "openzeppelin", "slowmist", "certik", "peckshield", "chainsecurity",
    "ottersec", "tontech", "certora", "cantina", "hacken", "code4rena",
    "spearbit", "sigmasecurity", "sigma prime", "sigmaprime", "zellic", "soliditylabs",
    "secure3", "sherlock", "quantstamp", "pashsig",
    "cubicfuzz", "cubic fuzz", "level5", "frankendend", "thorchain",
    "chainalysis", "nethermind", "inno/conf", "stakey", "redbull", "tether treasury",
)

# Terms that collide with product names, only counted next to audit context.
_AUDIT_CONTEXT = ("audit", "audits", "audited", "security review", "reviewed by", "report")

_AUDIT_AMBIGUOUS = ("guardian", "otter", "sablier", "tether")

_AUDIT_URL_RE = re.compile(
    r"https?://[^\s\"'<>\\]*?(?:audits?|security[-_]?(?:review|report)s?|medusa|audit[-_]reports?)[^\s\"'<>\\]*",
    re.I,
)


def _audit_evidence(seg: str, raw: str) -> dict[str, typing.Any]:
    """Independently detect evidence of external audit coverage.

    The `audits[]` field is unusable as a dedup signal: it only records whether a
    program *author chose to populate a field*, not whether it was reviewed. GMX,
    Chainlink and Arbitrum all report `audits: 0` while being among the most
    audited codebases in web3 - and that mis-signal repeatedly steered target
    selection toward mature programs during the 2026-09-28/30 sessions.

    Instead, scan the whole payload for audit-firm names and audit-report URLs.
    A program with real published reviews almost always references them somewhere
    (Origin links a `security` repo; Lombard ships reports in-repo; Celer links its
    cBridge docs). Absence of any such reference is the strongest available negative
    signal - not proof, but far better than the count field.
    """
    haystack = f"{seg}\n{raw}".lower()
    firms = {f for f in _AUDIT_FIRMS if f in haystack}
    # ambiguous names only count when audit wording is adjacent (avoids matching
    # Celer's "State Guardian Network" or a token named Tether)
    for amb in _AUDIT_AMBIGUOUS:
        if amb in haystack and any(c in haystack for c in _AUDIT_CONTEXT):
            # require the firm token in a run that also reads like a reference
            if re.search(rf"\b{re.escape(amb)}\b[^\n]{{0,60}}\b(?:audit|report|review)\b", haystack):
                firms.add(amb)
    firms = sorted(firms)
    urls = sorted({u[:120] for u in _AUDIT_URL_RE.findall(raw)})
    return {
        "audit_firms": firms,
        "audit_urls": urls[:8],
        "audit_evidence": bool(firms or urls),
    }


def _program_status(raw: str) -> dict[str, typing.Any]:
    """Report whether a program still accepts submissions.

    Scope reachability is NOT liveness. A paused program still lists repos and
    addresses and still fetches cleanly, so `scope` and `meta` both look healthy
    for a program nobody is reporting to. That is how Stakewise, Mux and Vesper
    all reached the front of a triage while being paused - two of them also had
    dormant or archived repositories, which looked like a separate signal but
    was the same one.

    Two independent signals, because either alone has a failure mode:

    - the rendered `>Paused</span>` badge. Verified as a clean discriminator over
      nine programs: present on every paused page, absent on every live one.
    - `pausedAt` in the embedded payload, which holds a timestamp when paused and
      is `null` when live. It is DOUBLE-ESCAPED in the page (`\\"pausedAt\\":null`),
      which is why a plain `"pausedAt"` search finds nothing and silently reports
      every program as live. Scanning for the bare word `paused` is worse still:
      the live AAVE page contains `"pausedAt":null` and matches it.

    A fetch failure is UNKNOWN rather than LIVE - guessing "live" on a failed
    read is how a paused program gets targeted.
    """
    if not raw:
        return {"status": "UNKNOWN", "reason": "page fetch returned nothing"}

    badge = re.search(r">\s*Paused\s*</span>", raw) is not None
    # the payload is double-escaped inside the HTML
    ts = re.search(r'\\?"pausedAt\\?"\s*:\s*\\?"([^"\\]+)\\?"', raw)
    paused_at = ts.group(1) if ts else None

    if badge or paused_at:
        return {
            "status": "PAUSED",
            "badge": badge,
            "paused_at": paused_at,
            "reason": "paused badge present" if badge else "payload carries a pausedAt timestamp",
        }
    return {
        "status": "LIVE",
        "badge": False,
        "paused_at": None,
        "reason": "no pause marker on the program page",
    }


def severity_floor(critical: float | None, medium: float | None) -> dict[str, typing.Any]:
    """What is the lowest severity worth hunting for here?

    Where a Medium pays under $10k, a High or Medium is not worth the hunt and
    the target has to be a Critical. A `$100k` pool where Critical is the top
    tier and Medium is a rounding error is a Critical-only target, and reading it
    as "a $100k opportunity" is how effort gets spent on High findings that pay
    almost nothing.

    Returns the floor plus the reasoning, and reports UNKNOWN rather than
    guessing when the tier table could not be parsed - a missing payout is not
    evidence of a small one.
    """
    if medium is None:
        return {"floor": "UNKNOWN", "reason": "no Medium tier parsed", "crit_worth_chasing": False}
    if medium < MIN_MEDIUM_PAYOUT_USD:
        return {
            "floor": "CRIT",
            "reason": f"Medium pays ${medium:,.0f} < ${MIN_MEDIUM_PAYOUT_USD:,.0f}",
            "crit_worth_chasing": bool(critical and critical >= MAX_SUBMITTABLE_BOUNTY_USD * 0.5),
        }
    return {
        "floor": "HIGH",
        "reason": f"Medium pays ${medium:,.0f}",
        "crit_worth_chasing": bool(critical and critical >= MAX_SUBMITTABLE_BOUNTY_USD * 0.5),
    }


def submit_eligibility(row: dict[str, typing.Any]) -> dict[str, typing.Any]:
    """Can we actually file at this program?

    Three independent ways a program is unusable, all of which have cost time:
      * paused - still lists scope, still fetches clean, so it looks healthy;
      * an entry fee - a $250 filing fee on Sherlock 122 made a real finding
        unsubmittable, and the fee is not visible in the scope payload;
      * a pool above our ceiling - a bigger number is not a better target if we
        are not going to chase it.

    Returned as explicit reasons rather than a bare boolean so a rejected program
    says which rule excluded it.
    """
    reasons: list[str] = []
    status = row.get("status_code") or (row.get("status") or {}).get("status", "UNKNOWN")
    if status == "PAUSED":
        reasons.append("PAUSED")
    fee = row.get("submission_fee_usd")
    if fee is not None and fee > SUBMISSION_FEE_MAX_USD:
        reasons.append(f"SUBMISSION_FEE_${fee:g}")
    bounty = row.get("max_bounty")
    # The ceiling must be compared against the TOP TIER, not maxBounty. bobanetwork
    # reports maxBounty under $100k while its Critical tier is $1,000,000, so a
    # maxBounty-based rule both waves through and blocks real programs for the
    # wrong reason. Take whichever is higher - the payout we would actually be
    # chasing.
    crit = row.get("critical_payout")
    ceiling_basis = max([v for v in (bounty, crit) if isinstance(v, (int, float))], default=None)
    if ceiling_basis is None or ceiling_basis > MAX_SUBMITTABLE_BOUNTY_USD:
        shown = f"${ceiling_basis:,.0f}" if ceiling_basis else "unknown"
        reasons.append(f"POOL_OVER_${MAX_SUBMITTABLE_BOUNTY_USD:,.0f}:{shown}")
    return {
        "submittable": not reasons,
        "reasons": reasons,
        "status": status,
        "max_bounty": bounty,
        "critical_payout": crit,
        "ceiling_basis": ceiling_basis,
        "submission_fee_usd": fee,
        "ceiling_usd": MAX_SUBMITTABLE_BOUNTY_USD,
    }


def _row(p: dict[str, typing.Any]) -> dict[str, typing.Any]:
    seg = p.get("_seg") or ""
    audits = p.get("audits") or []
    updated = _iso_epoch(p.get("updatedDate"))
    tiers = _tiers(seg) if seg else {}
    ev = _audit_evidence(seg, p.get("_raw") or "") if seg else {
        "audit_firms": [], "audit_urls": [], "audit_evidence": False}
    critical = tiers.get("Critical", {})
    high = tiers.get("High", {})
    # maxBounty is the AUTHORITATIVE ceiling. The payload also carries stale
    # `legacy` / `smartcontract_rewards` / `web_rewards` arrays whose values
    # disagree with the live program page (Celer: maxBounty=200,000 but
    # smartcontract_rewards claims 2,000,000). Prefer maxBounty; report tier
    # values as cross-checks only, never as a ceiling.
    ceiling = float(p.get("maxBounty") or 0)
    claimed = critical.get("payout")
    if claimed and claimed > ceiling * 4:
        # implausible vs the authoritative field - treat as stale, do not use
        claimed = None
    return {
        "slug": p.get("_slug") or p.get("slug"),
        "project": p.get("project"),
        "url": f"https://immunefi.com/bug-bounty/{p.get('_slug') or p.get('slug')}/information/",
        "max_bounty": ceiling,
        "tiers": tiers,
        "critical_payout": critical.get("payout"),
        "critical_payout_stale": bool(claimed is None and critical.get("payout")),
        "high_payout": high.get("payout"),
        "medium_payout": tiers.get("Medium", {}).get("payout"),
        "low_payout": tiers.get("Low", {}).get("payout"),
        "high_payout": high.get("payout"),
        "updated": updated,
        "updated_date": (p.get("updatedDate") or "")[:10],
        "launch_date": (p.get("launchDate") or "")[:10],
        "kyc": bool(p.get("kyc")),
        "poc": (p.get("proofOfConceptType") or "").lower() in ("required", "true", "yes"),
        # Immunefi supports PER-TIER primacy. The program default is `primacy`, and
        # a tier may override it. Surface both instead of collapsing to one value.
        "primacy_default": p.get("primacy"),
        "primacy_critical": critical.get("primacy") or p.get("primacy"),
        "network": p.get("networkType"),
        "audits": len(audits),
        "audit_evidence": ev["audit_evidence"],
        "audit_firms": ev["audit_firms"],
        "audit_urls": ev["audit_urls"],
        "audit_refs": [{"auditor": a.get("auditor"), "date": a.get("date"), "url": a.get("url")} for a in audits],
        "known_issues": _known_issues_count(p.get("knownIssues")),
    }


# Explorer host -> Sourcify chain spec, so deploy_source can resolve it.
_HOST_CHAINS = {
    "etherscan.io": "1",
    "basescan.org": "8453",
    "arbiscan.io": "42161",
    "optimistic.etherscan.io": "10",
    "bscscan.com": "56",
    "polygonscan.com": "137",
    "snowtrace.io": "43114",
    "ftmscan.com": "250",
    "lineascan.build": "59144",
    "scrollscan.com": "534352",
    "explorer.zkevm.cronos.org": "388",
    "zkevm.cronos.org": "388",
    "cronoscan.com": "25",
    "explorer.morphl2.io": "2818",
    "hyperevmscan.io": "999",
}

_SKIP_HOSTS = {
    "app.originprotocol.com", "lombard.finance", "immunefi.com",
    "github.com", "discord.com", "twitter.com", "x.com", "docs.immunefi.foundation",
    "immunefi.foundation", "immunefisecurity.com", "t.me", "telegram.me",
    "blog.immunefi.com", "immunefi.com/bug-bounty",
}


def _scope(slug: str, timeout: int = 45) -> dict[str, typing.Any]:
    """Scrape a program page for in-scope contract addresses and code repos.

    Returns {"addresses": [{"chain", "address", "host"}], "repos": [...]}.
    Explorer host is preserved as the Sourcify chain spec for deploy_source.
    """
    raw = _get(_PAGE.format(slug=slug), timeout=timeout)
    addresses: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for host, addr in re.findall(
        r"https?://([A-Za-z0-9.-]+)/[^\"'\s]*?(?:address|token|account)/(0x[0-9a-fA-F]{40})",
        _unescape(raw),
    ):
        host_l = host.lower()
        if host_l in _SKIP_HOSTS:
            continue
        key = (host_l, addr.lower())
        if key in seen:
            continue
        seen.add(key)
        chain = _HOST_CHAINS.get(host_l, host_l)
        addresses.append({"chain": chain, "address": addr, "host": host_l})
    # de-duplicate by address across hosts (same contract, multiple explorers)
    by_addr: dict[str, dict[str, str]] = {}
    for a in addresses:
        by_addr.setdefault(a["address"].lower(), a)
    repos = sorted(
        set(re.findall(r"https?://github\.com/[A-Za-z0-9_.\-]+/[A-Za-z0-9_.\-]+", raw))
    )
    return {"addresses": list(by_addr.values()), "repos": repos}


@app.command(name="list")
def list_programs(
    min_bounty: float = typer.Option(0, "--min-bounty", help="Min max-bounty in USD"),
    only_impact: bool = typer.Option(False, "--only-impact", help="Only programs using Primacy of Impact"),
    no_audits: bool = typer.Option(False, "--no-audits", help="Exclude programs with published audits"),
    fresh_scope: bool = typer.Option(False, "--fresh-scope", help="Only programs updated in the last N days"),
    fresh_days: int = typer.Option(30, "--fresh-days", help="Window for --fresh-scope"),
    sort: str = typer.Option("bounty", "--sort", help="Sort by: bounty|updated|audits"),
    top: int = typer.Option(20, "--top", help="How many programs to list"),
    refresh: bool = typer.Option(False, "--refresh", help="Force re-fetch (ignore 24h cache)"),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """List Immunefi programs matching the filters."""
    programs = _load(refresh)
    now = time.time()
    rows = [_row(p) for p in programs]
    rows = [r for r in rows if r["max_bounty"] >= min_bounty]
    if only_impact:
        rows = [r for r in rows if r["primacy_critical"] == "primacy_of_impact"]
    if no_audits:
        rows = [r for r in rows if not r["audits"]]
    if fresh_scope:
        cutoff = now - fresh_days * 86400
        rows = [r for r in rows if r["updated"] and r["updated"] >= cutoff]
    if not rows:
        typer.echo("No programs match the filters.", err=True)
        raise typer.Exit(1)
    keyf = {
        "bounty": lambda r: r["max_bounty"],
        "updated": lambda r: r["updated"],
        "audits": lambda r: r["audits"],
    }[sort]
    rows.sort(key=keyf, reverse=True)
    rows = rows[: int(top)]
    if not json_output:
        typer.echo(f"{len(rows)} program(s) match (max>={min_bounty:g}):")
        for r in rows:
            flags = []
            if r["primacy_critical"] == "primacy_of_impact":
                flags.append("IMPACT")
            if r["poc"]:
                flags.append("POC")
            if r["kyc"]:
                flags.append("KYC")
            tag = ("[" + ",".join(flags) + "] ") if flags else ""
            typer.echo(
                f"  ${r['max_bounty']:>10,.0f}  audits={r['audits']:<3d} upd={r['updated_date']:<10} "
                f"{tag}{r['project'] or r['slug']}  {r['url']}"
            )
    if json_output:
        typer.echo(json.dumps(rows, indent=2))



# --- local audit-corpus discovery -------------------------------------------
# Immunefi's per-program `audits[]` field is unreliable: Gearbox reports
# `audits: 0` on the page while the workspace holds 31 published report PDFs.
# Scoring `unmined` off the page field alone therefore ranks already-mined
# programs as untouched, which is the exact opposite of what triage needs.
# When a program folder exists locally, prefer what is on disk.
_LOCAL_AUDIT_DIRS = ("security/audits", "audits", "security-reports", "reports")


def find_local_audits(workspace: str, slug: str) -> tuple[int, str]:
    """Return (pdf_count, newest_audit_iso_date) for a program folder."""
    import glob as _glob
    import os as _os
    import re as _re

    root = _os.path.join(workspace, slug)
    if not _os.path.isdir(root):
        # Immunefi slugs are lower-case; the workspace folders are not
        # (GMX, Lido, Aave...). Resolve case-insensitively or the signal
        # silently reads 0 for every mixed-case folder -- which is exactly how
        # Gearbox was the only program detected.
        try:
            entries = {e.lower(): e for e in _os.listdir(workspace)}
        except OSError:
            return 0, ""
        hit = entries.get(slug.lower())
        if not hit or not _os.path.isdir(_os.path.join(workspace, hit)):
            return 0, ""
        root = _os.path.join(workspace, hit)
    pdfs: list[str] = []
    for sub in _LOCAL_AUDIT_DIRS:
        pdfs += _glob.glob(_os.path.join(root, sub, "**", "*.pdf"), recursive=True)
    if not pdfs:
        pdfs = _glob.glob(_os.path.join(root, "**", "*.pdf"), recursive=True)
    pdfs = [f for f in pdfs if "/node_modules/" not in f]
    if not pdfs:
        return 0, ""

    mon = {m: i for i, m in enumerate(
        ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"], 1)}
    best = ""
    for f in pdfs:
        b = _os.path.basename(f)
        m = _re.match(r"(\d{4})-(\d{2})(?:-|\s)", b)
        y, mo = (int(m.group(1)), int(m.group(2))) if m else (0, 0)
        if not y:
            m = _re.match(r"(\d{4})[- ]?([A-Za-z]{3})", b)
            if m:
                y, mo = int(m.group(1)), mon.get(m.group(2).lower(), 0)
            else:
                m2 = _re.search(r"(20\d{2})", b)
                y = int(m2.group(1)) if m2 else 0
        if y and (not best or (y, mo) > best):
            best = (y, mo)
    return len(pdfs), (f"{best[0]:04d}-{best[1]:02d}" if best and best[1] else (f"{best[0]:04d}" if best else ""))


def _workspace() -> str:
    """Parent of the ChainScope checkout, i.e. where the per-program folders live."""
    import os as _o
    here = _o.path.dirname(_o.path.dirname(_o.path.abspath(__file__)))
    return _o.path.abspath(_o.path.join(here, ".."))


def _keizo(p: dict[str, typing.Any], now: float) -> dict[str, typing.Any]:
    """Rank by signals Immunefi actually exposes.

    HackenProof's variant used thin_hunt (report count) and open_gate (rep
    requirement); neither exists on Immunefi, so the weight moves to signals
    that do: recency of scope change, payout, audit load (higher = more
    dedup pressure), Primacy of Impact (broader scope), and PoC friction.
    """
    row = _row(p)
    fresh = 0.0
    if row["updated"]:
        age_days = max(0.0, (now - row["updated"]) / 86400.0)
        fresh = max(0.0, 1.0 - age_days / 365.0)
    payout = min(1.0, math.log10(1.0 + row["max_bounty"]) / 6.0)
    # Dedup load. `audits` (the page field) only records whether a program chose
    # to populate a field, so prefer independent audit EVIDENCE when available.
    n_audits = row.get("audits", 0)
    has_ev = bool(row.get("audit_evidence"))
    local_n, local_newest = find_local_audits(_workspace(), str(p.get("slug") or ""))
    row["local_audits"] = local_n
    row["local_newest_audit"] = local_newest
    if local_n and not has_ev:
        # Reports on disk beat the page field. Scale so a real corpus lands in
        # the same range the page-driven heuristic would produce.
        load = min(1.0, local_n / 6.0)
    elif has_ev:
        # evidence of review: count firms/urls, default to a meaningful load even at 0
        load = max(min(1.0, len(row.get("audit_firms", [])) / 3.0),
                    0.5 if row.get("audit_urls") else 0.0)
    else:
        load = min(1.0, n_audits / 6.0)
    dedup_load = load
    impact = 1.0 if row["primacy_critical"] == "primacy_of_impact" else 0.0
    poc = 1.0 if row["poc"] else 0.0
    score = round(
        0.30 * fresh + 0.25 * payout + 0.20 * (1.0 - dedup_load) + 0.15 * impact + 0.10 * poc,
        3,
    )

    # Liveness gate. A paused program is not a target no matter how good the
    # other signals look: it still lists scope, still fetches cleanly, and still
    # pays well on paper, which is exactly why Stakewise, Mux and Vesper each
    # reached the front of a triage before being caught. Score is forced to 0
    # and the reason recorded, so a paused program can never rank on merit.
    status = (p.get("status") or {}).get("status", "UNKNOWN")
    row["status_code"] = status
    if status == "PAUSED":
        score = 0.0
    elif status == "UNKNOWN":
        score = min(score, 0.05)

    row["keizo"] = score
    row["signals"] = {
        "fresh": round(fresh, 3),
        "payout": round(payout, 3),
        "unmined": round(1.0 - dedup_load, 3),
        "dedup_load": round(dedup_load, 3),
        "audit_evidence": has_ev,
        "local_audits": local_n,
        "local_newest_audit": local_newest,
        "page_field_unreliable": bool(local_n > (row.get("audits") or 0)),
        "primacy_impact": impact,
        "poc_required": poc,
        "status": status,
        "live": status == "LIVE",
    }
    # Engagement rules applied last, so a program we cannot file at can never rank
    # above one we can, however good its other signals look.
    elig = submit_eligibility(row)
    row["submittable"] = elig["submittable"]
    row["submit_reasons"] = elig["reasons"]

    # Severity floor, computed once so the decision is testable without a
    # network fetch or a synthetic program page.
    floor = severity_floor(row.get("critical_payout"), row.get("medium_payout"))
    row["min_viable_severity"] = floor["floor"]
    row["severity_floor_reason"] = floor["reason"]
    row["crit_worth_chasing"] = floor["crit_worth_chasing"]

    if not elig["submittable"]:
        row["keizo"] = 0.0
    return row


@app.command(name="keizo")
def keizo_rank(
    min_bounty: float = typer.Option(0, "--min-bounty", help="Min max-bounty in USD"),
    only_impact: bool = typer.Option(False, "--only-impact", help="Only Primacy of Impact programs"),
    no_audits: bool = typer.Option(False, "--no-audits", help="Exclude programs with published audits"),
    verify_audits: bool = typer.Option(False, "--verify-audits",
        help="Use independently detected audit evidence instead of the page's audits[] field (recommended)"),
    top: int = typer.Option(15, "--top", help="How many programs to list"),
    refresh: bool = typer.Option(False, "--refresh", help="Force re-fetch (ignore 24h cache)"),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Rank Immunefi programs: fresh scope + payout + low dedup load + broad scope.

    The page's `audits[]` field is NOT reliable coverage evidence (GMX/Chainlink/Arbitrum
    all report 0). Use --verify-audits to rank on detected audit references instead."""
    programs = _load(refresh)
    now = time.time()
    rows = [_keizo(p, now) for p in programs]
    rows = [r for r in rows if r["max_bounty"] >= min_bounty]
    if only_impact:
        rows = [r for r in rows if r["primacy_critical"] == "primacy_of_impact"]
    if verify_audits:
        rows = [r for r in rows if not r.get("audit_evidence")]
    if no_audits:
        rows = [r for r in rows if not r["audits"]]
    rows.sort(key=lambda r: r["keizo"], reverse=True)
    rows = rows[: int(top)]
    if not rows:
        typer.echo("No programs match the filters.", err=True)
        raise typer.Exit(1)
    if not json_output:
            typer.echo(f"Keizo ranking (max>={min_bounty:g}):")
            for r in rows:
                s = r["signals"]
                typer.echo(
                    f"  keizo={r['keizo']:.3f}  ${r['max_bounty']:>10,.0f}  audits={r['audits']:<3d} "
                    f"upd={r['updated_date']:<10} {r['project'] or r['slug']}"
                )
                typer.echo(
                    f"      fresh={s['fresh']:.2f} payout={s['payout']:.2f} unmined={s['unmined']:.2f} "
                    f"impact={s['primacy_impact']:.0f} poc={s['poc_required']:.0f}  {r['url']}"
                )
    if json_output:
        typer.echo(json.dumps(rows, indent=2))


@app.command(name="scope")
def show_scope(
    slug: str = typer.Argument(..., help="Immunefi program slug (e.g. 'aera')"),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Show in-scope contract addresses and code repos for a program."""
    try:
        scope = _scope(slug)
    except RuntimeError as exc:
        typer.echo(f"scope fetch failed: {exc}", err=True)
        raise typer.Exit(1)
    if not json_output:
            typer.echo(f"{slug}: {len(scope['addresses'])} in-scope address(es), {len(scope['repos'])} repo(s)")
            for a in scope["addresses"]:
                typer.echo(f"  {a['chain']:>28}:{a['address']}   ({a['host']})")
            for r in scope["repos"]:
                typer.echo(f"  repo: {r}")
    if json_output:
        typer.echo(json.dumps(scope, indent=2))


@app.command(name="meta")
def show_meta(
    slug: str = typer.Argument(..., help="Immunefi program slug (e.g. 'aera')"),
):
    """Show one program's metadata, including its published audits (the dedup surface)."""
    prog = _program(slug)
    if prog is None:
        typer.echo(f"could not load program: {slug}", err=True)
        raise typer.Exit(1)
    row = _row(prog)
    typer.echo(f"{row['project'] or slug}  ({slug})")
    typer.echo(f"  max bounty    : ${row['max_bounty']:,.0f}")
    typer.echo(f"  launched      : {row['launch_date']}")
    typer.echo(f"  last updated  : {row['updated_date']}")
    typer.echo(f"  network       : {row['network']}")
    typer.echo(f"  primacy (dflt) : {row['primacy_default']}")
    typer.echo(f"  primacy (crit) : {row['primacy_critical']}")
    crit = row.get("critical_payout")
    if crit:
        typer.echo(f"  tier claim    : {crit} (cross-check only)")
    typer.echo(f"  PoC required  : {row['poc']}")
    typer.echo(f"  KYC required  : {row['kyc']}")
    typer.echo(f"  known issues  : {row['known_issues']}")
    typer.echo(f"  audits ({row['audits']}) — findings here are likely ineligible:")
    for a in row["audit_refs"]:
        typer.echo(f"    {a['auditor']}  {a['date']}  {a['url']}")

    # The bounty-page `audits[]` array under-reports badly for programs that
    # publish reports in a repo instead (Lido reports 0 while holding 164).
    # Resolve the external corpus so the dedup surface is not silently wrong.
    if corpus_for(slug):
        try:
            ext = baseline(slug, timeout=90)
        except Exception as exc:  # network/decoding must not break `meta`
            typer.echo(f"  external audits: lookup failed ({exc})")
            return
        if ext.get("ok"):
            typer.echo(
                f"  external audits: {ext['total_reports']} report(s) in "
                f"{ext['repo']} — use `immune baseline {slug} --scope ...` to filter"
            )


@app.command(name="baseline")
def show_baseline(
    slug: str = typer.Argument(..., help="Immunefi program slug (e.g. 'lido')"),
    scope: str = typer.Option("", "--scope", help="Scope filter, e.g. 'CSM v3'"),
    since: str = typer.Option("", "--since", help="Only reports dated YYYY-MM or later"),
    repo: str = typer.Option("", "--repo", help="Override the audit repository"),
    branch: str = typer.Option("main", "--branch", help="Audit repo branch"),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Resolve the external audit corpus that forms the real dedup surface.

    Immunefi's per-program `audits[]` array is not authoritative: Lido reports
    `audits (0)` while `lidofinance/audits` holds 164 reports, two of which
    cover CSM v3 and CM v2 exactly.
    """
    try:
        result = baseline(
            slug, scope_query=scope, since=since, repo=repo, branch=branch, timeout=90
        )
    except (urllib.error.URLError, RuntimeError, json.JSONDecodeError) as exc:
        typer.echo(f"audit baseline lookup failed: {exc}", err=True)
        raise typer.Exit(1)

    if json_output:
        typer.echo(json.dumps(result, indent=2))
        return
    typer.echo(summarise(result))


@app.command(name="triage")
def triage(
    slug: str = typer.Argument(..., help="Immunefi program slug (e.g. 'aera')"),
    max_fetch: int = typer.Option(12, "--max-fetch", help="Max in-scope addresses to fetch+index"),
    timeout: int = typer.Option(200, "--timeout", help="Graph build timeout seconds"),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Automated pipeline: scrape scope -> fetch sources -> build graph -> surface.

    Stops at hotspot ranking. Verdict + PoC stay manual.
    """
    from core import deploy_source

    try:
        scope = _scope(slug)
    except RuntimeError as exc:
        typer.echo(f"scope fetch failed: {exc}", err=True)
        raise typer.Exit(1)
    addrs = scope["addresses"][: int(max_fetch)]
    typer.echo(f"{slug}: {len(scope['addresses'])} in-scope address(es), {len(scope['repos'])} repo(s); fetching {len(addrs)}.")
    for r in scope["repos"][:10]:
        typer.echo(f"  repo: {r}")

    out = f".chainsource/immune-{slug}"
    specs = [f"{a['chain']}:{a['address']}" for a in addrs]
    results = deploy_source.fetch_many(specs, base_out=out) if specs else []
    ok = [r for r in results if "error" not in r]
    bad = [r for r in results if "error" in r]
    for r in ok:
        typer.echo(f"  [ok] {r['chain']}:{r['address']} files={r['files']}")
    for r in bad:
        typer.echo(f"  [err] {r.get('spec')}: {r['error']}", err=True)
    if not ok:
        typer.echo("No sources fetched; triage stops here.", err=True)
        raise typer.Exit(1)

    import mcp_server

    db = f"immune-{slug}.db"
    try:
        data = json.loads(mcp_server.cs_build(
            repo_path=out, db=db, lang="solidity",
            include_research=False, timeout_seconds=int(timeout), max_failure_examples=5,
        ))
        typer.echo(
            f"graph: {data['nodes']} nodes, {data['edges']} edges, "
            f"{data['files_indexed']}/{data['files_considered']} files"
        )
    except Exception as exc:  # noqa: BLE001
        typer.echo(f"graph build failed: {exc}", err=True)
        raise typer.Exit(1)

    import subprocess

    subprocess.run(
        [sys.executable, "-m", "cli", "surface", "surface", db, "--top", "25", "--json"],
        check=False, capture_output=True,
    )
    hotspots: list[dict[str, typing.Any]] = []
    try:
        surf = json.loads(Path(f"{Path(db).stem}_surface/hotspots.json").read_text())
        items = surf if isinstance(surf, list) else surf.get("hotspots", surf.get("items", []))
        hotspots = items[:25] if isinstance(items, list) else []
    except Exception:  # noqa: BLE001
        pass
    typer.echo(f"top hotspots ({db}):")
    for h in hotspots[:15]:
        typer.echo(
            f"  {h.get('function', '?')} {h.get('file', '?')}:{h.get('line', '?')} "
            f"score={h.get('score', '?')} [{','.join(h.get('reasons', [])[:4])}]"
        )
    typer.echo(
        "Next: read flagged functions, adjudicate vs program rules and the audit list, "
        "build fork PoC for survivors."
    )
    if json_output:
        typer.echo(json.dumps({"scope": scope, "fetched": len(ok), "errors": len(bad), "hotspots": hotspots}, indent=2))


if __name__ == "__main__":
    app()
