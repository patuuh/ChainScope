"""External audit-corpus baseline for dedup.

The Immunefi per-program payload's ``audits[]`` array is not a usable dedup
signal. ChainScope already records this in ``cli/cs_immune.py``: Chainlink and
Arbitrum both report ``audits: 0`` while being among the most audited codebases
in web3, and that mis-signal repeatedly steered target selection.

The underlying cause is that many programs do not publish their audit reports
through the bounty page at all. They publish PDFs in a repository next to the
code. Lido is the clearest case: ``cs_immune meta lido`` reports ``audits (0)``
while ``lidofinance/audits`` contains 164 reports, including two that cover
exactly ``CSM v3 and CM v2``.

This module resolves that second location so the gate has a real dedup surface:

    python3 -m core.cs_audit_baseline lidofinance/audits --scope "CSM"

Audit-report naming is inconsistent across firms, so entries are parsed from the
filename: a known-firm prefix, an optional trailing date, and whatever remains is
treated as the audited scope. Unparseable names are still listed (as ``scope=""
``) rather than dropped, because a report whose scope cannot be read is still a
report that may make a finding ineligible.
"""

from __future__ import annotations

import argparse
import json
import re
import typing as t
import urllib.error
import urllib.request

__all__ = [
    "AuditEntry",
    "AUDIT_CORPORA",
    "baseline",
    "corpus_for",
    "fetch_entries",
    "parse_pdf_name",
    "summarise",
]

# Audit firms that publish under this program. Longest-first so that multi-word
# firms ("Composable Security", "Sigma Prime") win over their prefixes.
_AUDIT_FIRMS: tuple[str, ...] = (
    "Ackee Blockchain",
    "Composable Security",
    "Runtime Verification",
    "ChainSecurity",
    "Code4rena",
    "Consensys Diligence",
    "OpenZeppelin",
    "Pessimistic",
    "Sigma Prime",
    "BlockSec",
    "Certora",
    "Cyfrin",
    "Hexens",
    "MixBytes",
    "Oxorio",
    "Statemind",
    "Nethermind",
    "Spearbit",
    "Sherlock",
    "Veridise",
    "Cantina",
    "Zellic",
    "Fuzzland",
    "Ethereum Foundation",
    "Ack3",
)

# Trailing report date. Both four- and two-digit years occur in the wild:
#   "06-2026", "03-2026"   and   "10-24", "07-24", "12-23"
_DATE_RE = re.compile(r"(?<![\d-])(\d{2})-(\d{2,4})(?![\d-])")

# Scope descriptors that carry no dedup signal on their own.
_NOISE_RE = re.compile(
    r"\b(?:security\s+)?(?:audit|review|formal\s+verification|code\s+assessment|"
    r"security\s+assessment|consultation|draft|re-?audit|hotfix|fix)\b"
    r"[\s\-_]*report*|[\s\-_]*report|[\s\-_]*-[\s\-_]*$",
    re.IGNORECASE,
)

# Month name/number normalisation for ordering and display.
_MONTHS = {
    m: i
    for i, m in enumerate(
        "jan feb mar apr may jun jul aug sep oct nov dec".split(), start=1
    )
}

_GITHUB_API = "https://api.github.com/repos/{repo}/git/trees/{branch}?recursive=1"


class AuditEntry(t.NamedTuple):
    """One published audit report."""

    firm: str
    """Audit firm, or ``""`` when the filename does not start with a known firm."""

    scope: str
    """Audited scope, cleaned of report boilerplate. ``""`` when unreadable."""

    date: str
    """ISO date (``YYYY-MM``) when derivable, else ``""``."""

    path: str
    """Path within the audit repository."""

    url: str
    """Canonical blob URL for the PDF."""

    @property
    def sort_key(self) -> tuple[int, str, str]:
        return (self.date or "0000-00", self.firm, self.scope)


# Programs whose audit reports live in a repository rather than on the bounty
# page. Keyed by Immunefi slug, then by project name as a fallback.
AUDIT_CORPORA: dict[str, str] = {
    "lido": "lidofinance/audits",
    "mantle-lsp": "mantle-lsp/audits",
    "meth": "mantle-lsp/audits",
}


def _norm_date(raw_year: str, raw_month: str) -> str:
    year = int(raw_year)
    if year < 100:
        year += 2000
    month = int(raw_month)
    if not 1 <= month <= 12:
        return ""
    return f"{year:04d}-{month:02d}"


def parse_pdf_name(path: str, url: str = "") -> AuditEntry:
    """Parse one audit-report PDF path into a structured entry.

    Splitting a filename into firm/scope/date is inherently heuristic. The
    contract is that this function never raises and never drops a report: an
    unreadable name yields empty fields, and the caller still gets the row.
    """
    name = path.rsplit("/", 1)[-1]
    if name.lower().endswith(".pdf"):
        name = name[: -len(".pdf")]
    # Some firms underscore-delimit instead of using spaces
    # ("MixBytes_Protocol_Security_Audit_Report"). Only rewrite underscores when
    # the whole name uses that convention, otherwise version identifiers such as
    # "V7_1" or "V5_2" would be mangled into "V7 1".
    if " " not in name.strip():
        name = re.sub(r"_+", " ", name)
    stem = name.strip()

    firm = ""
    for candidate in _AUDIT_FIRMS:
        if stem.lower().startswith(candidate.lower()):
            firm = candidate
            stem = stem[len(candidate) :].strip(" -_")
            break

    date = ""
    matches = list(_DATE_RE.finditer(stem))
    if matches:
        last = matches[-1]
        resolved = _norm_date(last.group(2), last.group(1))
        if resolved:
            date = resolved
            stem = (stem[: last.start()] + " " + stem[last.end() :]).strip()

    scope = _NOISE_RE.sub(" ", stem)
    scope = re.sub(r"\s+", " ", scope).strip(" -_,.")

    return AuditEntry(firm=firm, scope=scope, date=date, path=path, url=url)


def _blob_url(repo: str, branch: str, path: str) -> str:
    return f"https://github.com/{repo}/blob/{branch}/{path}"


def fetch_entries(
    repo: str,
    branch: str = "main",
    timeout: int = 120,
    opener: t.Callable[[str, float], str] | None = None,
) -> list[AuditEntry]:
    """List every audit report in ``repo`` as parsed entries.

    ``opener`` exists so tests can supply a fixture instead of hitting GitHub;
    it takes ``(url, timeout)`` and returns the response body.
    """
    url = _GITHUB_API.format(repo=repo, branch=branch)
    if opener is None:

        def opener(u: str, to: float) -> str:  # noqa: ANN202
            req = urllib.request.Request(
                u, headers={"User-Agent": "chainscope-audit-baseline"}
            )
            return urllib.request.urlopen(req, timeout=to).read().decode("utf8")

    payload = json.loads(opener(url, float(timeout)))
    if "tree" not in payload:
        msg = payload.get("message") if isinstance(payload, dict) else payload
        raise RuntimeError(f"unexpected tree response for {repo}: {msg!r}")

    entries = [
        parse_pdf_name(
            node["path"], _blob_url(repo, branch, node["path"])
        )
        for node in payload["tree"]
        if node.get("type") == "blob" and node["path"].lower().endswith(".pdf")
    ]
    entries.sort(key=lambda e: e.sort_key, reverse=True)
    return entries


def corpus_for(slug: str) -> str | None:
    """Return the audit repository for a program slug, if one is registered."""
    if slug in AUDIT_CORPORA:
        return AUDIT_CORPORA[slug]
    lowered = slug.lower()
    for key, repo in AUDIT_CORPORA.items():
        if key in lowered or lowered in key:
            return repo
    return None


def _terms(scope_query: str) -> list[str]:
    """Split a scope query into comparable lowercase terms.

    ``"CSM v3"`` -> ``["csm", "v3"]``; a bare token is matched on word
    boundaries so ``csm`` does not match ``csmv2``'s sibling ``v2`` entries by
    accident.
    """
    return [t for t in re.split(r"[^a-z0-9]+", scope_query.lower()) if t]


def matches_scope(entry: AuditEntry, scope_query: str) -> bool:
    """True when any query term appears in the entry's scope text."""
    if not scope_query:
        return True
    haystack = f"{entry.scope} {entry.firm}".lower()
    return any(term in haystack for term in _terms(scope_query))


def baseline(
    slug: str,
    scope_query: str = "",
    since: str = "",
    repo: str = "",
    branch: str = "main",
    timeout: int = 120,
    opener: t.Callable[[str, float], str] | None = None,
) -> dict[str, t.Any]:
    """Resolve the external audit baseline for a program.

    Returns a dict with the source repository, the reports matching the scope
    query, and a ``verdict`` stating how much of the audited surface overlaps.
    ``verdict`` is deliberately coarse: it flags overlap for a human to confirm
    against the report PDFs, and never claims a finding is ineligible on its own.
    """
    target_repo = repo or corpus_for(slug)
    if not target_repo:
        return {
            "program": slug,
            "repo": "",
            "scope_query": scope_query,
            "total_reports": 0,
            "matching": [],
            "verdict": "no audit corpus registered for this program",
            "ok": False,
        }

    entries = fetch_entries(target_repo, branch=branch, timeout=timeout, opener=opener)
    selected = [e for e in entries if matches_scope(e, scope_query)]
    if since:
        selected = [e for e in selected if e.date >= since]

    firms = sorted({e.firm for e in selected if e.firm})
    if not selected:
        verdict = f"no report in {target_repo} matches scope {scope_query!r}"
    elif len(firms) >= 2:
        verdict = (
            f"scope {scope_query!r} is covered by {len(selected)} report(s) from "
            f"{len(firms)} firms ({', '.join(firms)}) - treat overlapping findings "
            "as likely ineligible"
        )
    else:
        verdict = (
            f"scope {scope_query!r} matched {len(selected)} report(s) from "
            f"{len(firms) or 'an unparsed'} firm - confirm coverage before claiming novelty"
        )

    return {
        "program": slug,
        "repo": target_repo,
        "scope_query": scope_query,
        "since": since,
        "total_reports": len(entries),
        "matching": [
            {
                "firm": e.firm,
                "scope": e.scope,
                "date": e.date,
                "url": e.url,
                "path": e.path,
            }
            for e in selected
        ],
        "firms": firms,
        "verdict": verdict,
        "ok": True,
    }


def summarise(result: dict[str, t.Any], limit: int = 25) -> str:
    """Render a baseline result as plain text for the CLI."""
    lines: list[str] = []
    if not result.get("ok"):
        return f"audit baseline unavailable: {result.get('verdict', 'unknown')}"

    lines.append(f"audit corpus : {result['repo']} ({result['total_reports']} reports)")
    if result.get("scope_query"):
        lines.append(f"scope query  : {result['scope_query']!r}")
    if result.get("since"):
        lines.append(f"since        : {result['since']}")
    lines.append(f"matching     : {len(result['matching'])}")
    for row in result["matching"][:limit]:
        firm = row["firm"] or "(firm unread)"
        lines.append(f"    {firm}  {row['date'] or '??-??'}  {row['scope']}")
        if row["url"]:
            lines.append(f"        {row['url']}")
    extra = len(result["matching"]) - limit
    if extra > 0:
        lines.append(f"    ... and {extra} more")
    lines.append("")
    lines.append(f"verdict      : {result['verdict']}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("slug", help="Immunefi slug or 'org/repo' audit corpus")
    parser.add_argument("--scope", default="", help="scope filter, e.g. 'CSM v3'")
    parser.add_argument("--since", default="", help="only reports dated YYYY-MM or later")
    parser.add_argument("--repo", default="", help="override the audit repository")
    parser.add_argument("--branch", default="main", help="audit repo branch")
    parser.add_argument("--timeout", type=int, default=120)
    parser.add_argument("--json", action="store_true", help="emit JSON")
    args = parser.parse_args(argv)

    repo = args.repo or (args.slug if "/" in args.slug else "")
    try:
        result = baseline(
            args.slug,
            scope_query=args.scope,
            since=args.since,
            repo=repo,
            branch=args.branch,
            timeout=args.timeout,
        )
    except (urllib.error.URLError, RuntimeError, json.JSONDecodeError) as exc:
        print(f"audit baseline lookup failed: {exc}")
        return 1

    print(json.dumps(result, indent=2) if args.json else summarise(result))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())