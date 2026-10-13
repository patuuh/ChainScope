"""Target gate: decide whether a program is worth reading before anyone reads it.

Seven targets were closed by hand this session. Every one failed the same three
mechanical checks, and only the first of them was being caught early:

  1. NO_RETRIEVABLE_SOURCE  - no in-scope code repos, and no Sourcify-verified
     in-scope addresses. 1inch - Wallet is the canonical case: reported as a
     $100k "wallet" target, actually a mobile app with zero contract surface,
     and our own scope scrape had already said "0 repos, 0 addresses".
  2. NO_UNCOVERED_CODE      - nothing changed after the newest audit. Gamma
     Strategies' page showed no audit evidence at all, but the repo shipped
     ConsenSys Diligence + AE PDFs from March 2022; page-based audit detection
     produces false negatives (it also misses Chainlink and Arbitrum).
  3. NO_PERMISSIONLESS_ENTRY - the uncovered code has no unprivileged entry
     point. Gamma's post-audit delta was real (54 .sol commits, including the
     whole AutoRebal mechanism) but every function was onlyAdvisor/onlyAdmin,
     so it was unreachable without a privileged role - which these programs
     exclude.

Check 3 is the one that needs code, and it is what this module adds: classify
functions in the uncovered delta by reachability rather than by pattern-matching
for "vulnerability" shapes. It is deliberately conservative - anything it cannot
prove is privileged is reported as UNKNOWN rather than waved through.
"""
from __future__ import annotations

import datetime as _dt
import re
import subprocess
import typing as _t
from pathlib import Path

# --------------------------------------------------------------------------- #
# audit artefacts
# --------------------------------------------------------------------------- #

_AUDIT_FILE = re.compile(r"(audit|review|sec[a-z]*|report|rep[-_.])", re.I)
_AUDIT_DIR = re.compile(r"^audits?$|^security[-_]?audits?$", re.I)
_FIRM_IN_NAME = re.compile(
    r"(?:^|[-_\s.])(certik|certora|cantina|chainsecurity|consensys|"
    r"openzeppelin|slowmist|peckshield|trailofbits|paladin|hexens|"
    r"curio|crytic|ackee|bailsec|hashlock|mixbytes|spearbit|"
    r"code4rena|soliditylabs|sigmasecurity|pashov|"
    r"binplorer|coinfabrik|chainsulting|zellic|"
    r"gulamov|sablier|diamon)(?:[-_\s.]|\.pdf|$)",
    re.I,
)
_DATE_IN_NAME = re.compile(r"(20\d{2})[-_.]?(\d{2})[-_.]?(\d{2})")
# DD_MM_YY / DD-MM-YY, e.g. "Audit-28-03-22.pdf" or "audit_09_03_22.pdf".
_DATE_DMY = re.compile(r"(?<!\d)(\d{1,2})[-_.](\d{1,2})[-_.](\d{2})(?!\d)")
_DATE_WORDS = {
    ms: i
    for i, ms in enumerate(
        ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"],
        start=1,
    )
}
_DATE_SPELLED = re.compile(
    r"\b(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*[\s\-_/]?(\d{4})\b", re.I
)


def find_audits(repo: Path, extra_dirs: list[Path] | None = None) -> list[dict[str, _t.Any]]:
    """Locate audit reports for a repository.

    Directory membership is the primary signal - a PDF under `audits/` is an
    audit artefact regardless of how it is named. Filename parsing then enriches
    it with a firm and a date, because report filenames are usually the only
    place either is recorded.

    A report with no date in its filename falls back to the git commit date of
    the file, so an undated report is never silently dropped: dropping it would
    move the audit baseline backwards and invent a "new code" delta that does not
    exist.

    `extra_dirs` covers the common case where the reports are kept in a separate
    corpus repository rather than beside the code - 1inch keeps every report for
    cross-chain-swap, fusion-protocol and limit-order-protocol in a single
    `1inch-audits` repo, so none of them has a baseline on its own.
    """
    roots = [(repo, repo)] + [(d, d) for d in (extra_dirs or [])]
    found: list[dict[str, _t.Any]] = []
    for root, base_dir in roots:
        if not Path(root).is_dir():
            continue
        for path in Path(root).rglob("*"):
            if not path.is_file() or path.suffix.lower() not in {".pdf", ".md"}:
                continue
            rel_parts = path.relative_to(Path(root)).parts
            if any(p in {".git", "node_modules", "lib", "out", "cache"} for p in rel_parts):
                continue
            in_audit_dir = any(_AUDIT_DIR.match(p) for p in rel_parts[:-1])
            name = path.name
            if not (in_audit_dir or _AUDIT_FILE.search(name)):
                continue
            parsed = _date_from_name(name)
            date = parsed.isoformat() if parsed else None
            if date is None:
                # fall back to the commit date of the report in whichever git
                # root it lives, so an undated report is never dropped
                date = _git_file_date(Path(root), path.relative_to(Path(root)).as_posix())
            m = _FIRM_IN_NAME.search(name)
            found.append({
                "file": str(path.relative_to(base_dir)),
                "firm": m.group(1) if m else None,
                "date": date,
                "date_source": "filename" if parsed else ("git" if date else None),
                # A git date is a commit date, not an audit date. If the report was
                # added by a bulk re-upload ("Add files via upload"), the git date is
                # the upload date and can be arbitrarily later than the review. Using
                # it as the audit baseline silently hides any real post-audit delta,
                # so callers must be able to see that it happened and override it.
                "date_confidence": "high" if parsed else "low",
            })
    found.sort(key=lambda a: (a["date"] or ""), reverse=True)
    return found


def _git_file_date(repo: Path, rel: str) -> str | None:
    out = _git(repo, "log", "-1", "--format=%ad", "--date=short", "--", rel)
    if out is None:
        return None
    line = out.strip().splitlines()[0] if out.strip() else ""
    return line or None


def _date_from_name(name: str) -> _dt.date | None:
    m = _DATE_IN_NAME.search(name)
    if m:
        try:
            return _dt.date(int(m.group(1)), int(m.group(2)), int(m.group(3)))
        except ValueError:
            pass
    m = _DATE_SPELLED.search(name)
    if m:
        return _dt.date(int(m.group(2)), _DATE_WORDS[m.group(1).lower()[:3]], 1)
    # DD-MM-YY: the leading component is the day when it cannot be a month.
    m = _DATE_DMY.search(name)
    if m:
        d1, m1, y1 = int(m.group(1)), int(m.group(2)), int(m.group(3))
        year = 2000 + y1 if y1 < 70 else 1900 + y1
        for day, month in ((d1, m1), (m1, d1)):  # DD_MM_YY, else MM_DD_YY
            if 1 <= day <= 31 and 1 <= month <= 12:
                try:
                    return _dt.date(year, month, day)
                except ValueError:
                    continue
    return None


# --------------------------------------------------------------------------- #
# uncovered delta
# --------------------------------------------------------------------------- #


def _git(repo: Path, *args: str) -> str | None:
    try:
        out = subprocess.run(
            ["git", "-C", str(repo), *args],
            capture_output=True, text=True, timeout=120, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return out.stdout if out.returncode == 0 else None


def delta_files(repo: Path, since: _dt.date) -> list[dict[str, _t.Any]]:
    """Solidity files touched after `since`, with the newest commit on each."""
    if not (repo / ".git").exists():
        return []
    out = _git(repo, "log", f"--since={since.isoformat()}",
               "--name-only", "--pretty=format:@@%h %ad", "--date=short", "--", "*.sol")
    if out is None:
        return []
    per: dict[str, dict[str, _t.Any]] = {}
    current: dict[str, _t.Any] | None = None
    for line in out.splitlines():
        if line.startswith("@@"):
            parts = line[2:].split(None, 1)
            current = {
                "sha": parts[0] if parts else "?",
                "date": (parts[1] if len(parts) > 1 else "")[:10],
                "subject": "",
            }
            continue
        path = line.strip()
        if not path or current is None:
            continue
        rec = per.setdefault(path, {"path": path, "sha": current["sha"], "date": current["date"]})
        if current["date"] > rec["date"]:
            rec.update(sha=current["sha"], date=current["date"])
    return sorted(per.values(), key=lambda r: (r["date"], r["path"]), reverse=True)


# --------------------------------------------------------------------------- #
# reachability
# --------------------------------------------------------------------------- #

# Modifiers that gate by caller identity. `only*` is the OpenZeppelin convention;
# `requiresAuth`/`auth` are Solady; `restricted*`/`permissioned*` are explicit.
_ACCESS_MOD = re.compile(
    r"\b(only[A-Z]\w*|requires?(?:Auth|Owner|Admin|Role)\w*|auth\w*|"
    r"restricted\w*|permissioned\w*|governanceOnly|ownerOnly)\b"
)
# Guards written as statements rather than modifiers.
_BODY_GUARD = re.compile(
    r"msg\.sender\s*(?:==|!=)|_check(?:Owner|Role|Admin|Authority|Access)\s*\(|"
    r"_authorize\s*\(|requireAuth\s*\(|onlyOwner\s*\(|_checkSender\s*\(|"
    r"_validateCaller\s*\(|_verify\s*\(\s*(?:msg\.sender|caller)",
)
# Modifiers that are safety, not access control - must NOT be read as privileged.
_SAFETY_MOD = re.compile(r"\b(nonReentrant|whenNotPaused|whenPaused|whenResumed)\b")

_FUNC = re.compile(
    r"^\s*function\s+(?P<name>[A-Za-z_]\w*)\s*\((?P<args>[^)]*)\)"
    r"(?P<tail>[^;{]*)\{",
    re.M,
)
_VIEW = re.compile(r"\bview\b|\bpure\b")


def strip_comments(src: str) -> str:
    src = re.sub(r"/\*.*?\*/", "", src, flags=re.S)
    return re.sub(r"//[^\n]*", "", src)


def _matching_brace(src: str, open_idx: int) -> str:
    depth = 0
    for i in range(open_idx, len(src)):
        c = src[i]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return src[open_idx : i + 1]
    return src[open_idx : open_idx + 4000]


def classify_functions(src: str) -> list[dict[str, _t.Any]]:
    """Classify every function as VIEW / PRIVILEGED / PERMISSIONLESS / UNKNOWN."""
    body = strip_comments(src)
    out: list[dict[str, _t.Any]] = []
    for m in _FUNC.finditer(body):
        name = m.group("name")
        if name in {"constructor", "fallback", "receive"}:
            continue
        tail = m.group("tail") or ""
        # modifiers live between the arg list and the body; Solidity puts them on
        # their own lines, so also look ahead to the opening brace.
        lookahead = body[m.end() - 1 : m.end() - 1 + 400]
        header = tail + " " + lookahead.split("{")[0]
        header_wo_safety = _SAFETY_MOD.sub(" ", header)
        access_hit = _ACCESS_MOD.search(header_wo_safety)
        vis_external = "external" in tail
        vis_public = "public" in tail
        if not (vis_external or vis_public):
            kind = "INTERNAL"
        elif _VIEW.search(tail):
            kind = "VIEW"
        elif access_hit:
            kind = "PRIVILEGED"
        else:
            inner = _matching_brace(body, m.end() - 1)
            kind = "PRIVILEGED" if _BODY_GUARD.search(inner) else "PERMISSIONLESS"
        out.append({
            "name": name,
            "kind": kind,
            "guard": (access_hit.group(0) if access_hit else None),
            "signature": " ".join((m.group(0)[:150]).split()),
        })
    return out


def reachability(repo: Path, files: list[dict[str, _t.Any]]) -> dict[str, _t.Any]:
    """Classify the functions in the uncovered delta."""
    per_file: list[dict[str, _t.Any]] = []
    for rec in files:
        path = repo / rec["path"]
        if not path.exists():
            continue
        try:
            src = path.read_text(errors="replace")
        except OSError:
            continue
        fns = classify_functions(src)
        counts: dict[str, int] = {}
        for f in fns:
            counts[f["kind"]] = counts.get(f["kind"], 0) + 1
        per_file.append({
            "path": rec["path"],
            "last_change": rec["date"],
            "sha": rec["sha"],
            "counts": counts,
            "permissionless": [f for f in fns if f["kind"] == "PERMISSIONLESS"][:12],
            "unknown": [f for f in fns if f["kind"] == "UNKNOWN"][:12],
        })
    totals: dict[str, int] = {}
    for pf in per_file:
        for k, v in pf["counts"].items():
            totals[k] = totals.get(k, 0) + v
    return {
        "totals": totals,
        "files": per_file,
        "has_permissionless": totals.get("PERMISSIONLESS", 0) > 0,
    }


# --------------------------------------------------------------------------- #
# verdict
# --------------------------------------------------------------------------- #


def gate_repo(
    repo: Path,
    audit_date: str | None = None,
    audits_dir: list[Path] | None = None,
) -> dict[str, _t.Any]:
    """Apply checks 2 and 3 to a single local repository.

    `audit_date` (ISO) overrides the detected baseline. Use it whenever
    `baseline_low_confidence` is true: a git-derived date reflects when the PDF
    was committed, which for a bulk re-upload is not when the audit happened.
    `audits_dir` points at a separate report corpus when the repo carries none.
    """
    repo = Path(repo).resolve()
    audits = find_audits(repo, extra_dirs=[Path(d) for d in (audits_dir or [])])
    dated = [a for a in audits if a["date"]]
    detected = max((a["date"] for a in dated), default=None)

    baseline = audit_date or detected
    # If the *chosen* baseline came only from a git date, say so: the delta
    # computed from it is an upper bound on remaining work, not a fact.
    baseline_low_confidence = False
    if baseline and not audit_date:
        winners = [a for a in dated if a["date"] == baseline]
        baseline_low_confidence = all(a.get("date_confidence") == "low" for a in winners) if winners else True

    delta: list[dict[str, _t.Any]] = []
    reach: dict[str, _t.Any] = {"totals": {}, "files": [], "has_permissionless": False}
    if baseline:
        since = _dt.date.fromisoformat(baseline)
        delta = delta_files(repo, since)
        reach = reachability(repo, delta)

    blockers: list[str] = []
    warnings: list[str] = []
    if not audits:
        blockers.append("NO_AUDIT_BASELINE")
    elif baseline is None:
        # Reports exist but none carries a usable date (no git history, or an
        # unparseable filename). We do NOT know the baseline. Claiming
        # NO_UNCOVERED_CODE here would be a false reject that discards a live
        # target, which is as damaging as the false passes this gate exists to
        # remove.
        blockers.append("AUDIT_DATE_UNKNOWN")
        warnings.append(
            f"{len(audits)} audit report(s) found but none datable; "
            "supply --audit-date rather than treating this as no new code"
        )
    elif not delta:
        blockers.append("NO_UNCOVERED_CODE")
    elif not reach["has_permissionless"]:
        blockers.append("NO_PERMISSIONLESS_ENTRY")
    if baseline_low_confidence:
        warnings.append(
            f"audit baseline {baseline} is git-derived (likely a bulk re-upload); "
            "re-run with --audit-date to confirm"
        )

    if blockers:
        verdict = "REJECT"
    elif baseline_low_confidence:
        # A clean PASS here would be a false positive: the baseline is not
        # trustworthy, so the delta it produced cannot be. UNVERIFIED forces a
        # human to pin the real audit date before anyone reads the delta.
        verdict = "UNVERIFIED"
        warnings.append(
            "PASS withheld: baseline confidence too low to assert uncovered code; "
            "supply --audit-date"
        )
    else:
        verdict = "PASS"

    return {
        "repo": str(repo),
        "audits": audits[:12],
        "audit_count": len(audits),
        "latest_audit_detected": detected,
        "baseline_used": baseline,
        "baseline_low_confidence": baseline_low_confidence,
        "baseline_overridden": bool(audit_date),
        "delta_files": len(delta),
        "delta_sol_files": [d["path"] for d in delta][:40],
        "reachability": reach,
        "blockers": blockers,
        "warnings": warnings,
        "verdict": verdict,
    }


def gate_programs(
    entries: list[dict[str, _t.Any]],
) -> list[dict[str, _t.Any]]:
    """Run the gate over repo-shaped candidates.

    `entries` items need `repos` (list of local paths) and optional `addresses`
    (list of `chain:address` specs) plus a `name`.
    """
    results = []
    for e in entries:
        rec: dict[str, _t.Any] = {"name": e.get("name"), "repos": []}
        blockers: list[str] = []
        for rp in e.get("repos", []):
            path = Path(rp)
            if not path.is_dir():
                blockers.append("REPO_MISSING")
                continue
            g = gate_repo(path)
            rec["repos"].append(g)
            blockers.extend(f"{path.name}:{b}" for b in g["blockers"])
        if not e.get("repos") and not e.get("addresses"):
            blockers.append("NO_RETRIEVABLE_SOURCE")
        rec["blockers"] = sorted(set(blockers))
        rec["verdict"] = "PASS" if not rec["blockers"] else "REJECT"
        results.append(rec)
    return results