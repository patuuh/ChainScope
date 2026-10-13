"""Permissionless value-moving surface estimator.

Why this exists
---------------
Four programs produced the same pattern: real design weaknesses, all killed by one of
three filters -- role-gated (excluded by the program), published (deduped), or measured
empty (no impact). Two of those are checkable BEFORE spending a deep-dive, and one
was not being checked at all.

`cs_immune keizo` originally ranked targets on Immunefi's `audits[]` field, which
measures whether a program chose to populate a field, not whether code is reachable.
That sent a deep-dive to GMX's `FeeDistributor.sol` -- 781 lines, 2 audit mentions,
and **zero** permissionless attack surface, because every state-moving function is
keeper- or timelock-gated. The scan came back empty and the effort was wasted.

The signal that actually predicted both genuine findings was: **permissionless
value-moving surface combined with code changed since the last audit**. This module
computes the first half. It is a heuristic over source text, not a proof of
exploitability, and it is deliberately biased toward *recall* -- it counts candidates
for a human or agent to triage, not confirmed bugs.

Validation ground truth is in `tests/test_surface.py`: `ExchangeRouter.sol` must score
high and `FeeDistributor.sol` must score zero.
"""

from __future__ import annotations

import os
import re
import typing as t

__all__ = [
    "RoleGuardHit",
    "SurfaceHit",
    "analyze_file",
    "analyze_tree",
    "scan_repo",
]

# --- function extraction -------------------------------------------------
# Captures `function name(...) <modifiers> {` allowing the modifier run to wrap
# onto following lines.
_FUNC_START = re.compile(r"^\s*function\s+(\w+)\s*\(", re.M)
_FUNC_BODY = re.compile(
    r"^\s*function\s+(\w+)\s*\((?:[^()]|\([^()]*\))*\)\s*([^;{]*)\{", re.M | re.S
)

# --- role guards ---------------------------------------------------------
# A function carrying ANY of these is not permissionless for our purposes.
# Catch the whole family rather than an enumerated list: the first run of this
# check reported GMX's `depositReferralRewards` as permissionless because
# `onlyFeeDistributionKeeper` is not in any hand-written list.
_ROLE_GUARD_RE = re.compile(
    r"\bonly[A-Z]\w*\b"          # onlyOwner, onlyRole, onlyFeeDistributionKeeper, ...
    r"|\bhasRole\b|\b_checkRole\b|\bcheckRole\b|\b_checkAccessRole\b"
    r"|\bonlyCalls\b|\bmsg\.sender\s*==|\bmsg\.sender\s*!=",
    re.I,
)

_ROLE_GUARDS = (
    "onlyowner", "onlyrole", "onlyadmin", "onlygovernance", "onlyself", "onlycontroller",
    "onlykeeper", "onlytimelock", "onlyconfig", "onlyacl", "onlymodule", "onlyhandler",
    "onlyselforcontroller", "onlytoken", "onlyregistry", "onlymanager", "onlyoperator",
    "hasrole", "_checkrole", "checkrole", "onlystrategist", "onlyliquidationkeeper",
    "onlyadlkeeper", "onlyorderkeeper", "onlyclaimadmin", "onlypricedistributor",
    "onlymultichainreader", "onlyclaimedistributionkeeper", "onlyvotedelegator",
)
# `require(msg.sender == x)` / `_onlyX()` style guards are matched separately
_SENDER_GUARD = re.compile(
    r"require\s*\(\s*msg\.sender\s*==|if\s*\(\s*msg\.sender\s*!=|onlycalls|"
    r"_msgSender\(\)\s*==|sender\s*!=\s*address\(0\)",
    re.I,
)

# --- value movement ------------------------------------------------------
# Calls that move tokens or mutate a balance. Deliberately broad.
_VALUE_MOVING = re.compile(
    r"\.safeTransfer\s*\(|\.safeTransferFrom\s*\(|\.transfer\s*\(|\.transferFrom\s*\(|"
    r"\.approve\s*\(|\.mint\s*\(|\.burn\s*\(|\.burnFrom\s*\(|\.transferOwnership\s*\(|"
    r"\.forceTransfer\s*\(|\.call\{value|\.delegatecall\s*\(|sendValue|withdraw\s*\(",
    re.I,
)
# A call on a contract-like receiver, e.g. `depositHandler.createDeposit(...)`.
# Needed because most value movement is INDIRECT: GMX's routers do not move tokens
# themselves, they call the handler that does. Requiring a literal token op in the
# same body classified every genuinely permissionless router entry point as
# non-value-moving.
_EXTERNAL_CALL = re.compile(
    r"(?<![\w.])(?!require|if|for|while|return|emit|revert|assert|abi|memory|storage|calldata|payable|new)\b"
    r"[a-z]\w*\s*\.\s*\w+\s*\(",
    re.I,
)
# Direct balance writes, e.g. `tokenBalances[x] = y;`
_STATE_WRITE = re.compile(
    r"\b[\w\.\[\]]+\s*(?:=|\+=|-=)\s*[^=]", re.I
)

_SKIP_DIRS = ("/test/", "/tests/", "/node_modules/", "/script/", "/scripts/", "/mock/",
               "/mocks/", "/lib/", "/out/", "/cache/", "/deployments/", "/specs/")


def _is_test_path(path: str) -> bool:
    p = "/" + path.replace("\\", "/").strip("/")
    return any(d in p for d in _SKIP_DIRS)


class RoleGuardHit(t.NamedTuple):
    guard: str
    line: int


class SurfaceHit(t.NamedTuple):
    name: str
    line: int
    value_moving: bool
    state_writing: bool
    guards: tuple[str, ...]

    @property
    def permissionless(self) -> bool:
        return self.value_moving and not self.guards


def _find_guard(run: str) -> tuple[str, ...]:
    low = run.lower()
    found = {m.group(0).lower() for m in _ROLE_GUARD_RE.finditer(run)}
    for g in _ROLE_GUARDS:
        if g in low:
            found.add(g)
    if _SENDER_GUARD.search(run):
        found.add("msg.sender-check")
    return tuple(sorted(found))


def analyze_file(path: str) -> list[SurfaceHit]:
    """Return every external/public function in `path` with its guard analysis."""
    try:
        src = open(path, encoding="utf8", errors="replace").read()
    except OSError:
        return []
    # strip comments so documented examples are not mined for "transfer(" etc.
    src = re.sub(r"/\*.*?\*/", " ", src, flags=re.S)
    src = re.sub(r"//[^\n]*", " ", src)

    lines = src.split("\n")
    hits: list[SurfaceHit] = []
    for m in _FUNC_BODY.finditer(src):
        name = m.group(1)
        run = m.group(2) or ""
        # Only public entry points.
        if "external" not in run and "public" not in run:
            continue
        if re.search(r"\bview\b|\bpure\b", run):
            continue
        start = m.start()
        line_no = src.count("\n", 0, start) + 1
        # body: from the opening brace to the matching close (bounded)
        brace = src.find("{", m.end() - 1)
        if brace < 0:
            continue
        depth, i = 0, brace
        while i < len(src) and depth == 0 or (i < len(src) and depth > 0):
            if src[i] == "{":
                depth += 1
            elif src[i] == "}":
                depth -= 1
                if depth == 0:
                    break
            i += 1
        body = src[brace:i]
        vm = bool(_VALUE_MOVING.search(body)) or bool(_EXTERNAL_CALL.search(body))
        sw = bool(_STATE_WRITE.search(body))
        if not (vm or sw):
            continue
        hits.append(
            SurfaceHit(
                name=name,
                line=line_no,
                value_moving=vm,
                state_writing=sw,
                guards=_find_guard(run + " " + body[:400]),
            )
        )
    return hits


def analyze_tree(root: str, limit_files: int = 4000) -> dict[str, t.Any]:
    """Scan a directory tree. Returns aggregate counts and per-file hotspots."""
    per_file: dict[str, list[SurfaceHit]] = {}
    scanned = 0
    for dirpath, _dirnames, filenames in os.walk(root):
        if any(d in dirpath.replace("\\", "/") for d in _SKIP_DIRS):
            continue
        for fn in filenames:
            if not fn.endswith(".sol"):
                continue
            p = os.path.join(dirpath, fn)
            rel = os.path.relpath(p, root)
            hits = analyze_file(p)
            scanned += 1
            if any(h.permissionless for h in hits):
                per_file[rel] = hits
            if scanned >= limit_files:
                break
    total_hits = [h for hs in per_file.values() for h in hs]
    permissive = [h for h in total_hits if h.permissionless]
    return {
        "files_scanned": scanned,
        "files_with_permissive_functions": len(per_file),
        "total_candidate_functions": len(total_hits),
        "permissionless_value_moving": len(permissive),
        "permissive_ratio": (len(permissive) / len(total_hits)) if total_hits else 0.0,
        "hotspots": sorted(
            (
                {
                    "file": f,
                    "permissionless": sum(1 for h in hs if h.permissionless),
                    "functions": sorted(
                        h.name for h in hs if h.permissionless
                    )[:12],
                }
                for f, hs in per_file.items()
            ),
            key=lambda r: r["permissionless"],
            reverse=True,
        )[:25],
    }


def scan_repo(repo_dir: str) -> dict[str, t.Any]:
    """Analyse the `contracts/` tree of a cloned repo (falls back to repo root)."""
    target = os.path.join(repo_dir, "contracts")
    if not os.path.isdir(target):
        target = repo_dir
    return analyze_tree(target)
