"""Long-tail screen: find live, readable, thinly-audited programs ranked by attack surface.

Every target this project has triaged was chosen for bounty size or reputation,
and all eleven closed. That is not evidence the ecosystem is clean - it is
evidence the sample was biased. Payout correlates with maturity, maturity
corplicates with having already been found and fixed, so sorting by pool size
systematically selects for programs with nothing left. The $250k tier is mostly
money already paid out; a $10k program with an unguarded withdrawal path is a
better bet at any payout.

This ranks on ATTACK SURFACE, not reward:

  live + $0 filing fee + under the ceiling   (gate, unchanged)
  has scope we can actually read             (addresses or repos)
  source is retrievable                      (Sourcify coverage / repo present)
  thin audit coverage                        (no audit evidence AND no audits dir)
  recently changed                          (a commit since the audit era)
  holds value                                (has_value - an empty instance is not a target)

Small programs are explicitly welcomed here: the point is probability, not
payout. Every judgement records WHICH signal failed so the ranking can be audited
rather than trusted.
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cli.cs_immune import _keizo, _program, _scope  # noqa: E402
from core import deploy_source  # noqa: E402
from core.cs_rpc import load_dotenv, rpc_for  # noqa: E402
from core.cs_re import has_value  # noqa: E402

MAX_ADDRS = 6          # per program, enough to judge without a sweep
MAX_PROGRAMS = 260
RECENT_DAYS = 540      # ~18 months of activity


def gh(path: str) -> dict:
    p = subprocess.run(["gh", "api", path], capture_output=True, text=True, timeout=90)
    if p.returncode != 0:
        return {}
    try:
        return json.loads(p.stdout)
    except Exception:  # noqa: BLE001
        return {}


def repo_repo(url: str) -> str:
    m = re.match(r"https://github\.com/([^/]+/[^/]+)", url)
    return m.group(1) if m else ""


def screen(slug: str) -> dict:
    """One program's long-tail profile."""
    row: dict = {"slug": slug}
    try:
        p = _program(slug)
    except Exception as exc:  # noqa: BLE001
        return {**row, "fail": f"program fetch: {exc}"[:80]}
    if not p:
        return {**row, "fail": "not on Immunefi"}

    k = _keizo(p, time.time())
    row["critical"] = k.get("critical_payout") or 0
    row["status"] = k.get("status_code")
    row["submittable"] = k.get("submittable")
    row["audit_evidence"] = bool(k.get("audit_evidence"))
    row["audit_firms"] = k.get("audit_firms") or []
    if not k.get("submittable"):
        return {**row, "fail": "not submittable"}

    try:
        sc = _scope(slug)
    except Exception as exc:  # noqa: BLE001
        return {**row, "fail": f"scope: {exc}"[:80]}
    addrs = sc.get("addresses") or []
    repos = sc.get("repos") or []
    row["n_addrs"] = len(addrs)
    row["n_repos"] = len(repos)
    if not addrs and not repos:
        return {**row, "fail": "no readable scope"}

    # --- readability ---
    verified = 0
    probed = 0
    for a in addrs[:MAX_ADDRS]:
        if not rpc_for(str(a["chain"])):
            continue
        probed += 1
        try:
            cov = deploy_source.coverage([f"{a['chain']}:{a['address']}"], timeout=30)
            verified += len(cov.get("verified", []))
        except Exception:  # noqa: BLE001
            pass
    row["sourcify_probed"] = probed
    row["sourcify_verified"] = verified
    row["readable"] = bool(repos) or verified > 0
    if not row["readable"]:
        return {**row, "fail": "no published source and nothing Sourcify-verified"}

    # --- audit thinness, verified rather than trusted ---
    audit_repos = 0
    last_push = ""
    for r in repos[:4]:
        full = repo_repo(r)
        if not full:
            continue
        meta = gh(f"repos/{full}")
        if not meta:
            continue
        last_push = max(last_push, str(meta.get("pushed_at", ""))[:10])
        names = gh(f"repos/{full}/contents") or {}
        if isinstance(names, list):
            audit_repos += sum(
                1 for e in names if re.search(r"audit", str(e.get("name", "")), re.I)
            )
    row["last_push"] = last_push
    row["audit_dirs"] = audit_repos
    row["thin_audits"] = (not row["audit_evidence"]) and audit_repos == 0

    # --- does it hold anything ---
    holding = 0
    checked = 0
    for a in addrs[:MAX_ADDRS]:
        if not rpc_for(str(a["chain"])):
            continue
        checked += 1
        try:
            v = has_value(str(a["chain"]), a["address"])
            if v.get("live"):
                holding += 1
        except Exception:  # noqa: BLE001
            pass
    row["value_checked"] = checked
    row["holding_value"] = holding

    # --- freshness ---
    fresh = False
    if last_push:
        try:
            d = time.strptime(last_push, "%Y-%m-%d")
            fresh = (time.time() - time.mktime(d)) / 86400 <= RECENT_DAYS
        except Exception:  # noqa: BLE001
            fresh = False
    row["recently_changed"] = fresh

    # --- ranking: SURFACE, not reward ---
    surface = 0
    if row["n_addrs"]:
        surface += min(3, row["n_addrs"] / 4)
    if row["n_repos"]:
        surface += min(3, row["n_repos"] / 2)
    if row["sourcify_verified"]:
        surface += min(2, row["sourcify_verified"] / 2)
    if holding:
        surface += 2
    if row["thin_audits"]:
        surface += 3
    if fresh:
        surface += 2
    row["surface_score"] = round(surface, 2)
    row["fail"] = None
    return row


def main() -> int:
    load_dotenv()
    cache = Path(".chainsource/immune_programs.json")
    slugs = []
    if cache.exists():
        slugs = [p["_slug"] for p in json.loads(cache.read_text())["programs"]
                 if p.get("_slug")][:MAX_PROGRAMS]
    print(f"screening {len(slugs)} programs for live, readable, thinly-audited surface\n")

    with ThreadPoolExecutor(max_workers=10) as pool:
        rows = [r for r in pool.map(screen, slugs) if r.get("slug")]

    screened = [r for r in rows if not r.get("fail")]
    rejected = [r for r in rows if r.get("fail")]
    Path("/tmp/longtail.json").write_text(json.dumps(rows, indent=2, default=str))

    print(f"  screened {len(rows)}   candidates {len(screened)}   "
          f"rejected {len(rejected)}\n")

    from collections import Counter
    print("  rejection reasons: " + ", ".join(
        f"{k}={v}" for k, v in Counter(r["fail"] for r in rejected).most_common(8)))

    screened.sort(key=lambda r: -(r.get("surface_score") or 0))
    print(f"\n{'program':<24}{'surf':>6}{'addrs':>6}{'repos':>6}{'verif':>6}{'holds':>6}  "
          f"{'thin':<5}{'fresh':<6}{'CRIT':>9}")
    print("-" * 92)
    for r in screened[:28]:
        print(f"{r['slug'][:23]:<24}{r['surface_score']:>6}{r['n_addrs']:>6}{r['n_repos']:>6}"
              f"{r['sourcify_verified']:>6}{r['holding_value']:>6}  "
              f"{'y' if r['thin_audits'] else 'n':<5}"
              f"{'y' if r['recently_changed'] else 'n':<6}"
              f"{('$' + format(r['critical'], ',')) if r['critical'] else '-':>9}")
    print("\n  ranked on attack surface; payout shown but NOT used for ordering")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())