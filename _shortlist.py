"""Build an actionable Immunefi shortlist for economic/mechanism High hunting.

Discipline applied, each rule from a mistake made earlier in this session:
  1. UNTOUCHED   - not already triaged on disk.
  2. CODE SCOPE  - the program page must actually list code repos. A program with
                   zero retrievable scope cannot be read (this is what 1inch -
                   Wallet turned out to be: a mobile app, not contracts).
  3. NO AUDIT EVIDENCE - ranked last, reported explicitly, never asserted as
                   "unaudited" (detection is known-unreliable: Chainlink and
                   Arbitrum both report 0 despite heavy audits).
  4. ECONOMIC FIT - genre keywords indicating vault / lending / AMM / leverage /
                   oracle surface, i.e. where High-severity mechanism bugs live.
No entry payment is required on any Immunefi program.
"""
import json
import re
import subprocess
import sys
import time
from pathlib import Path

CHAIN = Path(__file__).resolve().parent
ECONOMIC = re.compile(
    r"vault|lending|lend|borrow|amm|perp|leverage|yield|liquidat|stable|rwa|"
    r"restak|cdp|collateral|market|money market|index|etf|usd|credit|"
    r"dex|swap|synth|derivat|options|insurance",
    re.I,
)


def disk_names() -> set[str]:
    base = Path("/home/charad7/Developments/Personal/Hacks")
    names = set()
    for plat in base.iterdir():
        if not plat.is_dir():
            continue
        names.add(re.sub(r"[^a-z0-9]", "", plat.name.lower()))
        for d in plat.iterdir():
            if d.is_dir():
                names.add(re.sub(r"[^a-z0-9]", "", d.name.lower()))
    return names


def scope_repos(slug: str) -> list[str]:
    p = subprocess.run(
        [sys.executable, "-m", "cli", "immune", "scope", slug, "--json"],
        capture_output=True, text=True, timeout=300, cwd=CHAIN,
    )
    try:
        return json.loads(p.stdout).get("repos", []) or []
    except Exception:
        return []


def main() -> None:
    rows = json.load(open("/tmp/k3.json"))
    touched = disk_names()

    def key(s):
        return re.sub(r"[^a-z0-9]", "", (s or "").lower())

    cands = []
    for r in rows:
        slugs = {key(r.get("slug")), key(r.get("project"))}
        if slugs & touched:
            continue
        cands.append(r)

    print(f"no-audit-evidence pool: {len(rows)}   untouched: {len(cands)}\n")

    scored = []
    for r in sorted(cands, key=lambda x: -(x.get("critical_payout") or 0)):
        slug = r["slug"]
        repos = scope_repos(slug)
        if not repos:
            continue  # rule 2: unreadable scope is a hard disqualifier
        econ = bool(ECONOMIC.search(r.get("project") or "")) or any(
            ECONOMIC.search(u) for u in repos
        )
        scored.append({
            "project": r.get("project"),
            "slug": slug,
            "critical": r.get("critical_payout"),
            "max": r.get("max_bounty"),
            "updated": r.get("updated_date"),
            "n_repos": len(repos),
            "econ": econ,
            "repos": repos[:4],
        })
        time.sleep(1)

    scored.sort(key=lambda x: (not x["econ"], -(x["critical"] or 0)))
    print(f"{'program':<26}{'CRIT':>10}{'repos':>6} {'econ':>5}  sample repos")
    print("-" * 104)
    for s in scored:
        crit = f"${int(s['critical']):,}" if s["critical"] else "-"
        print(f"{str(s['project'])[:24]:<26}{crit:>10}{s['n_repos']:>6} "
              f"{'yes' if s['econ'] else 'no':>5}  {', '.join(u.split('/')[-1] for u in s['repos'])}")
    json.dump(scored, open("/tmp/shortlist.json", "w"), indent=2)
    print(f"\n{len(scored)} candidates with retrievable code scope -> /tmp/shortlist.json")


if __name__ == "__main__":
    main()