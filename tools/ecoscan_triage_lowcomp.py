"""Triage low-competition Immunefi programs at CRIT/HIGH/MEDIUM.

Two inputs make this different from the earlier passes:

Severity. Every previous hunt was Critical-only, and that self-imposed bar
already cost us a real Midas Medium. This ranks across Critical, High and
Medium, which is where the reachable findings actually are.

Competition. A curated list of programs reported as no longer receiving
submissions. That is a durable targeting advantage rather than a mood: fewer
researchers means less dedup risk on a finding that does land, and undistributed
bounty pools. It is stored as data here, not as a setting, so it survives and
stays auditable - if a program on this list starts receiving reports again, the
entry should be removed rather than quietly ignored.

The point of ranking is to pick what to READ. Nothing here finds a bug; it
narrows the field to a couple of contracts worth understanding properly.
"""
from __future__ import annotations

import json
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from cli.cs_immune import _keizo, _program, _scope  # noqa: E402
from core.cs_rpc import load_dotenv  # noqa: E402

# Reported as no longer receiving submissions. Treat as a hint to prefer, never
# as a claim that the program is closed - liveness is checked via scope fetch.
QUIET_PROGRAMS = {
    "jito", "linea", "kamino", "nucleus", "zenlink", "apsida", "galagames",
    "stellaswap", "alpha-venture-dao", "hedera", "stackingdao", "mux",
    "stakewise", "zerion", "metronome", "vesper",
}
REVIVED = {"livepeer", "stacks"}


def triage(slug: str) -> dict:
    import time

    rec: dict = {"slug": slug}
    rec["quiet"] = slug in QUIET_PROGRAMS
    rec["revived"] = slug in REVIVED
    try:
        scope = _scope(slug)
    except Exception as exc:  # noqa: BLE001
        return {**rec, "error": f"scope: {exc}"}
    rec["addresses"] = len(scope.get("addresses", []) or [])
    rec["repos"] = scope.get("repos", []) or []
    try:
        prog = _program(slug)
    except Exception as exc:  # noqa: BLE001
        return {**rec, "error": f"meta: {exc}"}
    rec["title"] = prog.get("title") or prog.get("project") or slug
    row = _keizo(prog, time.time())
    rec["max_bounty"] = row.get("max_bounty")
    rec["critical_payout"] = row.get("critical_payout")
    rec["keizo"] = row.get("keizo")
    rec["audit_evidence"] = row.get("audit_evidence")
    rec["audit_firms"] = row.get("audit_firms") or []
    rec["updated"] = row.get("updated_date")
    rec["severities"] = row.get("severities") or prog.get("severities")
    # readable source is a hard requirement; nothing can be reviewed without it
    rec["readable"] = bool(rec["repos"] or rec["addresses"])
    return rec


def main() -> int:
    load_dotenv()
    slugs = sys.argv[1:] or sorted(QUIET_PROGRAMS | REVIVED)
    with ThreadPoolExecutor(max_workers=6) as pool:
        rows = list(pool.map(triage, slugs))

    ok = [r for r in rows if not r.get("error")]
    print(f"triaged {len(rows)} programs, {len(ok)} with reachable scope\n")

    def money(r):
        return r.get("critical_payout") or r.get("max_bounty") or 0

    ok.sort(key=lambda r: (not r["readable"], not (r["quiet"] or r["revived"]), -money(r)))
    print(f"{'program':<22}{'signal':<9}{'payout':>11}{'addrs':>7}{'repos':>6}  audits")
    print("-" * 78)
    for r in ok:
        sig = "quiet" if r["quiet"] else ("revived" if r["revived"] else "-")
        aud = ",".join(r["audit_firms"][:2]) or ("detected" if r["audit_evidence"] else "none")
        print(f"{r['slug']:<22}{sig:<9}{money(r):>11,}{r['addresses']:>7}{len(r['repos']):>6}  {aud}")
    for r in rows:
        if r.get("error"):
            print(f"{r['slug']:<22} ERROR {r['error'][:44]}")

    print("\nREADME FIRST: the three with money and readable source are where to read code.")
    json.dump(ok, open("/tmp/lowcomp_triage.json", "w"), indent=2, default=str)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())