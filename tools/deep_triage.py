"""Interface, event and dormant-path passes WITH 4byte resolution.

`full_triage.py` runs these with resolve_4byte disabled for speed, so its
interface and dormant columns read 0 - which is not a finding, it is missing work.
This closes that gap.

Efficiency: resolving every selector of every address independently would be
~14,000 lookups. Contracts share selectors heavily (totalSupply, balanceOf,
transfer all recur), so selectors are deduplicated globally and resolved once,
with the result cached to disk so repeat runs are offline. A rate-limit is
recorded as UNKNOWN rather than as "no signature", because the difference is
exactly what makes a detector look busy while finding nothing.
"""
from __future__ import annotations

import json
import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cli.cs_immune import _keizo, _program, _scope  # noqa: E402
from core import cs_re  # noqa: E402
from core.cs_rpc import load_dotenv, rpc_for  # noqa: E402

CACHE = Path("/tmp/selector_cache.json")
MAX_ADDRS_PER_PROGRAM = 12


def load_cache() -> dict[str, list[str]]:
    if CACHE.exists():
        try:
            return json.loads(CACHE.read_text())
        except Exception:  # noqa: BLE001
            return {}
    return {}


def save_cache(c: dict[str, list[str]]) -> None:
    CACHE.write_text(json.dumps(c, indent=0))


def gather() -> tuple[list[tuple[str, str, str]], set[str]]:
    """Collect (program, chain, address) plus every selector seen."""
    cache = json.loads(Path(".chainsource/immune_programs.json").read_text())
    slugs = [p["_slug"] for p in cache["programs"] if p.get("_slug")]

    def one(slug: str):
        try:
            p = _program(slug)
        except Exception:  # noqa: BLE001
            return None
        if not p:
            return None
        r = _keizo(p, __import__("time").time())
        if not r.get("submittable"):
            return None
        try:
            sc = _scope(slug)
        except Exception:  # noqa: BLE001
            sc = {}
        out = []
        for a in (sc.get("addresses") or [])[:MAX_ADDRS_PER_PROGRAM]:
            out.append((slug, str(a["chain"]), a["address"]))
        return out or None

    triples: list[tuple[str, str, str]] = []
    with ThreadPoolExecutor(max_workers=8) as pool:
        for res in pool.map(one, slugs):
            if res:
                triples.extend(res)

    selectors: set[str] = set()
    codes: dict[tuple[str, str, str], str] = {}

    def code_for(t: tuple[str, str, str]) -> tuple[tuple[str, str, str], str, list[str]]:
        slug, chain, addr = t
        try:
            code = cs_re.runtime_code(chain, addr)
        except Exception:  # noqa: BLE001
            return t, "", []
        return t, code, cs_re.extract_selectors(code)["dispatcher"]

    with ThreadPoolExecutor(max_workers=10) as pool:
        for t, code, sels in pool.map(code_for, triples):
            if code:
                codes[t] = code
                selectors.update(sels)

    return list(codes.keys()), selectors


def main() -> int:
    load_dotenv()
    print("fetching deployed code and extracting selectors...")
    addresses, selectors = gather()
    print(f"  {len(addresses)} contract(s), {len(selectors)} UNIQUE selectors\n")

    cache = load_cache()
    todo = sorted(s for s in selectors if s not in cache)
    print(f"cache hit: {len(selectors) - len(todo)}   to resolve: {len(todo)}")

    if todo:
        done = 0
        failed = 0
        with ThreadPoolExecutor(max_workers=6) as pool:
            futs = {pool.submit(cs_re.resolve_selectors, [s]): s for s in todo}
            for fut in as_completed(futs):
                sel = futs[fut]
                try:
                    res = fut.result()
                except Exception:  # noqa: BLE001
                    res = {}
                names = res.get(sel)
                if names is None:
                    failed += 1
                    cache[sel] = ["__RATE_LIMITED__"]
                else:
                    cache[sel] = names
                done += 1
                if done % 100 == 0:
                    print(f"  ...{done}/{len(todo)}")
        save_cache(cache)
        print(f"resolved {done - failed}, {failed} rate-limited/unknown")

    limited = sum(1 for v in cache.values() if v == ["__RATE_LIMITED__"])
    print(f"cache now holds {len(cache)} selectors ({limited} unknown)\n")

    # ---- apply to every contract ----
    rows = []
    for slug, chain, addr in addresses:
        try:
            code = cs_re.runtime_code(chain, addr)
        except Exception:  # noqa: BLE001
            continue
        sel = cs_re.extract_selectors(code)["dispatcher"]
        resolved = {s: [n for n in cache.get(s, []) if n != "__RATE_LIMITED__"]
                    for s in sel}
        inf = cs_re.infer_interfaces(resolved) if resolved else {}
        dorm = cs_re.dormant_paths(code, resolved, inf.get("interfaces", {}))
        try:
            ev = cs_re.resolve_events(cs_re.event_topics(code)[:30])
        except Exception:  # noqa: BLE001
            ev = {}
        rows.append({
            "program": slug, "chain": chain, "address": addr,
            "selectors": len(sel),
            "interfaces": sorted(inf.get("interfaces", {})),
            "dormant": dorm.get("dormant_count", 0),
            "dormant_risk": dorm.get("risk"),
            "delegatecall": dorm.get("contract_has_delegatecall"),
            "selfdestruct": dorm.get("contract_has_selfdestruct"),
            "events_named": ev.get("resolved_count", 0),
            "events": [e["signatures"][0] for e in ev.get("events", []) if e.get("signatures")][:6],
            "access": cs_re.access_control_hints(code)["verdict"],
        })

    Path("/tmp/deep_results.json").write_text(json.dumps(rows, indent=2, default=str))

    ok = [r for r in rows if r["selectors"]]
    print(f"=== analysed {len(ok)} contracts with 4byte resolution ===\n")

    print("--- ERC4626 vaults in bounty scope ---")
    v = [r for r in ok if "ERC4626" in r["interfaces"]]
    for r in v:
        print(f"  {r['program']:<18} {r['chain']}:{r['address']}  dorm={r['dormant']} "
              f"access={r['access']}")
    print(f"  total: {len(v)}")

    print("\n--- 7579 / smart-account surface ---")
    for r in ok:
        if "ERC7579" in r["interfaces"]:
            print(f"  {r['program']:<18} {r['chain']}:{r['address']}")

    print("\n--- unnamed selectors worth reading (>=3, >=20 total) ---")
    d = [r for r in ok if r["dormant"] >= 3 and r["selectors"] >= 20]
    d.sort(key=lambda r: -(r["dormant"] / max(1, r["selectors"])))
    for r in d[:15]:
        print(f"  {r['program']:<18} {r['dormant']:>3}/{r['selectors']:<4} "
              f"risk={r['dormant_risk']:<7} {r['chain']}:{r['address']}")

    print("\n--- contracts that can run foreign code (delegatecall) ---")
    dl = [r for r in ok if r["delegatecall"]]
    for r in dl[:12]:
        print(f"  {r['program']:<18} {r['chain']}:{r['address']}  sel={r['selectors']}")

    print("\n--- richest event vocabularies ---")
    for r in sorted(ok, key=lambda x: -x["events_named"])[:10]:
        if r["events_named"]:
            print(f"  {r['program']:<18} {r['events_named']:>3} events  e.g. "
                  + "; ".join(r["events"][:2]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())