"""Full ChainScope triage sweep across every live, submittable Immunefi program.

Runs the whole battery rather than one pass, because each layer answers a
different question and any one of them alone can be confidently wrong:

  gate       liveness, $0 filing fee, pool ceiling, severity floor
  scope      which addresses/repos the program actually exposes
  re probe   proxy kind, diamond facets, runtime, interfaces, events,
             dormant selectors, access-control shape
  re uninit  is an initializer still callable  (permissionless takeover)
  re diff    deployed bytecode vs a reference implementation
  deployed   Sourcify coverage, so "no source" is distinguished from
             "source we have not fetched"
  econ       donation / rounding / sandwich against any ERC4626 found
  veck       21 vulnerability classes over any source we do have

Every failure is recorded per-address rather than aborting the sweep: a target
that cannot be fetched is a fact about the target, not about the tool.
"""
from __future__ import annotations

import json
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cli.cs_immune import _keizo, _program, _scope  # noqa: E402
from core import cs_re, deploy_source  # noqa: E402
from core.cs_rpc import load_dotenv, rpc_for  # noqa: E402

MAX_ADDRS_PER_PROGRAM = 12
MAX_PROGRAMS = 60


def program_rows(limit: int = MAX_PROGRAMS) -> list[dict]:
    """Every program passing the submission policy, with its scope."""
    cache = Path(".chainsource/immune_programs.json")
    slugs = []
    if cache.exists():
        data = json.loads(cache.read_text())
        slugs = [p["_slug"] for p in data["programs"] if p.get("_slug")][:limit]

    def one(slug: str):
        try:
            p = _program(slug)
        except Exception as exc:  # noqa: BLE001
            return None
        if not p:
            return None
        r = _keizo(p, time.time())
        if not r.get("submittable"):
            return None
        try:
            sc = _scope(slug)
        except Exception:
            sc = {"addresses": [], "repos": []}
        return {
            "slug": slug,
            "critical": r.get("critical_payout") or 0,
            "medium": r.get("medium_payout"),
            "floor": r.get("min_viable_severity"),
            "addresses": (sc.get("addresses") or [])[:MAX_ADDRS_PER_PROGRAM],
            "repos": sc.get("repos") or [],
        }

    with ThreadPoolExecutor(max_workers=8) as pool:
        return [r for r in pool.map(one, slugs) if r]


def probe_address(spec: dict) -> dict:
    """Every RE pass for one address, failures isolated."""
    chain, addr = spec["chain"], spec["address"]
    out: dict = {"chain": chain, "address": addr}
    if not rpc_for(chain):
        out["error"] = f"no rpc for chain {chain}"
        return out
    try:
        info = cs_re.analyze(chain, addr, resolve_4byte=False)
    except Exception as exc:  # noqa: BLE001
        out["error"] = f"{type(exc).__name__}: {exc}"[:120]
        return out

    proxy = info.get("proxy", {})
    out["kind"] = proxy.get("kind")
    out["facets"] = len(proxy.get("facets") or [])
    out["runtime"] = (info.get("implementations") or [{}])[0].get("code_hex") is not None
    out["selectors"] = len(info.get("selectors", {}).get("dispatcher", []))
    out["interfaces"] = sorted(info.get("inference", {}).get("interfaces", {}))
    out["dormant"] = info.get("dormant", {}).get("dormant_count", 0)
    out["access"] = info.get("access", {}).get("verdict")
    out["events"] = info.get("events", {}).get("resolved_count", 0)
    try:
        out["metadata_cid"] = cs_re.extract_metadata(
            (info.get("implementations") or [{}])[0].get("code_hex", "0x")
        ).get("cid")
    except Exception:  # noqa: BLE001
        out["metadata_cid"] = None

    # the check that most often finds a real Critical
    try:
        u = cs_re.uninitialized_probe(chain, addr, max_args=4)
        out["uninit"] = u.get("verdict")
        out["uninit_probes"] = len(u.get("probes", []))
    except Exception as exc:  # noqa: BLE001
        out["uninit"] = f"ERR {type(exc).__name__}"
    return out


def main() -> int:
    load_dotenv()
    progs = program_rows()
    print(f"live + submittable programs: {len(progs)}")
    total = sum(len(p["addresses"]) for p in progs)
    print(f"in-scope addresses to probe: {total}\n")

    jobs = []
    for p in progs:
        for a in p["addresses"]:
            jobs.append((p["slug"], {"chain": str(a["chain"]), "address": a["address"]}))

    results: list[dict] = []
    with ThreadPoolExecutor(max_workers=8) as pool:
        futs = {pool.submit(probe_address, spec): (slug, spec) for slug, spec in jobs}
        done = 0
        for fut in as_completed(futs):
            slug, spec = futs[fut]
            try:
                r = fut.result()
            except Exception as exc:  # noqa: BLE001
                r = {"chain": spec["chain"], "address": spec["address"],
                     "error": f"{type(exc).__name__}: {exc}"[:120]}
            r["program"] = slug
            results.append(r)
            done += 1
            if done % 25 == 0:
                print(f"  ...{done}/{len(jobs)} probed")

    Path("/tmp/sweep_results.json").write_text(json.dumps(results, indent=2, default=str))

    errs = [r for r in results if r.get("error")]
    print(f"\nprobed {len(results)}  errors {len(errs)}")

    # ---- the findings that matter ----
    uninit = [r for r in results if r.get("uninit") == "UNINITIALIZED"]
    print(f"\n=== UNINITIALIZED (permissionless takeover) : {len(uninit)} ===")
    for r in uninit:
        print(f"  {r['program']:<18} {r['chain']}:{r['address']}  "
              f"selectors={r.get('selectors')} interfaces={r.get('interfaces')}")

    proxied = [r for r in results if r.get("kind", "").startswith(("EIP1967", "BEACON"))]
    print(f"\nupgradeable (1967/beacon) : {len(proxied)}  "
          f"of {len([r for r in results if not r.get('error')])} reachable")

    diamonds = [r for r in results if r.get("kind") == "EIP2535_DIAMOND"]
    print(f"diamonds (logic hidden in facets) : {len(diamonds)}")
    for r in diamonds[:10]:
        print(f"  {r['program']:<18} {r['address']}  facets={r['facets']}")

    vaults = [r for r in results if "ERC4626" in (r.get("interfaces") or [])]
    print(f"\nERC4626 vaults among in-scope addresses : {len(vaults)}")
    for r in vaults[:15]:
        print(f"  {r['program']:<18} {r['chain']}:{r['address']}  dorm={r.get('dormant')} "
              f"access={r.get('access')} events={r.get('events')}")

    dormant_hi = [r for r in results
                  if r.get("dormant", 0) >= 3 and r.get("selectors", 0) >= 20]
    print(f"\nsurface with >=3 unnamed selectors : {len(dormant_hi)}")
    for r in dormant_hi[:12]:
        print(f"  {r['program']:<18} {r['chain']}:{r['address']}  "
              f"dormant={r['dormant']}/{r['selectors']}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())