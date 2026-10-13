"""Find ERC4626 vaults among a program's in-scope addresses, then attack them.

sDAI and wstETH are flagship infrastructure and both are correctly hardened. The
economic surface worth probing is smaller and newer, but those are exactly the
contracts a scope page lists and a human never gets round to reading.

So: take the in-scope addresses we already have from the Immunefi catalog, probe
each one for the ERC4626 surface, and run the donation/inflation attack against
every vault that answers. In-scope means deployed, relevant, and already covered
by a program, so nothing here is a wild hunt.

Probing is by name and never assumes a failure means anything: wstETH's
totalAssets() reverts on mainnet, and that is a different fact from "not a vault".
Each verdict is reported with which calls answered.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

HERE = Path(__file__).resolve().parent
HARNESS = HERE.parent
REPO = HARNESS.parent.parent
sys.path.insert(0, str(REPO))

from core import deploy_source  # noqa: E402
from core.cs_rpc import load_dotenv, rpc_for  # noqa: E402

FOUNDRY = Path.home() / ".foundry/bin"
RPC = "https://ethereum.publicnode.com"

load_dotenv(REPO)

# Function detection must NOT use `cast call`. cast call SIMULATES, so a function
# that exists but reverts on the probed input is indistinguishable from one that
# does not exist - Sky's sDAI deposit() reverts on a 0-amount simulation and reads
# as absent. Matching function selectors against the deployed bytecode is
# immune to runtime revert, and needs one RPC call per address instead of eight.
#
# Return types and parameter variants differ between valid ERC4626
# implementations, so a capability is "ANY of these signatures is present".
CAPABILITIES = {
    "totalAssets":    ["totalAssets()"],
    "totalSupply":    ["totalSupply()"],
    "convertToShares":["convertToShares(uint256)"],
    "convertToAssets":["convertToAssets(uint256)"],
    "deposit": [
        "deposit(uint256,address)",
        "deposit(uint256)",
        "deposit(uint256,address,uint256)",
        "deposit(uint256,address,uint256,bytes)",
    ],
    "withdraw": [
        "withdraw(uint256,address,address)",
        "withdraw(uint256,address)",
        "withdraw(uint256,address,address,uint256)",
    ],
    "asset":          ["asset()"],
    "decimalsOffset": ["decimalsOffset()"],
}

# capabilities whose presence makes something an ERC4626-shaped vault
VAULT_CORE = {"totalAssets", "totalSupply", "convertToShares", "convertToAssets",
              "deposit", "withdraw"}

_SELECTOR_CACHE: dict[str, str | None] = {}


def selector(sig: str) -> str | None:
    """4-byte selector, cached. Falls back to keccak if `cast sig` is unavailable."""
    if sig in _SELECTOR_CACHE:
        return _SELECTOR_CACHE[sig]
    try:
        p = subprocess.run(["cast", "sig", sig], capture_output=True, text=True,
                           timeout=60, env=_env())
        val = p.stdout.strip() if p.returncode == 0 else ""
        _SELECTOR_CACHE[sig] = val or None
    except Exception:  # noqa: BLE001
        _SELECTOR_CACHE[sig] = None
    return _SELECTOR_CACHE[sig]


def _warm_selectors() -> None:
    for sigs in CAPABILITIES.values():
        for sig in sigs:
            selector(sig)


def _env() -> dict[str, str]:
    import os

    return {**os.environ, "PATH": f"{FOUNDRY}:{os.environ.get('PATH', '')}"}


def cast(args: list[str], timeout: int = 45) -> tuple[bool, str]:
    try:
        p = subprocess.run(["cast", *args], capture_output=True, text=True,
                           timeout=timeout, env=_env())
        return p.returncode == 0, p.stdout.strip()
    except Exception:  # noqa: BLE001
        return False, ""


# EIP-1967 implementation slot; the ERC4626 logic lives in the implementation,
# not the proxy shell, so bytecode matching on a proxy alone finds nothing.
IMPL_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
BEACON_SLOT = "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50"
MINIMAL_PROXY_SLOT = "0xc5f16f0fcc639fa48a6947836d9850f504798523bf8c9a3a87d5876cf622bcf7"


def _impl_address(url: str, addr: str) -> str | None:
    """Resolve an EIP-1967 / minimal-proxy implementation, if there is one."""
    for slot in (IMPL_SLOT, BEACON_SLOT, MINIMAL_PROXY_SLOT):
        ok, val = cast(["storage", addr, slot, "--rpc-url", url], timeout=60)
        if ok and val and val != "0x" and len(val) >= 66:
            cand = "0x" + val[-40:]
            if int(cand, 16) != 0:
                return cand
    return None


def probe(chain: str, addr: str) -> dict:
    """Report which ERC4626 selectors are present. Absence is a fact, not a verdict."""
    url = rpc_for(chain)
    out: dict = {"chain": chain, "address": addr, "selectors": {},
                 "answers": {}, "is_vault": False}
    if not url:
        out["error"] = f"no rpc for chain {chain}"
        return out

    ok, code = cast(["code", addr, "--rpc-url", url], timeout=90)
    if not ok or not code or code == "0x":
        out["error"] = "no code / rpc failed"
        return out
    body = code.lower()

    # follow the proxy so implementation-side selectors are visible
    impl = _impl_address(url, addr)
    if impl:
        out["implementation"] = impl
        ok2, icode = cast(["code", impl, "--rpc-url", url], timeout=90)
        if ok2 and icode and icode != "0x":
            body += icode.lower()

    for name, sigs in CAPABILITIES.items():
        present = [s for s in sigs if (sel := selector(s)) and sel.lower() in body]
        out["selectors"][name] = present

    # Static selectors are supplementary, not decisive: Sky's sDAI is a diamond
    # (EIP-2535) proxy, so it has no EIP-1967 slot and none of its ERC4626
    # selectors appear in its own 10.9KB of code - the logic lives in facets
    # registered in storage. Bytecode matching cannot see through that.
    #
    # The decisive signal is a runtime call of the pure view functions, which
    # traverses any proxy. deposit/withdraw are deliberately NOT required: a
    # simulated call reverts on a zero amount and that is indistinguishable from
    # an absent function (which is how sDAI first read as having no deposit at
    # all).
    views = {
        "totalAssets": ("totalAssets()(uint256)", []),
        "convertToShares": ("convertToShares(uint256)(uint256)", ["0"]),
        "convertToAssets": ("convertToAssets(uint256)(uint256)", ["0"]),
        "totalSupply": ("totalSupply()(uint256)", []),
    }
    for name, (sig, vargs) in views.items():
        ok, val = cast(["call", addr, sig, *vargs, "--rpc-url", url], timeout=60)
        out["answers"][name] = ok
        if ok:
            out[name] = val

    core_views = ("totalAssets", "convertToShares", "convertToAssets")
    out["is_vault"] = all(out["answers"].get(k, False) for k in core_views)
    out["static_match"] = all(
        bool(out["selectors"].get(k)) for k in VAULT_CORE
    )
    out["detection"] = (
        "view-call" if out["is_vault"] and not out["static_match"]
        else "selector" if out["static_match"]
        else "none"
    )
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("slugs", nargs="+", help="Immunefi program slug(s)")
    ap.add_argument("--limit", type=int, default=40)
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--json", default="")
    args = ap.parse_args()

    from cli.cs_immune import _scope

    jobs: list[tuple[str, str]] = []
    for slug in args.slugs:
        try:
            scope = _scope(slug)
        except Exception as exc:  # noqa: BLE001
            print(f"[err] scope fetch failed for {slug}: {exc}", file=sys.stderr)
            continue
        addrs = scope.get("addresses", [])[: args.limit]
        print(f"{slug}: {len(scope.get('addresses', []))} address(es), probing {len(addrs)}")
        for a in addrs:
            jobs.append((str(a["chain"]), a["address"]))

    print(f"\nprobing {len(jobs)} address(es) with {args.workers} workers...\n")
    _warm_selectors()
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        results = list(pool.map(lambda j: probe(*j), jobs))

    vaults = [r for r in results if r.get("is_vault")]
    unknown = [r for r in results if r.get("error")]
    for r in results:
        if r.get("is_vault"):
            missing = [k for k, v in r["answers"].items() if not v]
            print(f"  VAULT  {r['chain']}:{r['address']}  offset={r.get('decimalsOffset','n/a')} "
                  f"asset={r.get('asset','n/a')}" + (f"  missing={missing}" if missing else ""))
    print(f"\n{len(vaults)} ERC4626 vault(s) of {len(results)} probed; "
          f"{len(unknown)} unreachable")
    if results and len(unknown) == len(results):
        # Every target unreachable means the endpoint is broken, not that the
        # programs are empty. Reporting "0 vaults" here would read as coverage.
        errs = sorted({r.get("error", "") for r in results})
        print("\nWARNING: every address was unreachable - this is an endpoint "
              "fault, not a result.")
        for e in errs[:4]:
            print(f"  {e}")
        print("  check RPC_*/ALCHEMY_* in .env, or the public fallback for this chain")

    if args.json:
        Path(args.json).write_text(json.dumps(results, indent=2, default=str))
        print(f"wrote {args.json}")

    if vaults:
        print("\nnext: run run_target.py against each VAULT address above")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())