"""Run the rounding-drift attack across a list of real vaults on forks.

Unlike the fixture binding there is nothing to compare against: a live vault's
conversion functions cannot be faithfully reimplemented in Python without reading
its source, so the fork result is the answer. What this reports per vault is
whether the attack could run at all - a vault with a withdrawal cap or a minimum
deposit cannot be cycled, and that is reported as unprobeable rather than
cleared.

Usage:
    python3 run_drift.py --vaults 0xA 0xB [--asset 0xTOKEN] [--cycles 20]
"""
from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
HARNESS = HERE.parent
REPO = HARNESS.parent.parent
sys.path.insert(0, str(REPO))

from core.cs_rpc import load_dotenv, rpc_for  # noqa: E402

FOUNDRY = Path.home() / ".foundry/bin"
DEFAULT_RPC = "https://ethereum.publicnode.com"
_LOG = re.compile(r"DRIFT_(\S+)\s+(\S+)\s*:\s*(-?\d+)")
_CLS = re.compile(r"CLASSIFY\s+(\S+)\s*:\s*(-?\d+)")


def _env() -> dict[str, str]:
    return {**os.environ, "PATH": f"{FOUNDRY}:{os.environ.get('PATH', '')}"}


def latest_block() -> int:
    out = subprocess.run(["cast", "block-number", "--rpc-url", os.environ.get("ALCHEMY_MAINNET", DEFAULT_RPC)],
                         capture_output=True, text=True, timeout=120, env=_env())
    try:
        return int(out.stdout.strip())
    except ValueError:
        return 0


def classify(vault: str, asset: str, block: int) -> tuple[dict, str]:
    """Measure whether a round-trip shortfall is a fee or rounding drift.

    A designed exit fee scales with the deposit; a rounding bug is a roughly
    fixed number of wei. Both read identically at one amount, so both regimes
    are measured before anything is concluded.
    """
    env = _env()
    env.update({"TARGET_VAULT": vault, "FORK_BLOCK": str(block),
                "RPC_URL": os.environ.get("ALCHEMY_MAINNET", DEFAULT_RPC)})
    if asset:
        env["TARGET_ASSET"] = asset
    for _ in range(2):
        p = subprocess.run(["forge", "test", "--match-contract", "RoundingDriftTest",
                            "--match-test", "test_classify_shortfall", "-vv"],
                           cwd=HARNESS, capture_output=True, text=True, timeout=1800, env=env)
        out = p.stdout + p.stderr
        got = dict((k, int(v)) for k, v in _CLS.findall(out))
        if got:
            return got, out
    return {}, out


def run(vault: str, asset: str, block: int, cycles: int, test: str) -> tuple[dict, str]:
    env = _env()
    env.update({"TARGET_VAULT": vault, "FORK_BLOCK": str(block),
                "RPC_URL": os.environ.get("ALCHEMY_MAINNET", DEFAULT_RPC),
                "CYCLES": str(cycles)})
    if asset:
        env["TARGET_ASSET"] = asset
    combined = ""
    parsed: dict[str, int] = {}
    # one retry: the authenticated endpoint intermittently times out mid-sweep and
    # an empty result reads as "no drift" when it means "never ran"
    for attempt in range(2):
        p = subprocess.run(["forge", "test", "--match-contract", "RoundingDriftTest",
                            "--match-test", test, "-vv"],
                           cwd=HARNESS, capture_output=True, text=True, timeout=1800, env=env)
        combined = p.stdout + p.stderr
        parsed = dict((f, int(v)) for _t, f, v in _LOG.findall(combined))
        if parsed:
            break
    return parsed, combined


def verdict(d: dict) -> tuple[str, str]:
    if not d:
        return "RPC-FAILED", "no output from two attempts; this is an endpoint failure, not a result"
    done = d.get("cycles_done", 0)
    net = d.get("net", 0)
    stopped = d.get("stopped", 0)
    if done == 0:
        return "UNPROBEABLE", "vault blocked the first cycle (cap, minimum deposit, or no redeem)"
    if net < 0:
        return "DRIFT FOUND", f"depositor lost {-net:,} over {done} cycles"
    return "NO DRIFT", f"depositor net +{net:,} over {done} cycles (vault_delta {d.get('vault_delta',0):,})"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--vaults", nargs="+", required=True)
    ap.add_argument("--asset", default="")
    ap.add_argument("--cycles", type=int, default=20)
    ap.add_argument("--block", type=int, default=0)
    args = ap.parse_args()

    load_dotenv()
    block = args.block or latest_block()
    print(f"fork block: {block}")

    summary: dict[str, str] = {}
    print(f"{'vault':<44}{'rate_ppb':>10}  verdict")
    print("-" * 96)
    for v in args.vaults:
        c, _ = classify(v, args.asset, block)
        rate = c.get("small_rate_ppb", 0)
        verdict_code = c.get("verdict", -1)
        if not c:
            note = "RPC-FAILED - no output; not a result"
        elif verdict_code == 1:
            # rate is parts-per-billion: fraction = rate/1e9, percent = rate/1e7
            note = f"EXIT FEE {rate/1e7:.6f}% - proportional, a designed charge, not drift"
        elif verdict_code == 2:
            note = "ROUNDING DRIFT - shortfall roughly constant across sizes, a bug"
        elif verdict_code == 0:
            note = "NO SHORTFALL - round trip is exact"
        else:
            note = "no measurable shortfall"
        print(f"{v:<44}{rate:>10}  {note}")
        if verdict_code == 2:
            summary[v] = "DRIFT"
        elif verdict_code == 1:
            summary[v] = "FEE"
    print()
    print(f"drift: {sum(1 for x in summary.values() if x == 'DRIFT')}   "
          f"exit fee: {sum(1 for x in summary.values() if x == 'FEE')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
