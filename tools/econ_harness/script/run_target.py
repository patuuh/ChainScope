"""Run the donation / inflation attack against a REAL deployed vault on a fork.

The fixture binding (`check_binding.py`) proves `core/cs_econ.py` is
self-consistent with EVM execution. That cannot tell you whether any real vault
is affected. This does, and it does it in the order that matters:

  1. confirm the target has published/verified source, so you know what you are
     attacking;
  2. confirm the vault exposes the ERC4626 surface the probe needs - wstETH's
     `totalAssets()` reverts on mainnet, and a bare EvmError there is
     indistinguishable from a failed attack;
  3. run the attack on a local fork and report the numbers.

State safety: forking only. Nothing is submitted to mainnet; the target is read
from and called on a local copy.

IMPORTANT LIMITATION OF THE MODEL, which this harness is what exposed:
`cs_econ.donation_attack` assumes an EMPTY vault - the attacker's seed is the
only supply. Against a live vault holding 164k DAI, a 1-wei seed is
irrelevant: the attacker cannot become a dominant holder, so the inflation never
happens. Viability depends on the attacker's share of total supply, not only on
their absolute deposit. Treat a model prediction on a seeded vault as a bound,
and read the fork numbers as the answer.

Usage:
    python3 run_target.py --vault 0x83F20F44975D03b1b09e64809B757c47f942BEeA
    python3 run_target.py --vault 0x... --asset 0x... --block 26092205
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

from core import deploy_source  # noqa: E402

FOUNDRY = Path.home() / ".foundry/bin"
DEFAULT_RPC = "https://ethereum.publicnode.com"

_INT = re.compile(r"RESULT\s+(\S+)\s+(.+?)\s*:\s*(-?\d+)")
_BOOL = re.compile(r"RESULT\s+(\S+)\s+(withdrawal_ok|withdrawal_reverted|victim_deposit_reverted)\s*:\s*(\d)")
_BYTES = re.compile(r"RESULT\s+withdraw_revert_reason\s*:\s*(0x[0-9a-fA-F]*)")
_UINT = re.compile(r"PREREQ\s+(\S+)\s+available\s*:\s*(\d)")


def _env() -> dict[str, str]:
    env = {**os.environ, "PATH": f"{FOUNDRY}:{os.environ.get('PATH', '')}"}
    return env


def latest_block(rpc: str) -> int:
    out = subprocess.run(
        ["cast", "block-number", "--rpc-url", rpc],
        capture_output=True, text=True, timeout=120, env=_env(),
    )
    return int(out.stdout.strip())


def _rpc(chain: str) -> str | None:
    from core.cs_rpc import rpc_for

    return rpc_for(str(chain))


def verify_source(addr: str) -> str:
    """Report Sourcify verification status. Absence is not a verdict, only a fact."""
    try:
        cov = deploy_source.coverage([f"1:{addr}"], timeout=60)
        if cov.get("verified"):
            return "Sourcify-verified"
        if cov.get("unreachable"):
            return "Sourcify unreachable (unknown)"
        return "not Sourcify-verified"
    except Exception as exc:  # noqa: BLE001
        return f"verification check failed: {exc}"


def run_fork(vault: str, asset: str, block: int, rpc: str) -> str:
    env = _env()
    env["TARGET_VAULT"] = vault
    env["FORK_BLOCK"] = str(block)
    env["RPC_URL"] = rpc
    if asset:
        env["TARGET_ASSET"] = asset
    proc = subprocess.run(
        ["forge", "test", "--match-contract", "TargetVaultTest", "-vv"],
        cwd=HARNESS, capture_output=True, text=True, timeout=1800, env=env,
    )
    return proc.stdout + proc.stderr


def parse(out: str) -> dict[str, object]:
    ints: dict[str, int] = {}
    for _tag, field, value in _INT.findall(out):
        ints.setdefault(field.strip(), int(value))
    bools = {name: bool(int(v)) for _t, name, v in _BOOL.findall(out)}
    m = _BYTES.search(out)
    reason = ""
    if m and m.group(1) != "0x":
        hexs = m.group(1)[10:]
        try:
            reason = bytes.fromhex(hexs).decode(errors="replace").rstrip("\x00")
        except ValueError:
            reason = m.group(1)
    prereqs = {name: bool(int(v)) for name, v in _UINT.findall(out)}
    return {"ints": ints, "bools": bools, "reason": reason, "prereqs": prereqs}


def verdict(parsed: dict[str, object]) -> str:
    ints = parsed["ints"]
    bools = parsed["bools"]
    if "victim_shares" not in ints or "profit" not in ints:
        return "INCONCLUSIVE - probe did not complete"
    if bools.get("victim_deposit_reverted"):
        return "NOT VULNERABLE - vault reverts the victim's zero-share mint, so the attack cannot execute"
    if bools.get("withdrawal_reverted"):
        return "NOT VULNERABLE at this block - attacker's redemption was blocked by the vault"
    if ints["profit"] > 0:
        return f"PROFITABLE - attacker made {ints['profit']:,}; victim lost {ints.get('victim_loss', 0):,}"
    if ints.get("victim_shares", 0) == 0:
        return "NOT VULNERABLE - victim was minted zero shares"
    return (f"NOT PROFITABLE - attacker lost {-ints['profit']:,}; "
            f"victim lost {ints.get('victim_loss', 0):,}")


def check_asset(chain: str, addr: str, override: str) -> str:
    """Resolve the underlying, and say plainly when the vault declares none.

    A vault whose `asset()` returns the zero address is the wstETH/rebasing
    pattern: the real underlying is implied rather than stored. `deal()` on the
    zero address fails, so without this check the run just reports INCONCLUSIVE
    and looks like a tooling problem instead of a property of the target.
    """
    if override:
        return override
    url = _rpc(chain)
    if not url:
        return ""
    try:
        p = subprocess.run(
            ["cast", "call", addr, "asset()(address)", "--rpc-url", url],
            capture_output=True, text=True, timeout=90, env=_env(),
        )
    except Exception:  # noqa: BLE001
        return ""
    val = p.stdout.strip()
    # rc==0 with empty output still means unresolvable: a real asset() returns
    # 32 bytes, so silence is not a usable address
    if p.returncode != 0 or not val:
        return "__ZERO_ASSET__"
    if int(val, 16) == 0:
        return "__ZERO_ASSET__"
    return val


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--vault", required=True)
    ap.add_argument("--asset", default="")
    ap.add_argument("--chain", default="1")
    ap.add_argument("--block", type=int, default=0)
    ap.add_argument("--rpc", default=DEFAULT_RPC)
    args = ap.parse_args()

    asset = check_asset(args.chain, args.vault, args.asset)
    if asset == "__ZERO_ASSET__":
        print(f"target      : {args.vault}")
        print("asset       : asset() == address(0)")
        print()
        print("CANNOT BIND: this vault declares no underlying, the rebasing-implied")
        print("pattern used by wstETH and similar. Seed balances via the underlying")
        print("directly and pass --asset; the probe cannot resolve it from the vault.")
        return 3
    if not asset:
        print("WARNING: could not read asset(); falling back to vault.asset() in the fork")

    block = args.block or latest_block(args.rpc)
    print(f"target      : {args.vault}")
    print(f"asset       : {asset or '(from vault.asset())'}")
    print(f"fork block  : {block}")
    print(f"source      : {verify_source(args.vault)}")
    print("-" * 72)

    out = run_fork(args.vault, asset, block, args.rpc)
    parsed = parse(out)
    if not parsed["prereqs"]:
        print("prerequisite view calls did not report; see raw output below\n")
        print(out[-4000:])
        return 2

    ints = parsed["ints"]
    print(f"{'seed':>26}{'victim shares':>22}{'victim loss':>18}{'attacker pnl':>22}")
    print("-" * 72)
    # the sweep reuses one field name, so report the canonical case explicitly and
    # fall back to whatever was captured
    seed = ints.get("seed")
    if seed is not None:
        print(f"{seed:>26,}{ints.get('victim_shares', 0):>22,}"
              f"{ints.get('victim_loss', 0):>18,}{ints['profit']:>22,}")
    if parsed["reason"]:
        print(f"\nredemption revert reason : {parsed['reason']}")
    print(f"decimals_offset          : {ints.get('decimals_offset', 'n/a')}")
    print("-" * 72)
    print(verdict(parsed))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())