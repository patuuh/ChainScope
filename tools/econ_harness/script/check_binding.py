"""Prove `core/cs_econ.py` agrees with the EVM, then fail loudly if it stops doing so.

The Python models are exact only for the maths they are given. Nothing in them
establishes that those maths are the maths a real vault actually runs. This closes
that gap against ground truth we control: `NaiveVault` (known vulnerable) and
`OffsetVault` (known safe) in the same Foundry project, which execute the same
attack sequence the model prices.

Run `forge test -vv` first, or let this invoke it. Every field is compared, and a
mismatch is fatal - a model that has drifted from EVM execution will report a
confident wrong number for a real vault, which is the failure mode this whole
module exists to prevent.
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
HARNESS = HERE.parent
REPO = HARNESS.parent.parent          # ChainScope
sys.path.insert(0, str(REPO))

from core.cs_econ import (  # noqa: E402
    erc4626_naive,
    erc4626_virtual,
    donation_attack,
    rounding_drift,
    sandwich_profit_at_size,
)
from core.cs_econ import (  # noqa: E402
    _assets_naive as _assets_naive,
    _assets_virtual as _assets_virtual,
)

W = 10 ** 18

# label -> (shares model, assets model, seed, donation, victim_deposit)
CASES = {
    "naive_tiny":  (erc4626_naive, _assets_naive, 1, 100 * W, W),
    "naive_equal": (erc4626_naive, _assets_naive, W, 100 * W, W),
    "offset_tiny": (erc4626_virtual, _assets_virtual, 1, 100 * W, W),
}

FIELDS = ("victim_shares", "attacker_out", "profit", "victim_loss")

# the harness emits `profit`; the model's key is `attacker_profit`
MODEL_KEY = {
    "victim_shares": "victim_shares",
    "attacker_out": "attacker_out",
    "profit": "attacker_profit",
    "victim_loss": "victim_loss",
}

_LINE = re.compile(r"MODEL\s+(\S+)\s+(\S+)\s*:\s*(-?\d+)")


def run_forge() -> str:
    proc = subprocess.run(
        ["forge", "test", "-vv"],
        cwd=HARNESS, capture_output=True, text=True, timeout=900,
        env={**__import__("os").environ, "PATH": f"{Path.home()}/.foundry/bin:"
              + __import__("os").environ.get("PATH", "")},
    )
    if "Suite result: ok" not in proc.stdout:
        print(proc.stdout[-3000:], file=sys.stderr)
        raise SystemExit("forge tests did not pass; fix the harness before trusting the model")
    return proc.stdout


_DRIFT = re.compile(r"DRIFT\s+(\S+)\s+(\S+)\s*:\s*(-?\d+)")
_SAND = re.compile(r"SANDWICH\s+(\S+)\s+(\S+)\s*:\s*(-?\d+)")


def _check_rounding(out: str) -> list[str]:
    """rounding_drift vs a Solidity vault whose redemption floors to zero.

    Seeded at 1e22 assets / 1e24 supply rather than 1:1, because at assets ==
    supply every division is exact and both sides report zero drift for reasons
    that have nothing to do with the maths.
    """
    bad: list[str] = []
    rows = {(t, f): int(v) for t, f, v in _DRIFT.findall(out)}
    if ("asym", "total_assets") not in rows:
        return ["rounding: no DRIFT output captured from forge"]
    assets, recovered, paid = (rows[("asym", "total_assets")],
                               rows[("asym", "recovered")],
                               rows[("asym", "paid")])
    exp_assets = 10 ** 22 + paid

    d = rounding_drift(
        lambda a, s, x: x, lambda a, s, sh: 0,
        cycles=paid, amount=1, initial_assets=10 ** 22, initial_supply=10 ** 24,
    )
    checks = [
        ("total_assets", assets, exp_assets),
        ("recovered", recovered, d["recovered"]),
        ("attacker_net", recovered - paid, d["attacker_net"]),
        ("vault_gain", assets - 10 ** 22, d["vault_gain"]),
    ]
    for name, evm, model in checks:
        ok = evm == model
        print(f"{'rounding':<13}{name:<15}{evm:>22,}{model:>22,}  {'ok' if ok else 'MISMATCH'}")
        if not ok:
            bad.append(f"rounding.{name}: evm={evm} model={model}")
    return bad


def _check_sandwich(out: str) -> list[str]:
    """Sandwich accounting vs EVM at a FIXED attacker size.

    Not the optimiser's choice of size: the model searches continuous sizes in
    floating point and the chain executes one discrete trade, so comparing those
    proves nothing. This validates the accounting, including the flipped reserve
    order on the exit leg, which has been wrong twice.
    """
    bad: list[str] = []
    rows: dict[str, dict[str, int]] = {}
    for tag, field, val in _SAND.findall(out):
        rows.setdefault(tag, {})[field] = int(val)
    if "fee0" not in rows or "fee30" not in rows:
        return ["sandwich: no SANDWICH output captured from forge"]

    for tag, fee in (("fee0", 0), ("fee30", 30)):
        got = rows[tag]
        m = sandwich_profit_at_size(
            reserve_in=100 * W, reserve_out=100 * W,
            victim_amount_in=10 * W, attacker_in=5 * W, fee_bps=fee,
        )
        # forge labels the exit leg "proceeds"; the model calls it attacker_proceeds
        for field, key in (("victim_out", "victim_out"),
                           ("proceeds", "attacker_proceeds"),
                           ("profit", "attacker_profit"),
                           ("victim_at_spot", "victim_out_at_spot")):
            if field not in got:
                bad.append(f"sandwich[{tag}].{field}: missing from forge output")
                continue
            ok = got[field] == m[key]
            print(f"{'sandwich_' + tag:<13}{field:<15}{got[field]:>22,}{m[key]:>22,}  "
                  f"{'ok' if ok else 'MISMATCH'}")
            if not ok:
                bad.append(f"sandwich[{tag}].{field}: evm={got[field]} model={m[key]}")
    return bad


def main() -> int:
    observed = {label: {} for label in CASES}
    out = run_forge()
    for label, field, value in _LINE.findall(out):
        if label in observed and field in FIELDS:
            observed[label][field] = int(value)

    failures: list[str] = []
    print(f"{'case':<14}{'field':<16}{'evm':>24}{'model':>24}  result")
    print("-" * 80)

    for label, (model, red_model, seed, donation, victim) in CASES.items():
        got = observed.get(label, {})
        if not got:
            failures.append(f"{label}: no EVM numbers captured from forge output")
            continue
        predicted = donation_attack(model, convert_to_assets=red_model, attacker_deposit=seed,
                                    donation=donation, victim_deposit=victim)
        for field in FIELDS:
            model_value = predicted[MODEL_KEY[field]]
            evm_value = got.get(field)
            if evm_value is None:
                failures.append(f"{label}.{field}: missing from forge output")
                continue
            ok = evm_value == model_value
            print(f"{label:<13}{field:<15}{evm_value:>22,}{model_value:>22,}  {'ok' if ok else 'MISMATCH'}")
            if not ok:
                failures.append(f"{label}.{field}: evm={evm_value} model={model_value}")

    failures.extend(_check_rounding(out))
    failures.extend(_check_sandwich(out))
    print()
    if failures:
        print(f"{len(failures)} mismatch(es) between core/cs_econ.py and EVM execution:")
        for f in failures:
            print(f"  - {f}")
        return 1
    print("core/cs_econ.py matches EVM execution on every field of every case.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())