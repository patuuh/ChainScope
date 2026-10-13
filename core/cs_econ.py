"""Economic invariant checks for share-based vaults and AMM swaps.

`cs_veck` matches the *shape* of vulnerable code: a regex for `skim(`, a regex
for `totalSupply == 0`. That is the right tool for access control and the wrong
one here, because economic bugs live in the arithmetic, not the text. A vault can
contain every one of those strings and be perfectly safe, or omit all of them and
drain. The question is never "does this code look wrong" but "given these
numbers, does the attack make money".

So these functions are numerical models, not detectors. They take the vault's
share maths as an explicit callable and report numbers - attacker profit, victim
loss, per-cycle drift, sandwich margin - with the attacker paying real
consideration (deposit + donation, borrow, gas if given).

**Scope and honesty about scope.** These models are exact only for the maths they
are given. They do not read Solidity, and they do not prove anything about a
contract until you bind them to it: either by passing the vault's own conversion
functions, or with the Foundry harness in `tools/econ_harness/`, which runs the
same invariants against the deployed ABI. A model fed the wrong maths will
happily report a confidently wrong number, so every result is labelled with the
assumption it rests on.

The discrimination test is the point: `donation_attack` must report profit for a
vault with an empty-vault branch and no profit for one with virtual shares. If it
cannot tell those apart it is decoration, not a check.

**Scope: these models describe an EMPTY vault.** `donation_attack` starts from the
attacker's seed as the only supply, which is the regime where inflation bites.
`tools/econ_harness` exists because that assumption is itself worth testing, and
running it against a live vault showed what it hides: Sky's sDAI holds ~164k DAI
across 1.39M shares, so at a 1-wei seed the attacker still receives 846,617,106
shares against a 1-wei loss and the attack is worth about -100 DAI. Viability
turns on the attacker being able to hold a dominant fraction of total supply, not
on their absolute deposit. For a seeded vault, read the fork numbers - they are
the answer - and treat any model prediction as a bound.
"""
from __future__ import annotations

import typing as t

# --------------------------------------------------------------------------- #
# share maths models
# --------------------------------------------------------------------------- #

Number = int | float


def erc4626_naive(total_assets: int, total_supply: int, assets: int) -> int:
    """Share maths with an empty-vault branch and no virtual offset.

    The textbook shape: a fresh vault mints 1:1, so the first depositor's shares
    are the denominator for everyone after them, and a donation to the vault
    (which raises `total_assets` without raising `total_supply`) inflates the
    share price immediately.
    """
    if total_supply == 0:
        return assets
    return assets * total_supply // total_assets


def erc4626_virtual(total_assets: int, total_supply: int, assets: int,
                    offset: int = 3) -> int:
    """Share maths with `decimalsOffset` virtual shares/liquidity.

    The offset seeds `total_supply` and `total_assets` with a dead amount, so the
    denominator cannot be small enough for a donation to move the share price
    materially.
    """
    if total_assets + (10 ** offset) == 0:
        return assets
    return assets * (total_supply + 10 ** offset) // (total_assets + 10 ** offset)


def erc4626_dead_shares(total_assets: int, total_supply: int, assets: int,
                        dead: int = 1000) -> int:
    """Share maths protected by pre-minting dead shares to a burn address."""
    return assets * (total_supply + dead) // (total_assets + dead)


SHARE_MODELS: dict[str, t.Callable[[int, int, int], int]] = {
    "naive": erc4626_naive,
    "virtual_offset": erc4626_virtual,
    "dead_shares": erc4626_dead_shares,
}


def _assets_naive(total_assets: int, total_supply: int, shares: int) -> int:
    if total_supply == 0:
        return shares
    return shares * total_assets // total_supply


def _assets_virtual(total_assets: int, total_supply: int, shares: int, offset: int = 3) -> int:
    denom = total_supply + 10 ** offset
    if denom == 0:
        return shares
    return shares * (total_assets + 10 ** offset) // denom


def _assets_dead(total_assets: int, total_supply: int, shares: int, dead: int = 1000) -> int:
    denom = total_supply + dead
    if denom == 0:
        return shares
    return shares * (total_assets + dead) // denom


# The matching redemption maths. These are written out rather than derived by
# swapping arguments into the share models: the inverse of a rounded division is
# not the same function with its arguments exchanged, and silently assuming so
# reports zero drift for every vault, including ones that lose money.
ASSET_MODELS: dict[str, t.Callable[[int, int, int], int]] = {
    "naive": _assets_naive,
    "virtual_offset": _assets_virtual,
    "dead_shares": _assets_dead,
}


# --------------------------------------------------------------------------- #
# check 1: donation / first-depositor inflation
# --------------------------------------------------------------------------- #


def donation_attack(
    convert_to_shares: t.Callable[[int, int, int], int],
    *,
    convert_to_assets: t.Callable[[int, int, int], int] | None = None,
    attacker_deposit: int = 10 ** 18,
    donation: int = 100 * 10 ** 18,
    victim_deposit: int = 10 ** 18,
    victim_deposit_reverts: bool = True,
) -> dict[str, t.Any]:
    """Model the canonical first-depositor inflation attack and price it out.

    Sequence, all of it permissionless:
      1. attacker seeds the vault
      2. attacker donates directly to the vault, raising assets but not supply
      3. victim deposits and receives shares priced against the inflated ratio
      4. attacker redeems everything

    `victim_deposit_reverts` decides what happens when the victim's deposit would
    mint zero shares, and it decides whether the attack works at all. Most
    ERC4626 implementations (OpenZeppelin included) revert on a zero-share mint,
    and on those vaults the victim simply cannot deposit: nothing enters the
    pool and the attacker extracts nothing. A vault that accepts a zero-share
    mint hands the whole deposit to the existing holder instead. Reporting the
    vulnerable branch unconditionally - which an earlier version did - turns a
    non-issue into a Critical, so the regime is an explicit input and appears in
    the result.
    """
    to_shares = convert_to_shares
    # Redemption must go through the vault's OWN maths. Assuming the plain
    # `shares * assets / supply` ratio is only correct for a vault with no virtual
    # or dead shares; against an offset vault it misprices the redemption by
    # orders of magnitude and can even report a negative victim loss, which is
    # impossible. Pass the matching convertToAssets.
    if convert_to_assets is None:
        def convert_to_assets(ta: int, ts: int, shares: int) -> int:  # noqa: ANN202
            return shares if ts == 0 else shares * ta // ts

    # 1. seed, priced against a genuinely empty vault. Using total_assets =
    #    attacker_deposit here mis-mints the seed for any model with virtual
    #    shares, because the real mint reads the vault before it is credited.
    total_assets = 0
    total_supply = to_shares(0, 0, attacker_deposit)
    if total_supply == 0:
        return {
            "viable": False,
            "reason": "seed deposit mints zero shares",
            "attacker_profit": 0,
            "victim_loss": 0,
            "victim_shares": 0,
            "assumptions": [],
        }
    attacker_shares = total_supply
    total_assets += attacker_deposit

    # 2. donation: assets rise, supply does not
    total_assets += donation

    # 3. victim deposit
    victim_shares = to_shares(total_assets, total_supply, victim_deposit)
    reverted = victim_shares == 0 and victim_deposit_reverts
    if not reverted:
        total_assets += victim_deposit
        total_supply += victim_shares

    # 4. attacker redeems everything
    attacker_out = convert_to_assets(total_assets, total_supply, attacker_shares)

    attacker_profit = attacker_out - attacker_deposit - donation
    # assets are conserved: what the attacker extracts beyond their own
    # contribution is exactly what the victim fails to receive
    victim_value_out = convert_to_assets(total_assets, total_supply, victim_shares)
    victim_loss = victim_deposit - victim_value_out

    return {
        "viable": attacker_profit > 0,
        "attacker_profit": attacker_profit,
        "victim_loss": victim_loss,
        "victim_shares": victim_shares,
        "attacker_out": attacker_out,
        "victim_deposit_reverted": reverted,
        "share_price_before_donation": _share_price(attacker_deposit, attacker_shares),
        "share_price_after_donation": _share_price(total_assets, total_supply),
        "assumptions": [
            "donation is a plain transfer to the vault, no hooks",
            "attacker pays attacker_deposit + donation and can redeem in full",
            "victim deposit is not protected by a minimum-shares check",
            "vault reverts a zero-share mint" if victim_deposit_reverts
            else "vault accepts a zero-share mint",
        ],
    }


def _share_price(total_assets: int, total_supply: int) -> float:
    if total_supply == 0:
        return float("inf")
    return total_assets / total_supply


def scan_donation_sensitivity(
    convert_to_shares: t.Callable[[int, int, int], int],
    *,
    convert_to_assets: t.Callable[[int, int, int], int] | None = None,
    # Seeds must span orders of magnitude down to 1 wei. The inflation attack is
    # most severe when the attacker's seed is negligible next to the victim
    # deposit: at a seed of 1 wei the victim is minted ZERO shares and loses the
    # entire deposit, while at a seed equal to the victim deposit the attacker
    # already owns the vault and extracts nothing. A sweep that starts at
    # 1e15 therefore reports a rounding-error profit of ~99 wei and misses the
    # total-loss case entirely - which is exactly what the first version of this
    # default did.
    deposits: tuple[int, ...] = (1, 10, 10 ** 3, 10 ** 6, 10 ** 9, 10 ** 12, 10 ** 15, 10 ** 18),
    donations: tuple[int, ...] = (10 ** 17, 10 ** 18, 10 ** 19, 10 ** 20),
    victim_deposit: int = 10 ** 18,
    victim_deposit_reverts: bool = True,
) -> list[dict[str, t.Any]]:
    """Sweep seed/donation sizes; report the combination that extracts the most.

    Inflation attacks need the donation large relative to the seed and the victim
    deposit, so a single (deposit, donation) pair is not evidence either way.
    """
    rows: list[dict[str, t.Any]] = []
    for dep in deposits:
        for don in donations:
            r = donation_attack(
                convert_to_shares,
                convert_to_assets=convert_to_assets,
                attacker_deposit=dep,
                donation=don,
                victim_deposit=victim_deposit,
                victim_deposit_reverts=victim_deposit_reverts,
            )
            r["attacker_deposit"] = dep
            r["donation"] = don
            rows.append(r)
    rows.sort(key=lambda r: r["attacker_profit"], reverse=True)
    return rows


# --------------------------------------------------------------------------- #
# check 2: rounding drift across repeated cycles
# --------------------------------------------------------------------------- #


def rounding_drift(
    convert_to_shares: t.Callable[[int, int, int], int],
    convert_to_assets: t.Callable[[int, int, int], int],
    *,
    cycles: int = 1000,
    amount: int = 1,
    initial_assets: int = 10 ** 24,
    initial_supply: int | None = None,
) -> dict[str, t.Any]:
    """Repeatedly deposit then fully redeem, and total the value lost.

    Catches the classic rounding asymmetry: when `convertToShares` and
    `convertToAssets` round in the same direction against the pool, every
    full cycle converts a little of the attacker's deposit into dust and the
    remainder accrues to existing holders.

    The starting pool matters and is easy to get wrong. With `initial_assets ==
    initial_supply` every division is exact and the drift is identically zero for
    every vault, including ones that do lose money - so a default that hides this
    would report zero everywhere and look like a clean result. Set
    `initial_supply` to a different value (a real share price) to make the
    rounding observable.
    """
    total_assets = int(initial_assets)
    total_supply = int(initial_supply if initial_supply is not None else initial_assets)
    start_assets = total_assets
    recovered = 0

    for _ in range(int(cycles)):
        minted = convert_to_shares(total_assets, total_supply, amount)
        if minted == 0:
            # the deposit cannot buy a whole share - a distinct and separately
            # reportable failure mode
            return {
                "attacker_net": 0,
                "vault_gain": 0,
                "cycles_completed": 0,
                "zero_share_deposit": True,
                "total_assets": total_assets,
                "total_supply": total_supply,
                "rounding_exploit": False,
                "conservation_holds": True,
                "note": "deposit mints zero shares; caller is exposed to a direct loss",
            }
        total_assets += amount
        total_supply += minted
        redeemed = convert_to_assets(total_assets, total_supply, minted)
        total_assets -= redeemed
        total_supply -= minted
        recovered += redeemed

    # Conservation: whatever the attacker fails to recover is exactly what the
    # pool keeps. Reporting only the pool's asset total hides which side moved,
    # because a vault absorbing the attacker's rounding loss ends the run with
    # MORE assets than it started with.
    attacker_net = recovered - int(cycles) * amount
    vault_gain = total_assets - start_assets
    return {
        "attacker_net": attacker_net,
        "vault_gain": vault_gain,
        "recovered": recovered,
        "paid": int(cycles) * amount,
        "cycles_completed": int(cycles),
        "zero_share_deposit": False,
        "total_assets": total_assets,
        "total_supply": total_supply,
        "rounding_exploit": attacker_net < 0,
        "conservation_holds": attacker_net + vault_gain == 0,
        "note": "attacker_net < 0 means the pool absorbed the loss across cycles",
    }


# --------------------------------------------------------------------------- #
# check 3: sandwich / MEV margin
# --------------------------------------------------------------------------- #


def sandwich_profit_constant_product(
    *,
    reserve_in: float,
    reserve_out: float,
    victim_amount_in: float,
    min_out_ratio: float = 0.0,
    attacker_gas: float = 0.0,
    fee_bps: float = 0.0,
    max_attacker_in: float | None = None,
) -> dict[str, t.Any]:
    """Optimal two-sided sandwich on a constant-product pool, priced out.

    The attacker buys before the victim and sells after. Profit as a function of
    the attacker's size is smooth and unimodal, so it is optimised numerically
    rather than solved for a closed form - the slippage constraint is what makes
    the closed form fiddly, and a wrong closed form reports a confident wrong
    number.

    **Read `attacker_profit` together with `attacker_buy_size`.** Extraction grows
    with the attacker's own capital: committing more lets them move the price
    further and capture more of the victim's fill. A commit as large as the
    victim's trade can approach extracting the whole fill, which is arithmetically
    correct but usually not executable. `max_attacker_in` bounds the search to a
    plausible budget; the default (one full reserve) will find a theoretical
    maximum that no real attacker could fund.

    The victim's `min_out_ratio` is their slippage floor as a fraction of the
    no-arb quote. If a candidate size pushes the victim below their floor the
    victim's transaction reverts, so that size is infeasible rather than
    profitable: if no feasible size exists the attack cannot be executed at all.
    """
    if min_out_ratio < 0 or min_out_ratio > 1:
        raise ValueError("min_out_ratio must be in [0, 1]")

    def amm_out(x_in: float, r_in: float, r_out: float) -> float:
        if x_in <= 0:
            return 0.0
        x_in_after_fee = x_in * (1.0 - fee_bps / 10_000.0)
        return (x_in_after_fee * r_out) / (r_in + x_in_after_fee)

    spot_quote = amm_out(victim_amount_in, reserve_in, reserve_out)
    floor = spot_quote * min_out_ratio

    def evaluate(attacker_in: float) -> tuple[float, float, float]:
        """Return (profit, victim_out, attacker_out_after_sandwich) for a size."""
        if attacker_in <= 0:
            return -float("inf"), spot_quote, 0.0
        # attacker front-runs
        got = amm_out(attacker_in, reserve_in, reserve_out)
        r_in_1 = reserve_in + attacker_in * (1.0 - fee_bps / 10_000.0)
        r_out_1 = reserve_out - got
        # victim swaps
        victim_out = amm_out(victim_amount_in, r_in_1, r_out_1)
        if victim_out < floor:
            return -float("inf"), victim_out, 0.0
        r_in_2 = r_in_1 + victim_amount_in * (1.0 - fee_bps / 10_000.0)
        r_out_2 = r_out_1 - victim_out
        # attacker unwinds, paying fees on the exit too. The attacker is selling
        # token B (what it received) back for token A, so the reserve order flips:
        # its holding is the INPUT against the pool's out-side reserve.
        proceeds = amm_out(got, r_out_2, r_in_2)
        return proceeds - attacker_in - attacker_gas, victim_out, proceeds

    # golden-section search over the unimodal profit curve, bounded by the
    # attacker's capital budget
    budget = float(max_attacker_in) if max_attacker_in else reserve_in
    lo, hi = 1e-12, max(budget, 1e-11)
    phi = (5 ** 0.5 - 1) / 2
    a, b = hi - phi * (hi - lo), lo + phi * (hi - lo)
    fa, fb = evaluate(a)[0], evaluate(b)[0]
    for _ in range(400):
        if fa > fb:
            hi, b, fb = b, a, fa
            a = hi - phi * (hi - lo)
            fa = evaluate(a)[0]
        else:
            lo, a, fa = a, b, fb
            b = lo + phi * (hi - lo)
            fb = evaluate(b)[0]
        if hi - lo < max(1e-12, hi * 1e-12):
            break

    best_x = (lo + hi) / 2
    best_profit, victim_out, proceeds = evaluate(best_x)
    spot_now = evaluate(0.0)[1]

    if best_profit == -float("inf"):
        return {
            "profitable": False,
            "attacker_profit": 0.0,
            "victim_out": spot_now,
            "victim_floor": floor,
            "victim_tx_reverts": True,
            "reason": "no attacker size satisfies the victim's floor; the attack cannot be executed",
            "assumptions": [
                "constant-product pool",
                "attacker can fund any size and pay attacker_gas",
                "victim is a single swap sized as given",
                "min_out_ratio is the victim's floor as a fraction of the spot quote",
            ],
        }

    extracted_from_victim = spot_now - victim_out
    # Not all of the attacker's profit comes out of the victim. Committing enough
    # capital to move the price also degrades the exit, so the residual is taken
    # from existing LPs. Reporting only victim_loss understates a sandwich's
    # total social cost, and the LP share is the larger one at large sizes.
    lp_implicit_cost = best_profit - extracted_from_victim

    return {
        "profitable": best_profit > 0,
        "attacker_profit": best_profit,
        "attacker_buy_size": best_x,
        "attacker_proceeds": proceeds,
        "victim_out": victim_out,
        "victim_loss_vs_spot": extracted_from_victim,
        "victim_floor": floor,
        "spot_quote": spot_now,
        "value_extracted_from_victim": extracted_from_victim,
        "value_extracted_from_lps": lp_implicit_cost,
        "victim_tx_reverts": False,
        "assumptions": [
            "constant-product pool",
            "attacker can fund any size and pay attacker_gas",
            "victim is a single swap sized as given",
            "min_out_ratio is the victim's floor as a fraction of the spot quote",
        ],
    }


def amm_out_exact(x_in: int, r_in: int, r_out: int, fee_bps: int = 0) -> int:
    """Exact integer constant-product quote, matching the Foundry `CPMM` fixture.

    The floating-point `amm_out` inside the optimiser cannot be compared against
    EVM execution: the model searches continuous sizes and the chain executes one
    discrete integer trade. Binding therefore prices a FIXED size in integer
    arithmetic, so what is validated is the accounting rather than the search.
    """
    if x_in <= 0:
        return 0
    xi = x_in * (10_000 - fee_bps) // 10_000
    denom = r_in + xi
    if denom == 0:
        return 0
    return xi * r_out // denom


def sandwich_profit_at_size(
    *,
    reserve_in: int,
    reserve_out: int,
    victim_amount_in: int,
    attacker_in: int,
    fee_bps: int = 0,
    attacker_gas: int = 0,
    min_out_ratio: float = 0.0,
) -> dict[str, t.Any]:
    """Price one specific sandwich size in exact integers.

    Mirrors `sandwich_profit_constant_product`'s accounting (including the flipped
    reserve order on the exit leg) but at a caller-chosen size, so a model
    prediction and a fork execution are comparable field for field.
    """
    spot = amm_out_exact(victim_amount_in, reserve_in, reserve_out, fee_bps)
    floor = int(spot * min_out_ratio)

    attacker_got = amm_out_exact(attacker_in, reserve_in, reserve_out, fee_bps)
    r_in_1 = reserve_in + attacker_in
    r_out_1 = reserve_out - attacker_got
    victim_out = amm_out_exact(victim_amount_in, r_in_1, r_out_1, fee_bps)

    feasible = victim_out >= floor or victim_out == 0 and floor == 0

    r_in_2 = r_in_1 + victim_amount_in
    r_out_2 = r_out_1 - victim_out
    # exit leg: the attacker sells the OUTPUT token, so its holding is the input
    # against the pool's out-side reserve
    denom = r_out_2 + attacker_got
    proceeds = 0 if denom == 0 else attacker_got * r_in_2 // denom
    profit = proceeds - attacker_in - attacker_gas

    return {
        "attacker_in": attacker_in,
        "attacker_got": attacker_got,
        "attacker_proceeds": proceeds,
        "attacker_profit": profit,
        "victim_out": victim_out,
        "victim_out_at_spot": spot,
        "victim_floor": floor,
        "feasible": feasible,
        "value_extracted_from_victim": spot - victim_out,
    }


def sandwich_sensitivity(
    *,
    reserve_in: float,
    reserve_out: float,
    victim_amount_in: float,
    bounds: tuple[float, ...] = (0.0, 0.005, 0.01, 0.05),
) -> list[dict[str, t.Any]]:
    """Price the sandwich across a range of victim slippage bounds.

    The useful output is the shape: extraction should collapse once the bound
    bites. A pool that stays profitable at a tight bound is a different bug from
    one that is only profitable when unbounded.
    """
    rows = []
    for b in bounds:
        r = sandwich_profit_constant_product(
            reserve_in=reserve_in,
            reserve_out=reserve_out,
            victim_amount_in=victim_amount_in,
            min_out_ratio=b,
        )
        r["min_out_ratio"] = b
        rows.append(r)
    return rows
