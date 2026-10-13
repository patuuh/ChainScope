# GMX coverage map, and the GLV share-math campaign

Answers "which swaps/pools/farms/flashloans have not been tested?" with a measured
map rather than an impression.

## Coverage before this campaign

| area | first-party files | executed by me? |
|---|---|---|
| **flash loans** | **0** | **N/A — GMX has no flash-loan surface at all** |
| swap (amount application) | 5 | no — prior fuzz covered *pricing*, not application |
| farm / GLV vault share math | 15 | **no — largest gap, now tested** |
| rewards / fee distribution | 7 | no |
| liquidation | 8 | no |
| position impact pool | — | yes, 25k runs |

## CORRECTION — this campaign covered ~0.6% of GLV, not "GLV tested"

An earlier version of this file described GLV as "the largest gap, now done". That
**overstated it**. Measured:

| | |
|---|---|
| total first-party GLV surface | **3,586 lines / 24 files** |
| exercised here | **~20 lines** (`GlvUtils.usdToGlvTokenAmount`) |
| coverage | **~0.6%** |

The campaign tested one pure division function. It answers exactly one question — can a
depositor over-mint at the share-price conversion? — and answers it soundly. It says
nothing about the rest of GLV.

Not tested, and ordered by where a bug would hurt most:

1. **`GlvUtils.getGlvValue`** — the valuation function computing `glvValue` from
   market-token balance and pool value. This is the higher-risk function and it was
   skipped in favour of the division beneath it.
2. **`GlvWithdrawalUtils` (389)** and `GlvWithdrawalStoreUtils` (311) — the **exit**
   path. Deposit rounding at least favours the vault; *withdraw* rounding can favour
   the withdrawer, which is the direction that steals.
3. `GlvShiftUtils` (285), `ExecuteGlvDepositUtils` (244), `GlvDepositUtils` (293).

Read-only, so the supply-capture ordering above is established — but that is the one
GLV question answered without execution, not a clean bill of health.

## What did hold

The flash-loan row is the useful negative: `grep -rl "flashLoan|flashMinter|onFlashLoan"`
over `contracts/` returns **zero files**, so that entire class cannot apply to GMX.
GMX perps are cross-margin without flash liquidity, so this removes a category rather
than adding one.

## What reading established before testing

`ExecuteGlvDepositUtils.executeGlvDeposit` caches both inputs to the share-price
conversion, and the ordering is what matters:

```solidity
cache.glvSupply = GlvToken(payable(glvDeposit.glv())).totalSupply();   // :72  read BEFORE mint
cache.mintAmount = GlvDepositCalc.getMintAmount(..., cache.glvValue, cache.glvSupply);
if (cache.mintAmount < glvDeposit.minGlvTokens()) revert ...          // :81  user min
GlvToken(payable(glvDeposit.glv())).mint(glvDeposit.receiver(), cache.mintAmount);  // :86  mint
...
cache.glvSupply = GlvToken(payable(glvDeposit.glv())).totalSupply(); // :125 re-read
GlvEventUtils.emitGlvValueUpdated(...);                               // :126 event ONLY
```

The supply used for minting is captured **before** the mint, so a depositor cannot
inflate their own rate, and the post-mint re-read feeds only the event log. That
closes the stale-supply question by reading — these tests pin the arithmetic it rests
on rather than re-deriving it.

## Result — 6 tests, 25,000 runs, clean

| Test | Property |
|---|---|
| `testFuzz_seed_noSupplyNoValue_isOneToOne` | supply==0 && value==0 ⇒ `floatToWei(usd)` |
| `testFuzz_seed_zeroSupplyWithValue_includesBacking` | supply==0 && value>0 ⇒ backing is included |
| `testFuzz_main_roundsDown` | `got*val <= supply*usd` — rounding favours the vault |
| `testFuzz_seed_neverMintsMoreThanDepositedPlusBacking` | single-division carry bounded by 1 wei |
| `testFuzz_tinyDeposit_cannotClaimMoreThanDeposited` | first-depositor probe: cannot claim more than deposited |
| `test_zeroValueWithNonZeroSupply_reverts` | degenerate-state behaviour, pinned |

## One observation, recorded not claimed

`usdToGlvTokenAmount` has two seed branches, both gated on `glvSupply == 0`. With
`glvSupply > 0 && glvValue == 0` control reaches
`Precision.mulDiv(glvSupply, usdValue, glvValue)` and **reverts on division by zero**.

That is a revert, not a loss: it means deposits into a GLV vault whose tracked value
has gone to zero fail rather than minting nonsense. Whether it is reachable is not
established — it needs the vault emptied first — and GMX's own notes list
"reserve-check decrease flows" among the June-2026 2.2c findings, so related ground
is likely already covered. **Not filed as a finding.**

## Three failures that were bugs in my test

Worth recording, since each would have been publishable had I not traced it.

1. **`floatToWei` rounds down** (`value / DIVISOR`), so `floatToWei(val+usd)` — one
   division — is `sum` or `sum+1` of `floatToWei(val) + floatToWei(usd)` — two
   divisions. My `assertLe(got, sum)` was backwards; the fuzzer failed on the first
   input and was right.
2. **Double-scaling.** I compared against a `floatToWei`-scaled ideal while the
   contract calls `mulDiv` on raw values. False failure.
3. **`glvValue == 0` with supply > 0** surfaced as a division-by-zero panic that was
   neither of my bugs nor a finding — it is the contract's behaviour, now pinned by
   an explicit `vm.expectRevert` test.

All three were the fuzzer testing my reasoning rather than the protocol. In every
case the protocol was correct.


---

## Addendum — GLV exit path (`GlvWithdrawalUtils`)

The exit path is the one where rounding runs in the direction that can steal:
deposit rounding favours the vault, so bugs there are self-harming; withdraw
rounding does not.

**5 tests, 20,000 runs, all green.**

| Test | Property |
|---|---|
| `testFuzz_roundTrip_neverProfits` | deposit d → withdraw returns USD ≤ d at a constant ratio |
| `testFuzz_repeatedRoundTrips_doNotAccumulate` | up to 8 consecutive cycles never extract more than one deposit each |
| `testFuzz_exitRoundsDown` | `usd*supply <= value*amount` — exit never rounds up |
| `testFuzz_fullSupplyWithdrawal_neverExceedsVault` | withdrawing the entire supply cannot exceed the vault's value |
| `test_zeroSupplyWithdrawal_reverts` | `EmptyGlvTokenSupply` pinned |

What reading established, and the tests now pin: the exit is two conversions, both
via `Precision.mulDiv` → OZ `Math.mulDiv`, which rounds **down**, and
`_getMarketTokenAmount` calls `getGlvValue(..., maximize = false)` where the deposit
path passes `true`. That asymmetry is deliberate and against the withdrawer.

**Coverage, stated honestly — again.** Executed: `usdToGlvTokenAmount` (19 lines) and
`glvTokenAmountToUsd` (12 lines). **Not** executed: `_getMarketTokenAmount` itself
(32 lines), which composes those two with oracle prices, market pool value and market
token supply, and cannot run without a market, an oracle and a GLV vault deployed.

So the arithmetic composing the exit is now pinned at 20,000 runs. The wiring above it
is still read-only, and the `maximize` asymmetry is a reading, not a result.

### Cumulative GMX

| area | runs | status |
|---|---|---|
| position impact pool distribution | 25,000 | executed, clean |
| GLV share-price conversion | 25,000 | executed, clean |
| GLV exit round-trip | 20,000 | executed, clean |
| `_getMarketTokenAmount` wiring | 0 | read only |
| swap amount application | 0 | untested |
| fee distribution | 0 | untested |
| liquidation | 0 | untested |

70,000 runs across three isolated arithmetic layers, and **no CRIT/HIGH/MEDIUM**. Every
layer that needed an oracle, a market, a vault or a router remains unexecuted — which is
also why the honest verdict is "the pure math is sound", not "GLV is sound".

---

## Addendum 2 — the valuation input to `_getMarketTokenAmount`

Reached the layer the arithmetic campaigns could not, via the **shallow short-circuit**
in `GlvUtils.getGlvValue`: when the GLV itself carries an oracle price, it returns
`(maximize ? max : min) * totalSupply()` without touching a market. That short-circuit is
exactly what `GlvWithdrawalUtils._getMarketTokenAmount` consumes, and it is the only
part of the valuation path reachable without deploying a market, an oracle and a vault.

**5 tests, 20,000 runs, all green.**

| Test | Property |
|---|---|
| `testFuzz_exitUsesMin_andDepositUsesMax` | exit values at `min`, deposit at `max` |
| `testFuzz_exitValuation_neverExceedsDepositValuation` | **the round-trip guard**: exit ≤ deposit |
| `testFuzz_swapOfBounds_wouldBreakTheGuard` | with inverted bounds the exit *is* the richer side — pins the dependency |
| `testFuzz_valuationScalesLinearlyWithSupply` | valuation == price × supply |
| `testFuzz_valuationMonotonicInSupply` | monotone in supply |

**The design is sound, and the asymmetry is real:** the withdrawal path calls
`getGlvValue(..., maximize = false)` and the deposit path `true`, so the exit is always
valued at the *lower* of the oracle's two prices. An oracle spread therefore moves
against the withdrawer, which is the conservative direction.

### The oracle dependency, stated precisely

`IOracle.primaryPrices(address) returns (uint256 min, uint256 max)` — the interface
declares the ordering explicitly and `Price.Props { uint256 min; uint256 max; }` matches.
So the guard holds **iff the oracle honours its own interface.**

`testFuzz_swapOfBounds_wouldBreakTheGuard` pins that: given inverted bounds the exit
becomes the richer side. That is not a protocol bug — it is a correct function consuming
malformed data — but it does mean the GLV exit's safety is **conditional on the oracle
reporting `min <= max`**, which is worth knowing and is not asserted anywhere in the
contract.

### Third instance of the same test bug

The V2 run failed initially with "exit valued ABOVE the deposit". Cause: I bounded the
`min_` and `max_` fuzz arguments **independently**, so the fuzzer supplied
`min_ = 3.438e29 > max_ = 9.953e23` — a malformed oracle. The contract then correctly
took the larger of the pair.

Third time this session (after the impact-pool monotonicity bound and the GLV
`floatToWei` double-scale). **Fuzzers punish independently-bounded related inputs**,
and the failure always looks like a protocol finding until you read it.

### Coverage after three campaigns

| area | runs | executed |
|---|---|---|
| position impact pool distribution | 25,000 | yes |
| GLV share-price conversion | 25,000 | yes |
| GLV exit round-trip | 20,000 | yes |
| GLV valuation input (`getGlvValue` short-circuit) | 20,000 | yes |
| `_getMarketTokenAmount` market loop | 0 | **still read-only** |
| swap amount application / fees / liquidation | 0 | untested |

**90,000 runs. No CRIT/HIGH/MEDIUM.** The `getGlvValue` short-circuit is now executed,
so the earlier caveat that `maximize` was "a reading, not a result" is resolved for that
branch. What remains unexecuted is the per-market loop beneath it, which needs a market,
a pool value and market token balances deployed.

---

## Addendum 3 — the market loop, executed

The first three campaigns tested arithmetic in isolation. This one deploys the real
pieces and drives `_getMarketTokenAmount` end to end: `RoleStore`, `DataStore`, a market
that is also its own market token, the real `GlvToken` (a `StrictBank`), and pool amounts
seeded through DataStore exactly as `MarketUtils.getPoolAmount` reads them
(`Keys.poolAmountKey`). No Uniswap pool, because `getPoolValueInfo` reads virtual
reserves from DataStore rather than calling the pool.

The GLV is deliberately left **unpriced** (`primaryPrices` returns `(0,0)`), so
`getGlvValue` cannot short-circuit and the per-market loop actually executes — that loop
was the entire point.

**5 tests, 20,000 runs, all green.**

| Test | Property |
|---|---|
| `testFuzz_amountIsProportionalToGlvBalance` | linear in the GLV amount, monotonic, bounded |
| `testFuzz_exitValuation_neverExceedsDepositValuation` | **the guard, now at market level**, with the oracle spread varied to 100% |
| `testFuzz_neverExceedsGlvMarketTokenBalance` | exit ≤ the GLV's whole balance |
| `test_zeroGlvBalance_returnsZero` | zero balance contributes zero |
| `test_zeroPoolValue_reverts_ratherThanWrapping` | degenerate state reverts, never wraps |

### Observation recorded, not claimed

A **zero** pool value does not produce `Errors.GlvNegativeMarketPoolValue` — that guard
is `poolValue < 0`, and zero is not negative. Control instead falls through to
`usdToMarketTokenAmount(0, 0, supply)`, which skips both seed branches (they require
`supply == 0` or `poolValue > 0`) and reverts with **panic 0x12, division by zero**.

So the exit reverts rather than wrapping, which is safe. But it burns the full gas
allowance instead of failing with a clean custom error, and it is reachable whenever a
GLV's underlying market has already been emptied to zero. That is a gas/error-hygiene
observation on a degenerate path, not a fund-loss path, and it needs an emptied market to
reach. **Not filed.**

### Harness notes for reuse

- `GlvToken` is `onlyController` for `mint`, so the test contract needs
  `Role.CONTROLLER` before seeding.
- `glvTokenAmountToUsd` reverts `EmptyGlvTokenSupply` at zero GLV supply — so a
  "full withdrawal returns the full balance" identity is only true when the GLV holds the
  entire market-token supply. My first version asserted identity and failed on the first
  input; the contract was right. The correct invariant is linearity plus bounds.
- Funding goes through the real `StrictBank` path: ERC20 transfer to the GLV, then
  `recordTransferIn` as CONTROLLER. That sets `tokenBalances` the same way production does.

### Cumulative GMX — 110,000 runs

| area | runs | executed |
|---|---|---|
| position impact pool distribution | 25,000 | yes |
| GLV share-price conversion | 25,000 | yes |
| GLV exit round-trip | 20,000 | yes |
| GLV valuation input (short-circuit) | 20,000 | yes |
| **`_getMarketTokenAmount` market loop** | **20,000** | **yes — harness deployed** |
| swap amount application / fees / liquidation | 0 | untested |

**No CRIT/HIGH/MEDIUM.** The GLV surface is now covered down to the market loop, which
means the honest remaining gap is no longer GLV — it is the three untouched areas, and
none of them has had a single run.
