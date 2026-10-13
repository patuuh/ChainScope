# GMX FeeDistributor — split arithmetic, executed

The biggest untouched surface: `FeeDistributor.sol`, 781 lines, 57 hit-count in the
21-class sweep and **zero executed runs** until this campaign.

Everything routes through `Precision.mulDiv` → OZ `Math.mulDiv` (rounds down) and
`Precision.applyFactor` (= `mulDiv` by `FLOAT_PRECISION`, also down). For a fee
splitter the question is **conservation**: parts handed out must never exceed what
came in, and any shortfall must land in the treasury rather than vanish.

**7 tests, 30,000 runs, all green.**

| Test | Property |
|---|---|
| `testFuzz_splitConserves_and_partsFit` | keeper + Chainlink + treasury ≤ balance |
| `testFuzz_v2DominantSplitConserves` | holds when v2 fees dominate v1 |
| `testFuzz_finalizeIsMonotonicInKeeperCost` | more keeper cost never raises the treasury take |
| `testFuzz_pullFromTreasury_respectsCap` | the treasury pull respects `MAX_WNT_AMOUNT_FROM_TREASURY` |
| `test_pullBeyondCap_reverts` | reverts past the cap |
| `testFuzz_unspentBalanceAccruesToTreasury` | unspent balance accrues to treasury, not lost |
| `test_undersizedV2Slice_reverts` | documents the unguarded subtraction |

## Observation recorded, not claimed

`FeeDistributor.sol:656`:

```solidity
uint256 wntForTreasury = chainlinkTreasuryWntAmount - wntForChainlink - keeperCostsV2;
```

**No prior guard.** `keeperCostsV2` comes from `FeeDistributorUtils.calculateKeeperCosts`
(target balances minus actual balances), and the v2 slice is
`mulDiv(totalWntBalance, feesV2UsdInWnt, feesV1UsdInWnt + feesV2UsdInWnt)`. When v1 fees
dominate, the v2 slice is small and the subtraction **underflows**, reverting the entire
weekly distribution. Concrete case from the fuzzer:
`bal=4985, feesV1=21272, feesV2=18, keeperCostsV2=12` → slice `4`, `4 - 0 - 12` underflows.

Reverting is safe — no misallocation. Two things make it worth reporting anyway:

1. **`distribute` is keeper-triggered and time-gated** (per-week). A revert blocks that
   week until someone intervenes, and the `initiateDistribute` → `processLzReceive` →
   `distribute` sequence has already paid for cross-chain reads by then.
2. **The contract's own `_finalizeWntForTreasury` logic exists precisely to absorb
   shortfalls** — it has a whole branch for `keeperAndReferralCostsV1 > wntBeforeV1`,
   including pulling extra WNT from the treasury up to a cap. It simply **never gets to
   run**, because the earlier unguarded subtraction reverts first.

So the deficit-handling design exists and is unreachable on this path. That reads like a
missing guard rather than intended behaviour. **Not filed** — reachability from production
configuration is not established, and `keeperCostsV2` exceeding a small v2 slice requires
an unusual fee mix.

## Harness notes

The mirrors needed struct parameters, not positional ones: the originals take 4–7
arguments and solc's stack limit trips once a harness adds its own locals. Four separate
"Stack too deep" failures before packing inputs into `Split`/`Final` structs — the fix is
structs, not trimming variables.

## Cumulative GMX — 140,000 runs

| area | runs | executed |
|---|---|---|
| position impact pool distribution | 25,000 | yes |
| GLV share-price conversion | 25,000 | yes |
| GLV exit round-trip | 20,000 | yes |
| GLV valuation input | 20,000 | yes |
| GLV market loop (deployed harness) | 20,000 | yes |
| **fee split arithmetic** | **30,000** | **yes** |
| swap amount application | 0 | untested |
| liquidation | 0 | untested |

**No CRIT/HIGH/MEDIUM across 140,000 runs.**

## The recurring lesson, sixth instance

F4 asserted `assertGe(tHigh, tLow)` — **inverted**. The fuzzer failed it on the first
input by correctly showing treasury *falls* as keeper cost rises. Same shape as the
impact-pool monotonicity bound, the GLV `floatToWei` double-scale, the GLV supply
assumption, and the independently-bounded `min_`/`max_` pair: **I write an invariant
from reading, the fuzzer disproves my direction or domain, and the contract is right.**

Six times now. The tools have not found one protocol bug in GMX and have found six
errors in my reasoning — which is the strongest argument I have for the discipline.
