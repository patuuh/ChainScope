# IPOR PowerToken — exhaustive sweep, 2026-10-02

All 21 Critical classes plus reverse engineering of the deployed bytecode, on
`ipor-power-tokens` and the live Ethereum deployment. Result: **no submittable
finding.** Eight threads opened, eight closed, five of them against deployed code.

## 21 classes

| Class | Hits | Disposition |
|---|---|---|
| 1 Uninitialized proxies | 8 | **False positive.** 7 are `_disableInitializers()` — the mitigation. The 1 real candidate (`PowerTokenRouter.initialize`) is not the PowerToken proxy. Verified live: `eth_call initialize()` on the PowerToken proxy reverts `Initializable: contract is already initialized`. |
| 12 delegatecall to untrusted | 1 | **False positive.** `PowerTokenRouter._delegate` routes through `getRouterImplementation(msg.sig)`, an if/else ladder over four `immutable` addresses ending in `revert(ROUTER_INVALID_SIGNATURE)`. |
| 3 Oracle manipulation | 11 | **Real hardening gap, not exploitable.** See below. |
| 5 Storage collisions | 4 | False positive. All are `StorageLib` structs at `1_000_000 + enum`, non-overlapping by construction. |
| 7 Access control | 32 | All `onlyOwner` / `onlyPauseGuardian` / `onlyRouter`. Correctly gated. |
| 9 Token handling | 7 | Mock/aggregate `transferFrom` assumptions. No fee-on-transfer token in the live set (DAI/USDC/USDT). |
| all others | 0 | — |

### Class 3 detail — the one real gap

`CalculateWeightedLpTokenBalance{Ethereum,Arbitrum}` destructure the Chainlink
answer and **discard the round metadata entirely**:

```solidity
(, int256 answer, , , ) = AggregatorV3Interface(ethUsdOracle).latestRoundData();
```

`updatedAt` and `answeredInRound` are never read, so there is no staleness bound.
Deployed `getConfiguration()` returns `0x5f4ec3df9cbd43714fe2740f5e3616155c5b8419`,
which is the genuine mainnet Chainlink ETH/USD feed — so this is not
attacker-triggerable without compromising the feed. Informational hardening, not a
finding.

## Reverse engineering — deployed LiquidityMining

| Check | Result |
|---|---|
| Proxy | `0xCC3Fc4C9Ba7f8b8aA433Bc586D390A70560FF366` |
| Implementation | `0x0a06ec4004c02fd514ee02c455d20062f7c45edc` |
| Runtime size | 22,262 bytes |
| `getVersion()` | **2002** |
| Sourcify | `runtimeMatch: match` |
| `reconcileAggregatedPowerUp(address[],int256[])` | **absent** — confirms the v2003 fix is not deployed |
| `DELEGATECALL` sites | 4, all from OZ UUPS `upgradeToAndCall`; zero `delegatecall` in project source |

### Correction — the selector scan was not sound, and neither was the original claim

An earlier version of this table reported "41 dispatcher selectors, 39 resolved, no
function in the binary absent from source — no backdoor". **That was not a valid
conclusion**, and it has been retracted.

`extract_selectors` scans for `PUSH4` immediates. Modern solc does not emit a table
of selectors — it builds a **binary search over range comparisons** (`GT`/`LE`
chains), so those immediates are comparison *bounds*. A correctly-dispatched
selector frequently has no literal in the code at all, and a bound can coincide
with an unrelated known selector. Confirmed on IPOR's deployed PowerToken
implementation (`0x78DBF1EA..`, Sourcify `runtimeMatch: match`): the scan reported
42 "selectors", all of which 4byte-resolved to plausible signatures, while on-chain
probing shows `transfer`, `transferFrom`, `allowance`, `nonces`, `delegate` and
`approve` **all revert** — because `contract PowerToken is PowerTokenInternal,
IPowerToken` does **not** inherit ERC20 and is a non-transferable staking receipt.
Several "resolved" entries were bounds that merely happened to match a well-known
selector.

The "no backdoor" conclusion still stands, but it rests on **Sourcify
`runtimeMatch: match`** — the implementation bytecode is proven to match verified
source — not on the selector scan. `core/cs_re.py` now carries this warning, returns
`is_function_list: False` so callers cannot mistake the output for an ABI, and ships
`probe_selectors` for behavioural ground truth via `eth_call`.

## The PT_711 principal freeze is live

`getVersion()` returns **2002**, not 2003. The IL-8156 fix exists in source but is
not deployed, so the deployed `calculateAggregatedPowerUp` still does
`require(PT_711)` instead of clamping.

**This is not a finding.** IPOR already has it: the fix commit states it "Fixes
the PT_711 principal freeze reported via Immunefi (IL-8155)", names the victim
(`0xFA8a4aD4…`, 679.6 ipDAI), and ships the fix plus three regression suites. The
victim's ipDAI balance is now `1` — they have already recovered. Reporting it
would be a duplicate of a report IPOR filed against itself.

## Review of the pending fix (v2003) — the actually unreviewed code

`_reconcileAggregatedPowerUp` settles accrual with the **old** aggregate
(`LiquidityMiningInternal.sol:389-407`) before recomputing the multiplier from the
new one (`:411-414`). That ordering is correct — rewards are earned under the old
weight, then the weight changes.

I expected the clamp to introduce a *new* freeze: `calculateCompositeMultiplier`
returns `0` when `aggregatedPowerUp == 0`, and `calculateAccountRewards` requires
`accruedCompMultiplierCumulativePrevBlock >= accountCompMultiplierCumulativePrevBlock`.
If the cumulative reset to 0, every account with a non-zero stored cumulative would
be stuck.

**That hypothesis was wrong, and it is worth recording why.** The cumulative is
*not* reset — `calculateAccruedCompMultiplierCumulativePrevBlock` returns
`stored + blocksElapsed × perBlock`, and it is only `perBlock` that goes to zero.
The cumulative stays consistent, the `require` holds, and the pool simply
under-accrues until reconciled. The fix is sound. Post-reconcile the multiplier
also *decreases* (aggregate grows), so the `toUint128` cast gets safer, not
riskier.

## pool powerUp curve — intended, and my numbers check out

`logBase` is **3.0** (stored 18-decimal; the repo's own test is named
`MiningCalculationLog3Mod5Curv02`), `pwTokenModifier` **5.0**, `horizontalShift`
**0.5**.

The log branch is taken when `ratio > 0.1`, and `underLog = 5.0 × ratio + 0.5`, so
`ratio > 0.1 ⟺ underLog > 1 ⟺ log₃(underLog) > 0`. The branch condition is exactly
aligned to where the log turns positive, which is why the source comment "This
value can never be negative" is correct. I had expected a reachable negative-log
underflow at the threshold; it is unreachable.

There **is** a ~2× discontinuity in powerUp across `ratio = 0.1` (0.59995e18 →
1.178e18), because the step-function branch adds `vectorOfCurve` while the
logarithmic branch subtracts `222392421336447926` and adds nothing. This is
**intentional** — the project's own test asserts it:

```solidity
_testData.push(TestData(1000e18, 99e18,  599500000000000001)); // should be jump between 99 and 101
_testData.push(TestData(1000e18, 101e18, 1182147434591329528)); // should be jump between 99 and 101
```

My independently computed values match their asserted values to the wei.

## Verdict

Nothing here is submittable. The three things that looked most promising —
the freeze, the fix, and the curve — are respectively already known to IPOR,
correct, and intentional. The two scanner strong-hits are false positives verified
on-chain. The one real gap (missing Chainlink round-freshness) is Informational and
not attacker-triggerable.

At a **flat $1,000** Critical tier this is the right place to stop. The reusable
output is the method: run all 21 classes, then prove each survivor against
deployed bytecode and live state before believing it, because on this codebase two
of two strong hits were false positives and three of eight leads were already-known
or intentional.