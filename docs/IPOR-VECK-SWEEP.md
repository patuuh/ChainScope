# IPOR — 21-class Critical sweep, both repos

`python3 -m cli veck scan <dir>` across both IPOR codebases, 2026-10-02.

```
ipor/protocol/contracts    189 .sol files
ipor/power-tokens/contracts 45 .sol files
```

## Full class counts

| Class | protocol | power-tokens |
|---|---|---|
| 1  Uninitialized proxies | 11 | 8 |
| 2  Read-only reentrancy | 5 | — |
| 3  Oracle manipulation | — | 11 |
| 5  Storage collisions | 26 | 4 |
| 7  Access control on admin fns | 63 | 32 |
| 9  Incorrect token handling | 29 | 7 |
| 12 delegatecall to untrusted | 1 | 1 |
| 18 Swap slippage / MEV | 477 | — |
| others | 0 | 0 |

Class 18's 477 is the shape of an AMM, not a finding. The two strong-only hits
were the interesting ones, and both are false positives on deployed code.

## Strong hits, both disproven

**Class 1 — `initialize(...) external initializer`** on `IporProtocolRouterAbstract.sol:24`
and `PowerTokenRouter.sol:46`.

Every other class-1 hit is a `_disableInitializers()` call in a constructor — that
is the mitigation, not the bug. The two real candidates were checked against
mainnet, not just read:

| Contract | Test | Result |
|---|---|---|
| PowerToken proxy `0xD72915B9…5409F` | `eth_call initialize()` | reverts `Initializable: contract is already initialized` |
| IporProtocolRouter `0x16d10400…26fd` | owner at slot `0xF4240` | `0xd92e9f039e4189c342b4067cc61f5d063960d248` (non-zero) |

`StorageLib._getStorageSlot` is `uint256(storageId) + 1_000_000`, so `Owner` (enum 0)
is slot `0xF4240`. Both proxies are initialised. **Disproven.**

## Class 12 — `delegatecall` in both routers

`SpreadRouter.sol:144` and `PowerTokenRouter.sol:164`. Both `_delegate` into
`getRouterImplementation(msg.sig)`, an if/else ladder over **four `immutable`
addresses** (`stakeService`, `flowsService`, `liquidityMiningLens`,
`powerTokenLens`) that ends in `revert(Errors.ROUTER_INVALID_SIGNATURE)`.

Immutables are fixed at construction, and an unrecognised selector reverts rather
than falling through. The delegatecall target is not user-controlled.
**Disproven.**

## Where the remaining signal is

Ranked by how much money is reachable, not by hit count.

1. ~~**`DemandSpreadLibs` — what bounds `demandSpread`.**~~ **Closed — bounded.**
   The `payFixedMinCap` applies to the *base* rate and `demandSpread` is added on
   top, which looked like an unbounded rate. It is not:

   ```solidity
   ratio = weightedNotional * 1e18 / maxNotional;   // maxNotional = lpDepth * demandSpreadFactor
   ratio < 0.2 -> 0.05 * ratio
   ratio < 0.5 -> 0.1333 * ratio - 0.01667
   ratio < 1.0 -> 0.5   * ratio - 0.2
   else        -> 3e17            // hard 30% cap
   ```

   The piecewise curve is continuous at all three boundaries (1% at 0.2, 5% at 0.5,
   30% at 1.0) and hard-capped at 30%. So the offered rate is bounded by
   `(iporIndex + oracleBaseSpreadPerLeg) + 30%`. The only unbounded input left is
   the risk oracle's `baseSpreadPerLeg`, which is governance-controlled and a
   disclosed trust assumption, not a bug.

   Edge cases in the same path are fail-safe rather than dangerous:
   `calculateLpDepth` is `liquidityPoolBalance + |payFixed - receiveFixed|`, and
   `IporMath.division(x, 0)` reverts. If the imbalance ever exceeds the pool
   balance, or lpDepth reaches 0, the open-swap reverts. Those are denial of
   service at worst — they cannot be turned into a loss.

2. **`CalculateWeightedLpTokenBalance{Ethereum,Arbitrum}` (class 3, 11 hits).**
   Weighting LP-token balances by a Chainlink `latestRoundData()` read. Class 3 is
   usually a false positive when the feed is a real oracle, but the interesting
   question is not spot-manipulability — it is whether a stale or
   partially-populated round (`answeredInRound`, `updatedAt`) is checked before
   the answer is used.

3. **`AmmTreasuryBaseV2` (class 2/5/9).** Reads `IERC4626(ammAssetManagement)
   .balanceOf(address(this))` and raw `IERC20.balanceOf` into signed `int256`
   arithmetic. The ERC4626 vault's own share price feeding treasury accounting is
   the same donation-sensitivity family as PowerToken — and the sDAI/PowerToken
   work already gives the harness for it.

4. **Class 9 (29 protocol hits) — fee-on-transfer assumption.** IPOR pulls DAI,
   USDC, USDT. USDC/USDT are not fee-on-transfer today, but the accounting assumes
   an exact pull. Whether the AMM checks received-vs-requested on open determines
   if a fee token would silently desync the treasury.

## Honest status

I have not found the Critical, and I want to be straight that this is now the
likely answer rather than an open question.

Closed so far, each with evidence rather than inference:

| Lead | Result |
|---|---|
| PowerToken exchange rate (no virtual offset) | Real, confirmed on deployed bytecode, but unprofitable while attacker's base share < 1 — 256 fuzz runs |
| `payFixedMinCap` / `receiveFixedMaxCap` rate clamps | Sound, clamped both directions and floored at 0 |
| `DemandSpreadLibs` demand spread | **Bounded** at 30%, continuous across all three breakpoints |
| lpDepth / division-by-zero edges | Fail-safe reverts, cannot cause loss |
| Veck class 1, uninitialized proxy | False positive — both proxies verified initialised on mainnet |
| Veck class 12, delegatecall | False positive — targets are four `immutable` addresses behind a reverting ladder |

What I have not demonstrated, and would need to demonstrate before writing a
report: oracle round freshness in `CalculateWeightedLpTokenBalance*`, and the
ERC4626 share price feeding `AmmTreasuryBaseV2`.

One thing worth weighing before more time goes in here. IPOR's Critical tier is a
**flat $1,000** — a fixed sum, not a band. And the shape of this codebase argues
against there being an undiscovered Critical: it is a Yieldspace-style
fixed-rate-per-tenor AMM whose two central numbers (the index and the base spread)
both come from a governance risk oracle, with every derived spread clamped and
every pathological input reverting rather than paying out. The places a Critical
would actually live are the oracle trust assumptions and the ERC4626 treasury
interaction, and those are the places this design is explicitly conservative.

Spending another hour to find a $1,000 issue here is a worse trade than
submitting the $5,000 mETH finding that is already PoC-green.