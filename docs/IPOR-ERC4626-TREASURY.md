# IPOR — ERC4626 treasury interaction, and oracle freshness across chains

Two threads left open after the PowerToken sweep. Both closed. Neither is a finding.

## Thread 1 — Chainlink round freshness (all three chain variants)

`CalculateWeightedLpTokenBalance{Ethereum,Arbitrum,Base}` all destructure the feed
answer and discard the round metadata:

```solidity
(, int256 answer, , , ) = AggregatorV3Interface(ethUsdOracle_).latestRoundData();
```

`updatedAt` and `answeredInRound` are never read, so there is no staleness bound on
a value that scales a staker's reward weight. The Arbitrum and Base variants
compound this by reading **two** feeds and multiplying them:

```solidity
return MathOperation.division(
    lpTokenBalance_ * answerEthUsd.toUint256() * answerWstEthEth.toUint256(),
    1e26 // 18 + 8 + 18 - 26 = 18
);
```

**Not exploitable.** Every address involved is a real Chainlink aggregator — the
Ethereum config reads back `0x5f4ec3df9cbd43714fe2740f5e3616155c5b8419` live on
chain, and the Arbitrum/Base feed addresses are documented in-source. Missing
staleness checks are a Chainlink best-practice violation, not an attack: triggering
them would require compromising the feed networks. Informational hardening.

## Thread 2 — `getLiquidityPoolBalance()` reads the ERC4626 vault share price

`AmmTreasuryBaseV2.getLiquidityPoolBalance()` (`:85`) includes:

```solidity
IporMath.convertToWad(IERC4626(ammAssetManagement).maxWithdraw(address(this)), assetDecimals)
```

`maxWithdraw` is `convertToAssets(balanceOf)` — the vault's **share price**. That
is the same donation-sensitive quantity as PowerToken's `_baseTotalSupply`, and it
is not decorative: `AmmOpenSwapServiceBaseV1:142` feeds it into
`_validateLiquidityPoolCollateralRatioAndSwapLeverage`, where it is the
**denominator of the collateral-ratio gate** on opening a swap.

So the question was whether donating to `ammAssetManagement` inflates the ratio,
lets a swap open without real collateral, and strands the AMM.

**It cannot, and the reason is the opposite of PowerToken.** Donating D to the
vault raises `totalAssets` while the treasury's share count is unchanged, so
`convertToAssets` rises and `maxWithdraw` rises by ~D. That D is **real, claimable
backing sitting in the vault** — the treasury can withdraw it. The ratio the AMM
reports is therefore honest, and the attacker who inflates it has funded the AMM
rather than tricked it. Worse for the attacker, the donation is a plain transfer
and is unrecoverable by the donor.

Contrast with PowerToken: there, the donation inflated a rate that the donor's
1-wei position captured, so the value was extractable by whoever held the base.
Here the donation flows to the protocol as backing and cannot be withdrawn back.
Same primitive, opposite risk.

## Fail-safe edges, for completeness

`getLiquidityPoolBalance()` ends in `.toUint256()` on a signed sum, so if AMM
liabilities ever exceed assets it **reverts** rather than wrapping. That would make
the ratio check and the spread calculation revert, blocking swap opens — a denial of
service at worst, and the same fail-closed pattern seen elsewhere in this codebase
(`calculateLpDepth` / `IporMath.division(x, 0)`).

## Verdict

Neither thread is submittable. Across the whole IPOR effort — AmmStorage
accounting, PowerToken exchange rate, the 21 Critical classes, reverse engineering
of two deployed implementations, the pending PT_711 fix, the pool powerUp curve, the
Chainlink freshness gap, and this ERC4626 treasury path — the outcome is consistent:
**the deployed system is conservative in exactly the places a Critical would live.**

Ten threads, ten closed. Every lead resolved into one of: already known to IPOR,
verified false positive, provably correct, or intentional and documented in their
own tests.