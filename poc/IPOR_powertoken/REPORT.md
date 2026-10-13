# IPOR — PowerToken exchange rate has no virtual offset

**Verdict: real structural weakness, confirmed on deployed bytecode, but NOT
economically exploitable against the live pool. Not worth a bounty claim.**

This closes the one open item from the IPOR solvency review — "PowerToken's
exchange rate is derived from a raw `balanceOf` and is therefore
donation-sensitive in principle". It is donation-sensitive. It is also not
profitable, and the PoC proves both halves rather than arguing them.

```bash
git clone --recurse-submodules https://github.com/IPOR-Labs/ipor-power-tokens.git
cd ipor-power-tokens
npm ci
cp /path/to/ChainScope/poc/IPOR_powertoken/*.t.sol test/pwToken/
forge test --match-contract PwTokenDonation -vv
# 7 passed, 0 failed   (256 fuzz runs)
```

## The mechanism — confirmed

`_calculateInternalExchangeRate` (`PowerTokenInternal.sol:143`):

```solidity
uint256 balanceOfGovernanceToken = IERC20Upgradeable(_governanceToken).balanceOf(address(this));
if (baseTotalSupply == 0) return 1e18;
if (balanceOfGovernanceToken == 0) return 1e18;
return MathOperation.division(balanceOfGovernanceToken * 1e18, baseTotalSupply);
```

No virtual offset, no dead shares, no minimum-liquidity lock. A plain ERC-20
transfer to the proxy moves the rate.

Deposits are credited at that rate (`PowerToken.sol:120`):

```solidity
uint256 baseAmount = MathOperation.division(updateGovernanceToken.governanceTokenAmount * 1e18, exchangeRate);
```

`baseAmount` is what the depositor owns, and **the depositor cannot see or bound
it**. `StakeService.stakeGovernanceTokenToPowerToken(beneficiary, amount)` takes
no `minBaseOut`, no expected rate and no deadline; `PowerTokenRouter` is a
pass-through `fallback` that adds none. So once the rate is inflated past roughly
`amount`, `baseAmount` rounds to zero and the deposit is credited to nobody while
the tokens sit in the contract.

The PoC shows exactly that:

| Test | Result |
|---|---|
| `test_donationAloneInflatesExchangeRate` | a bare `transfer` moved the rate **>1e6x** |
| `test_victimDepositIsCreditedZeroBase` | 1,000 ipOR deposited, **0** base credited |
| `test_attackerRedeemsVictimStakeFeeFree` | attacker extracts the victim's stake via cooldown + `redeemPwToken`, which charges **no** fee (unlike `removeGovernanceTokenWithFeeInternal`, which takes 50%) |
| `test_control_stakeIsCreditedOneToOne` | undisturbed deposits are credited 1:1 — so the above is the attack, not a broken harness |

## Deployed verification

| Check | Result |
|---|---|
| Power Token proxy (Ethereum) | `0xD72915B95c37ae1B16B926f85ad61ccA6395409F` |
| EIP-1967 implementation | `0x78DBF1EA2042fbEf4aF542aaAA81adB26884a0F7` |
| Sourcify | `creationMatch: match`, `runtimeMatch: match`, verified 2024-08-08 |
| `getGovernanceToken()` | `0x1e4746dC744503b53b4A082cB3607B169a289090` (IPOR) |

The formula was then confirmed **numerically against live state**, which is
stronger than reading the source:

```
_baseTotalSupply                     = 10,932,060.528832957156850155
IPOR.balanceOf(powerToken)           = 12,521,485.624402463118847737
calculateExchangeRate()              = 1,145,391,172,265,964,730

12,521,485.624402463118847737 * 1e18 / 10,932,060.528832957156850155
                                   = 1,145,391,172,265,964,730   ✓ exact
```

The deployed contract really does compute `balanceOf(this) * 1e18 /
_baseTotalSupply`. Note the repo build is *not* byte-identical to the deployed
runtime (18,657 vs 10,727 bytes — different optimizer settings), so the PoC runs
against repo source while the deployed behaviour is confirmed separately on-chain.

The base/token gap is also visible: 12.52M tokens are held against 10.93M base
units. That is rounding drift — `baseAmount` rounds **down** on every deposit, so
the rate creeps up and the dust accrues to existing holders. A slow, small leak
from depositors to holders, not a loss.

## Why it is not exploitable

The donor is diluted along with everyone else. Writing `f` for the attacker's
share of base supply:

```
attacker stakes A, contract holds I + A, rate = 1
attacker donates D  -> rate = 1 + D/(I+A)
attacker redeems A  -> receives A * (1 + D/(I+A))
net                 = -D + D*A/(I+A) = -D*(1 - f)
```

Strictly negative for every `f < 1`. Break-even only at `f == 1`, i.e. the
attacker already owns the entire outstanding supply — which is the purchase, not
the attack. The fee-free `redeemPwToken` path does not change this: it only ever
returns the attacker's pro-rata share, so it cannot exceed `D` unless `f == 1`.

`PwTokenDonationProfitability.t.sol` pins the sign of that result — 256 fuzz runs
asserting `attackerEnd < attackerStart` for arbitrary pool shapes, with
`incumbentStake > attackerStake` assumed inline as the `f < 1` precondition. If
a future change made deposits creditable without a proportional token pull, or
let a caller write base directly, these fail.

On the live deployment `_baseTotalSupply` is ~10.93M ipOR held by real users, so
`f == 1` is unreachable by attack.

## Audit gap

Real, and worth recording even though it is not payable here:

- **2022.11 Aacke, "IPOR token audit"** — scope was `IporToken` only. 0 criticals,
  0 highs, 2 findings, both cosmetic.
- **2023.01 Aacke, "IPOR liquidity mining audit"** — scope `LiquidityMining` +
  `PowerIpor`. 21 findings: 1 High (unstake liveness, fixed), 3 Medium
  (ownership renunciation ×2, constants), 1 Warning, 16 Informational.

**Nothing in either report touches the exchange rate.** Every finding is about
liveness, ownership, constants or code quality. The donation-sensitivity of
`_calculateInternalExchangeRate` has never been audited.

## Where it would become real

The mechanism turns from latent to live whenever the pool is small enough for
`f == 1` to be reachable:

- a fresh chain deployment, in the window between the first and second stake
- any period where `_baseTotalSupply` is small relative to intended deposits
- any future change that lets a caller inflate the numerator without the
  proportional `_baseTotalSupply` increase

IPOR is multichain (Ethereum, Polygon, Arbitrum, Base, Optimism, zkSync), so new
deployments are a live consideration rather than a hypothetical.

## Suggested fix (not submitted)

Any one of:

- **Virtual offset** — track `totalAssets` and `totalShares` separately, or mint
  dead shares to an address that can never stake, so a donation cannot move the
  rate.
- **Slippage bound on deposit** — `stakeGovernanceTokenToPowerToken` should take a
  `minBaseAmountOut` and revert if `baseAmount < minBaseAmountOut`. This is the
  single highest-value change: it makes the attack impossible for users
  regardless of pool state, at the cost of one extra parameter.
- **Non-zero floor** — require `baseAmount > 0` in `addGovernanceTokenInternal`
  so a fully-diluted deposit reverts instead of silently vanishing.

## Not a bounty claim

IPOR's Critical tier is a **flat $1,000**, and this is Informational/Low: real
code smell, confirmed deployed, never audited, but with no path to profit on the
live pool. Spending the program's reputation on it would be a bad trade. Filed
here so the reasoning is reusable — the same virtual-offset check is worth
running against any vault whose share price is derived from a raw `balanceOf`,
which is the family `poc/` already covers for ERC4626.