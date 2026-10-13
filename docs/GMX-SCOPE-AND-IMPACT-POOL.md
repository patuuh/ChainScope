# GMX — scope discipline, and the impact-pool layer

## Scope verified live, and it caught an error in my own notes

| target | in-scope repos (live) | on disk |
|---|---|---|
| GMX | `gmx-synthetics`, `gmx-contracts`, `GuardianAudits/Audits` | `gmx-synthetics` ✓ |
| Chainlink | 11 × `smartcontractkit/*` + `libocr` | none |
| Wormhole | `wormhole`, `native-token-transfers`, `wormhole-circle-integration` | none |

**`gmx-interface` is not in scope.** My own `AI_AUDIT_FILTER.md` listed it as
*"Repo D: gmx-io/gmx-interface — WEB (the run that's worth it)"*. That is wrong, and
following it would have spent a session on unreportable findings. It is excluded here
and everything below is `gmx-synthetics` only.

Note `GuardianAudits/Audits` is itself in scope but is a **dedup baseline**, not a
hunting target — it is where the Known-Issues registry and prior findings live.

## Payout structure, for calibrating effort

Critical **10% of funds affected, up to $5,000,000 (min $50k)** · High flat **$25,000**
· Medium flat **$10,000**. So a Critical scales with the loss, which makes large-value
bugs worth far more here than the flat High/Medium tiers.

## The prior work that already exists

`HUNT_LOG.md` and `AI_AUDIT_FILTER.md` on this target record substantial prior effort, and
it changes what is worth doing:

- **Audit-saturated.** Guardian continuous to **2026-06-16**, with the June-2026 2.2c
  review reporting 4C/15H/67M/44L/44I, plus Certora, dedaub, abdk and Sherlock. 24 paid
  reports / $2.6M already paid, against 250 in-scope assets.
- **Already fuzzed clean:** PricingUtils core, swap-impact worsening, and swap round-trips
  at 5k/5k/8k runs. Position impact factors and exponents are already confirmed capped
  `pos <= neg`, and position impact mirrors swap — so no round-trip desync.
- **Explicitly identified as the only genuinely NEW layer:** *impact-pool **amount**
  application and token rounding*, as opposed to the impact *price* computation that
  had already been fuzzed.

## What I read: position impact pool distribution

`MarketUtils.getPendingPositionImpactPoolDistributionAmount` (`MarketUtils.sol:2920`):

```solidity
uint256 positionImpactPoolAmount = getPositionImpactPoolAmount(dataStore, market);
if (positionImpactPoolAmount == 0) return (0, positionImpactPoolAmount);

uint256 distributionRate = dataStore.getUint(Keys.positionImpactPoolDistributionRateKey(market));
if (distributionRate == 0) return (0, positionImpactPoolAmount);

uint256 minPositionImpactPoolAmount = dataStore.getUint(Keys.minPositionImpactPoolAmountKey(market));
if (positionImpactPoolAmount <= minPositionImpactPoolAmount) return (0, positionImpactPoolAmount);

uint256 maxDistributionAmount = positionImpactPoolAmount - minPositionImpactPoolAmount;
uint256 durationInSeconds = getSecondsSincePositionImpactPoolDistributed(dataStore, market);
uint256 distributionAmount = Precision.applyFactor(durationInSeconds, distributionRate);
if (distributionAmount > maxDistributionAmount) distributionAmount = maxDistributionAmount;
```

**Sound, and specifically so in three places that matter:**

1. **The floor cannot be breached.** Distribution only proceeds when
   `positionImpactPoolAmount > minPositionImpactPoolAmount`, and `maxDistributionAmount`
   is exactly the excess above that floor. The pool can never be drained below its
   configured minimum.
2. **The subtraction cannot underflow.** The `<=` early return precedes
   `positionImpactPoolAmount - minPositionImpactPoolAmount`, so the invariant
   `positionImpactPoolAmount > minPositionImpactPoolAmount` is already established.
   (A subtraction here would have been a live Critical — underflow would wrap to ~2^256
   and hand an attacker the entire pool.)
3. **The distribution is clamped**, and `Precision.applyFactor` rounds **down**, favouring
   the pool over the claimer.

The withdrawal path (`PositionImpactPoolUtils.withdrawFromPositionImpactPool`, `:38`) is
guarded the same way — it re-checks against `totalPendingImpactAmount` and reverts with
`InsufficientImpactPoolValueForWithdrawal` rather than allowing a partial drain.

## Honest verdict

No finding in what I read, and I am not going to dress the scope of it up. The
impact-pool *distribution* is sound; the earlier-noted untested layer was the *amount
application* inside swap execution, which sits in `MarketUtils.applyDeltaToSwapImpactPool`
and the swap path — not the distribution accrual above.

The thing that decides whether GMX is worth more time is not a code question. It is that
Guardian has audited it continuously to 2026-06-16 and the last review alone carried
4 Criticals and 15 Highs, with 24 paid reports already. **Re-running an
audit-saturated $5M programme is a worse bet than it looks**, and the honest framing is
that the remaining value sits in the layer a static read cannot reach: whether the
**deployed** Arbitrum/Avalanche contracts still match this source, and whether any
Guardian finding's fix was later reverted by a refactor.
