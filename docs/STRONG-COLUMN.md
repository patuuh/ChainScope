# The `strong` column is a navigation aid, not evidence

A quantified correction to how ChainScope's 21-class output should be read,
found by examining the class with the largest untriaged strong count.

## How this surfaced

I recommended the full 21-class sweep to close a coverage gap, and the most
eye-catching number in the output was **class 11 "flawed liquidation math / health
factor" at 137 strong hits across the portfolio**. I picked it as the largest
genuinely-unexamined class, with payout precedent in two programmes.

Sampling the hits before reading any of them:

```
repos/protocol-v2/contracts/interfaces/ILendingPool.sol:326   * @return healthFactor the current health factor of the user
repos/protocol-v2/contracts/interfaces/ILendingPool.sol:337   uint256 healthFactor
repos/protocol-v2/contracts/protocol/lendingpool/LendingPool.sol:600   uint256 healthFactor
repos/protocol-v2/.../LendingPoolCollateralManager.sol:94    (, , , , vars.healthFactor) = GenericLogic.calculateUserAccountData(
```

All 51 strong hits on AAVE matched `/healthFactor/`. Every one was an interface
declaration, a local variable, a doc comment, or the canonical `GenericLogic`
library — which has been audited more times than anything else in this corpus.
**None was a risk signal.** `healthFactor` is simply Aave's variable name.

## The systemic measurement

Splitting all 42 `strong` patterns into *bare identifiers* (match vocabulary) and
*shape-based* (match a risk form):

| class | bare | shape | |
|---|---|---|---|
| **11** liquidation math | **2** | 0 | *entirely* name-based |
| 21 modular account | 5 | 6 | `installModule`, `executeFromModule`, … |
| 20 paymaster | 4 | 6 | canonical 4337 hook names |
| 17 CL pool math | 3 | 4 | `sqrtPriceX96`, `getSqrtRatioAtTick`, … |
| 4 share rounding | 1 | 3 | `decimalsOffset` |

**15 of 42 strong patterns are bare identifiers.** Class 20 was already caught and
fixed (`r"EntryPoint"` matching Royco's own `RoycoEntryPoint`; `r"postOp\b"`
matching a local variable — 252 → 0 on Royco). Class 11 is the same defect, in the
largest untriaged class.

## The fix, and why it demotes rather than replaces

```python
"strong": [
    r"function\s+healthFactor\s*\(",                  # a definition, not a mention
    r"MAX_HEALTH_FACTOR",
    r"liquidationThreshold\s*(?:<|>)\s*(?:ltf|ltc|loan)",
],
"weak": [..., r"healthFactor", r"liquidateBorrow"],
```

`healthFactor` and `liquidateBorrow` move to `weak`: still useful for
**navigation** — they find the right subsystem — but no longer counted as
evidence.

I did **not** invent a replacement "shape" pattern to keep the count up. The real
bugs in this class are semantic: health-factor comparison inverted, missing
`MAX_HEALTH_FACTOR` sentinel, no zero-collateral guard before dividing, `closeFactor`
treated as 100%. None of those is reliably regex-detectable, and a pattern that
looked like it detected them while not would be worse than a demotion.

**Result: AAVE 51 strong → 0**, SparkleEnd → 0, with hits preserved as weak
navigation. EtherFi retains 2, and both are genuine `function healthFactor(address
safe)` definitions — the correct read anchors — each delegating to Aave V3's
`getUserAccountData`. No finding.

## The rule this establishes

**A `strong` hit means "look here", not "look — this is wrong."**

Three consequences worth carrying forward:

1. **Ratios across corpora are meaningless for name-based classes.** A 94% strong
   ratio (class 20) and a 100%-name-based class (class 11) both produced numbers
   that looked fertile and were pure noise. Twice I nearly recorded one as a
   headline finding.
2. **The only classes whose strong counts can be compared across corpora are the
   shape-based ones** — 1, 3, 6, 7, 8, 9, 12, 13, 14, 15, 18, 19 (27 of 42 patterns).
3. **Counting was never the bottleneck.** Every candidate this session died on
   reading, and one died on the target's own catalogue. Six closed by tracing to
   the layer that actually carries the invariant.

Classes 17 and 21 carry the same weakness and were fixed on inspection rather than
measurement; **the remaining name-based patterns should be treated as navigation
only until reshaped**. That is the honest backlog, and it is a tooling task, not a
hunting one.
