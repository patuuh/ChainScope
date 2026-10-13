# The Critical bias, and what High-severity hunting actually found

A fair challenge: I framed this whole session around Critical, and the evidence
says that was the wrong lens.

## The bias, quantified

| | tier | payout |
|---|---|---|
| **The only thing I submitted this session** (mETH permit griefing) | **Medium** | $5,000 |
| Hydration's DCA + batch-call oracle manipulation | **High** | **$25,000** |
| Hydration's aToken liquidity addition | Critical | $500,000 |

**My sole submission was a Medium, and the target pays 5x that for a High.** So
"not Critical" was never a negative result — I was treating the absence of the
rarest, best-defended tier as a clean result while the realistic earnable tier sat
one notch down and unpaid.

Three further consequences of the framing:

1. **The 21 classes are named "Critical" but span the range.** Class 19
   (donation) produced a *Medium* on three separate protocols.
2. **I ranked targets by Critical ceiling.** Gamma's $50,000 Critical vs
   Hydration's $222,222 — but Hydration's actual High payout was $25,000 and its
   Medium is a fraction of that, while Gamma's scope was three mature addresses
   where every finding died on `f < 1`.
3. **The strongest theme on Hydration's own checklist is a High** — *"DCA + batch_call
   can guarantee transaction ordering across blocks … attackers can ratchet oracle
   prices over multiple blocks while keeping net exposure near zero"* — and it paid
   $25,000. It is theme #12 of 14 and I treated it as an afterthought.

## What High-severity hunting found

Targeted the class with a demonstrated High payout and no price limit anywhere in
the system: **liquidation executed on a manipulated or stale oracle.**

**There is no freshness check in the liquidation pallet** — no `stale`, no
`updated_at`, no deviation guard, no `PriceLimit` in either `circuit-breaker` or
`ema-oracle`. Volume caps are the only per-block bound. That looked like a real gap.

It is not, and the reason is the interesting part: **the pallet does not compute
the health factor or the seize amount at all.** It is a router.

```rust
// liquidation/src/lib.rs:341 — note `_origin` is ignored; the public path is open
pub fn liquidate(_origin: OriginFor<T>, collateral_asset, debt_asset, user, debt_to_cover, route)
```

`debt_to_cover` is caller-supplied, which is the classic "repay less, seize more"
shape. But it is forwarded to **Aave's `liquidationCall`**, which validates the
position is underwater, bounds the repay against actual debt, and computes the
seizure itself from the configured liquidation bonus. The substrate pallet defers
to the money market as the source of truth.

**No finding — and a good design worth naming.** Adding a second, pallet-side health
calculation would have created a *divergence* risk against Aave's own, which is
exactly the cross-pool confusion that produced the $200k XYK report (theme #14).

Two structural notes from the same read:

- `liquidate_with_pool` is **unsigned-only** — `ValidateUnsigned` rejects
  `TransactionSource::External`, so only a collator's own liquidation worker can
  submit it. Its `pool` parameter is an anti-footgun assertion
  (`PoolAddressMismatch`), not a second resolver: both paths resolve identically, so
  a liquidation cannot execute against a different market than the decision was
  made against.
- The GIGAHDX branch is documented as fail-closed: that reserve lists HOLLAR as its
  only borrowable asset, so the `debt_asset == HollarId` check is a guard, not a
  router, and a gigahdx position *must not* fall through to the generic path. The
  comment says what must change if that configuration ever does — which is the
  right way to record a latent coupling.

## What actually changes in the approach

- **Rank by the tier I can reach, not the ceiling I cannot.** A well-evidenced
  Medium on a live pool beats an unproven Critical on a scope-limited one.
- **Stop treating "no Critical" as a clean result.** The classes that found things —
  donation/first-depositor, confused deputy, slippage, saturating arithmetic — all
  produce Medium and High findings, not Critical ones.
- **High-severity classes I have not hunted at all:** permanent fund-freeze
  (Hydration's PT_711 was a freeze — a High, and I filed it as a "process failure"
  because it wasn't deployed), protocol bad debt without theft, and
  governance/privileged-role impact. Theme #10 is the last of these and is
  explicitly in scope, with no fee.
