
---

## Worked #12 (multi-block oracle attacks) — the fix is present; sufficiency needs live state

This is the $25k post-mortem, so it got the most attention.

**The fix they described is in the code.** Their recommended remediation was "rate-limit
DCA trade sizes and monitor multi-block price drift":

```rust
// runtime/hydradx/src/assets.rs:629
pub const DefaultMaxNetTradeVolumeLimitPerBlock: (u32, u32) = (1_670, 10_000);  // 17%
```

plus `MaxSchedulePerBlock` bounding DCA schedules per block, and
`MinimumTradingLimit` in the DCA pallet. `ScheduleIdsPerBlock::take(block)` in
`dca/src/lib.rs:148` collects a block's schedules for execution.

**The limit is on NET flow, not gross** — `circuit-breaker/src/lib.rs:71-93`:

```rust
pub fn check_outflow_limit(&self) -> DispatchResult {
    if self.volume_out > self.volume_in {
        let diff = self.volume_out.checked_sub(&self.volume_in)?;
        ensure!(diff <= self.limit, Error::<T>::TokenOutflowLimitReached);
    }
    Ok(())
}
```

A round trip nets to zero and passes regardless of gross volume. That is
**semantically correct for price impact** — net position is what moves a price, and
a buy-then-sell leaves no net exposure, so charging it against a directional limit
would penalise the wrong thing. The `17%` bound is on net directional flow per
block, per asset, per direction.

**One discrepancy worth recording:** both write-ups describe *per-block **price**
change* limits ("max 50%" in the Omnipool post-mortem), but no `PriceLimit` exists
in `circuit-breaker` or `ema-oracle`. What is implemented is a per-block **volume**
cap. That is a defensible substitute — volume bounds price impact in proportion to
pool depth — but it is not the same instrument, and the documentation describes one
while the code implements the other.

### Where this actually stops

Whether 17% net flow per block, sustained across blocks, permits a profitable
ratchet depends on things I cannot read from source:

1. live pool depth per pool — price impact of 17% flow is a function of depth
2. the configured `MaxSchedulePerBlock` value (only benchmark references found)
3. how much arbitrage competition reverts the price between blocks
4. whether `batch_call` still guarantees the intra-block ordering the attack needed

**This is the first theme where the blocker is genuinely economic and
deployment-level rather than code-level.** Every previous theme closed on something
I could establish from source. This one does not, and guessing at it would be the
exact failure mode this session has been guarding against — reporting a story
instead of a demonstration.

The code-level question ("is the documented fix present?") is answered: yes. The
security question ("is it sufficient?") needs a parachain endpoint and a fork
simulation, which is the same blocker that closed the `debug_assert` finding.

---

## Final state

Eight of fourteen themes worked: #1, #2, #3, #4, #5, #9, #12, #14.

| # | Theme | Result |
|---|---|---|
| 1 | Direct transfers bypass hooks | clean — no unhooked path into pool accounts |
| 2 | `asset_in == asset_out` | clean — invariant at pool creation, not the trade path |
| 3 | Division by zero on empty pools | clean — minimum-reserve floors + 53 division guards |
| 4 | Slippage gaps | opt-in variants + privileged path; trait path is a known class |
| 5 | Oracle hook coverage | clean — `on_liquidity_changed` / `on_trade` on every mutator |
| 9 | EVM/Substrate boundary | clean — two-namespace discriminator is sound; ERC20 collision catalogued |
| 12 | Multi-block oracle attacks | fix present (17% net/block); sufficiency needs live state |
| 14 | Confused deputy | defended in the shared handler, not the wrapper |

**No novel finding.** Six themes closed on source; #12 closed on the boundary of
what source can answer.

Six untouched: #6 amplification rate-limiting, #7 amplification sandwich, #8
existential-deposit awareness, #10 privileged-role impact, #11 `saturating_*`
(covered by R5 — clean), #13 scope creep in shared layers.

The two that remain most promising both need a **fork simulation**, not more
reading: #12's sufficiency, and #13's blast radius — theme #13 is precisely the
lesson of the $500k aToken Critical, where a "small" fix in the shared
`currencies` transfer layer broke every dependent pallet. Nothing static will find
that; it needs a test that exercises the shared layer under a dependent pallet's
assumptions.
