
---

## Two challenges answered: audit gaps, and vault/swap/farm/flashloan coverage

### Q1 — Did I find flaws in their audits?

**One, and it is not in their own threat model.**

The stableswap share-issuance invariant enforced only by `debug_assert_eq!` (fixed
2026-07-15, commit `50a55673c4`) survived three Stableswap audits — 2023-07
Runtime Verification, 2024-04 Code4rena, 2025-05 OAK — plus a Cantina engagement on
the liquidation pallet. Grepping their own 410-line attack-vector reference for
`debug_assert`, `invariant`, or `ShareIssuance` returns **nothing**: they have not
documented it as a known issue either.

That it escaped is the interesting part, because their own checklist theme #11 shows
they reason carefully about exactly this family:

> "**Never use `saturating_sub` by default** — prefer `checked_sub` / `checked_*`
> math; saturating arithmetic silently hides critical errors"

They built theme #11 entirely out of a Critical they paid $500k for, and still
missed that an assertion in the same language which *compiles out of release WASM*
was the sole enforcement of a share-ledger invariant. A production Substrate runtime
is release WASM; `debug_assert_eq!` is not a check there. It is the same class of
error — an operation that looks like it validates and does not — in the sibling
construct.

**Honest caveat:** I found it by reading, they fixed it before I did, and it is not
live. So it is an audit observation, not a bounty finding. It is, however, a clean
demonstration that their documented threat model is not complete, which matters for
deciding where to spend time.

### Q2 — Vault / swap / farm / flashloan re-scan

**Vault, swap, farm, liquidity: covered.** Those are Veck classes 4, 18, 19 and 2
across the 33-target Solidity sweep, and the Rust equivalents R1–R5 across 718
Hydration files. Vault donation (R2/class 19) returned zero on Hydration — correctly,
since Curve stableswap divides by the invariant D rather than `total_supply`.

**Flashloans: not previously covered. Now audited.** The surface is concentrated in
`pallets/liquidation`, which funds liquidations through a flash-mint precompile:

- `T::FlashMinter: Get<Option<(EvmAddress, EvmAddress)>>` — the configured lender
  (`liquidation:150`), set via governance through `hsm::set_flash_minter`
- `Function::FlashLoan = "flashLoan(address,address,uint256,bytes)"` (`:96`)
- `encode_liquidation_data` / `decode_liquidation_data` (`:796-846`) — the callback codec

**The codec is well-built.** `decode_liquidation_data` validates the action byte
against `1`, reads every field through a fallible `EvmDataReader`, SCALE-decodes
each route entry via `decode_from_bytes::<Trade<AssetId>>`, and bounds the route with
`Route::truncate_from`. No length-confusion or unchecked-cast path.

**The callback entry point is dead code.** `liquidate_position` (`:790`) has exactly
**one occurrence in the entire tree — its own definition**. Nothing calls it; it is
not an extrinsic, and no precompile references it. It appears to be a leftover from
a refactor of the pre-multi-MM liquidation path.

**The live path is unsigned-transaction based, and properly gated**
(`ValidateUnsigned`, `:176-224`):

```rust
TransactionSource::External => return InvalidTransaction::Call.into(),  // network: disallow
TransactionSource::Local    => {}   // offchain worker
TransactionSource::InBlock  => {}   // some other node included it in a block
```

Only `Call::liquidate` and `Call::liquidate_with_pool` are accepted, and
`liquidate_with_pool` provides on `(user, pool)` so the same borrower underwater in
two markets cannot produce mutually-replacing transactions. Network-submitted
unsigned liquidations are rejected outright.

**Verdict: no finding.** The flash-loan surface is well-defended at every layer I
could reach — codec validated, callback unreachable, unsigned path restricted with
sensible replacement semantics.

**One residual worth recording, and it is a trust assumption rather than a bug:**
`TransactionSource::InBlock` is accepted, meaning a block producer can include an
unsigned liquidation of their choosing. That is theme #10 (privileged-role impact)
rather than a permissionless Critical, and a crafted liquidation still has to be
economically sound for the producer to profit. It is the kind of thing that belongs
in a privileged-role review, not a public report.
