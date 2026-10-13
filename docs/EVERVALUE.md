# EverValue Coin DualDefense — read in full

## It is not live

```
title     : EverValue Coin DualDefense Audit
status    : Completed          published 09 Jan 2025  ->  end_date 01 Feb 2025
ceiling   : $37,000            prior reports: 9        kyc_required: true
repo      : github.com/devervalue/orderbook @ a958f6ec1761f869f4300c109e01f4c347245709
```

A three-week DualDefense contest that closed in **February 2025** — 15 months ago.
No submission is possible to that programme.

## What I read

The pinned commit is small enough to read rather than pattern-match: **five source
files, ~1,964 lines** — `OrderBookFactory` (367), `PairLib` (627), `RedBlackTreeLib`
(734), `OrderBookLib` (123), `QueueLib` (113) — against ~2,847 lines of tests.

The 21-class recon is **clean**: 6 weak class-7 (access control), 3 weak class-9
(token handling), **zero strong hits**. So this was a read, not a triage.

## Architecture

`addNewOrder` escrows nothing itself; the money path is reached through the library:

```
addNewOrder → addBuyOrder/addSellOrder → createOrder (:469)
    ├─ matches → fillOrder (:285) / partiallyFillOrder (:345)
    └─ remainder → addOrder (:241) → safeTransferFrom(trader, this, …)
```

`withdrawBalanceTrader` lets a trader pull credited balances, and the pinned
commit is literally **"Split withdrawals for base and quote token"** — so the
withdrawal path is what changed last.

## What I checked, and the one real trap

**The token flow is correct in both directions.** For a taker buy, the taker sends
quote and receives base while the *maker* is credited quote; for a taker sell the
mirror holds. The fee is taken from the received amount and forwarded to
`feeAddress` only when set.

**The memory-semantics trap — real, and it does not fire.** `fillOrder` does
`takerOrder.quantity -= matchedOrder.availableQuantity` on a **memory** struct,
while the matching loop conditions on a separate local `_quantity`. That looks like
the classic "mutation lost across a call" over-fill: a taker draining makers' escrow
beyond what they ordered. It is handled — `matchOrder` *returns* the remaining
quantity, and `createOrder:511` reassigns `newOrder.quantity = _quantity`. Memory
structs pass by reference for internal calls, so the decrement propagates as well.
**Verified, not assumed** — this was the most promising thing in the codebase.

**Escrow matches the order.** `addOrder` escrows `newOrder.quantity` *and* books
`newOrder.quantity` *and* stores the struct with that value; `createOrder:511` has
already reduced `quantity` to the post-match remainder, so resting orders escrow
exactly their `availableQuantity`. `cancelOrder` refunds on the same basis.

**The order ID is a `keccak256(abi.encodePacked(msg.sender, "buy"|"sell", price, timestamp))`.**
Mixed-width packed encoding is a classic collision vector, but here the leading
element is a fixed 20-byte address and the `"buy"`/`"sell"` branch differs at byte
3 (`0x79` vs `0x6c`), so no two distinct tuples can produce the same preimage. The
user-supplied `timestamp` only re-derives an ID that already collides with itself,
which `PL__OrderIdAlreadyExists` rejects.

**The symmetric pair identifier is a design subtlety, not a bug.**
`addPair` sorts the two token addresses into `identifier` so `(A,B)` and `(B,A)`
collide, while storing `baseToken`/`quoteToken` in whatever orientation the caller
passed. Since `addPair` is `onlyOwner` and `getPairById` returns the stored
orientation, there is no way for a user to be misled about which is base.

## Verdict

**No finding.** The settlement path holds together under reading, and the one
genuine trap — memory-struct quantity mutation in `fillOrder` — is correctly
handled by `matchOrder` returning the remainder. This was also the thinnest contest
in the dataset by report count (9), which is exactly why it was worth reading; it
simply does not yield.

Two observations that are not findings but would matter to anyone integrating:

- `addNewOrder` takes a **user-supplied `timestamp`** that only feeds the order ID.
  Nothing is time-gated, so it is cosmetic today, but it becomes a real hazard the
  moment any time-based rule (expiry, FIFO decay) is added on top of it.
- The description's bitcoin-custody model ("bitcoins deposited daily, withdrawable
  only by burning EVA") is **not implemented in this repository**. `withdrawBalance`
  pays out ERC-20 balances already credited in `traderBalances`; there is no
  bitcoin accounting, no deposit function, and no redemption path here. The
  custodial mechanism the program text describes lives elsewhere, which is worth
  confirming before anyone treats this repo as the whole attack surface.
