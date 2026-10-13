# Lido Stonks — the LP vault, read

`lidofinance/stonks`, 62 files / 7,458 lines, mainnet deployed as
`0x8c595aA4AEc6F42B9e7D77F83179768D37CE3042` (LP mode) and
`0xb368586CB980895E51e1D82102E63b3F69d3F151` (Treasury mode).

**Shape note:** Stonks is an *aggregator/router* across Curve, Balancer, CoW and 1inch
(`ICurvePool`, `ICoWSwapSettlement`, and reward programmes in the docs), not an LP with
share math. So the donation/first-depositor family that produced findings on three other
protocols this session **does not apply here** — there are no shares to dilute.

## 21-class recon

44 first-party files: **82 hits, 1 strong** — class 1 at `contracts/Order.sol:148`
(`initialize`). Weak: 32 class-7, 17 class-2, 15 class-13, 6 class-9, 4 class-6, 3 class-3,
2 class-18.

## The one strong hit, and it is guarded

`Order` is deployed two ways, and both are safe:

1. **Direct** (`StonksFactory.sol:80`: `new Order(...)`) — the constructor sets
   `initialized = true` with the comment *"Prevents accidental initialization on the
   implementation itself."* So the implementation can never be initialised.

2. **Minimal proxy** (`Stonks.sol:425-428`):
   ```solidity
   Order orderCopy = Order(Clones.clone(ORDER_SAMPLE));
   ...
   orderCopy.initialize(minBuyAmount_, manager, RECEIVER);
   ```
   A clone's storage is empty, so a clone *is* initialisable — but deploy and
   `initialize` happen in the **same execution frame**, so nothing can interleave and
   there is no front-running window. `initialize` also sets `stonks = msg.sender`, which
   is the `Stonks` contract itself, and rejects `receiver_ == address(0)`.

**No finding.** Clean negative, and the read was still worth doing: the class-1 shape is
exactly what the scanner is for, and it survived on reading.

## What this adds to the pattern

The donation/share family has now been looked for on seven protocols — IPOR PowerToken,
Gamma Hypervisor, Gamma xGamma, mETH StETH, GMX GLV, GMX FeeDistributor and Lido Stonks.
It produced a real, unaudited instance exactly once (xGamma), and that instance turned out
to be mathematically impossible below sole-holder share. Stonks does not have the shape at
all, because it holds no shares.

That is a stronger statement than "no finding": **the family is close to exhausted on
audited code**, and the remaining exposure is fresh deployments and forks, which is where
the economics actually pointed from the start.
