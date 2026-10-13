# Deployment verification sweep — high-ceiling Immunefi programmes

**Purpose:** the class that needs no novel bug. An in-scope proxy whose implementation
was never initialised is Critical on its own — whoever calls `initialize()` owns the
contract — and it is answerable mechanically across hundreds of addresses.

Built `core/cs_deploy.py` for it: EIP-1967 implementation and beacon slot reads,
OZ initialisation flags, runtime identity, one RPC round-trip per address.

## Result

**360 in-scope EVM addresses across 9 programmes, 359 verified (1 RPC error):**

| programme | addresses | proxies |
|---|---|---|
| sparklend | 144 | 49 |
| gmx | 125 | 0 |
| balancer | 24 | — |
| optimism | 18 | 9 |
| ethena | 15 | 2 |
| stargate | 14 | — |
| layerzero | 9 | 0 |
| usdt0 | 8 | 7 |
| aave | 3 | 1 |

**68 proxies. Zero uninitialised implementations.**

LayerZero's nine in-scope addresses are **all direct, non-proxy** — no EIP-1967 slot is
set on any of them, which closes that axis for the $15M programme outright.

## The caveat that matters — this is not a clean bill

The detection is **slot-based** and that is weaker than it looks. Evidence:

- Probes against the same proxies returned `init4=0, init5=255` for a large group.
  `255` is not a plausible `_initialized` value — it means my read hit something that
  is not an OZ `Initializable` layout at all.
- Following that up **behaviourally** — calling `initialized()` on the implementation
  rather than guessing slots — **every implementation reverted or had no such
  selector.** These are Aave-lineage contracts; the proxy/initialisation model is
  `PoolAddressesProvider` + `setImplementation`, not per-proxy `initialize()`.

So the `0 uninitialised` figure is weaker than the headline suggests. What it
establishes is that **no proxy was found whose implementation is initialisable and
uninitialised under the two OZ layouts probed**. It does *not* establish that no
in-scope address is takeover-able by any other route.

That limitation is the reason the sweep is worth re-running with proper per-framework
detection (OZ v4 / v5 ERC-7201 / Aave's `setImplementation` / Bebe / Diamond) rather
than being treated as a completed clearance.

## Where this leaves the recommendation

Deployment verification is the right axis — it needs no novel bug, it covers the class
that static reading cannot reach, and it scales. This run is a partial pass over
360 addresses with a known-weak detector, not a finished clearance.

The productive next step is to finish it properly: derive each implementation's
initialisation model from its own bytecode instead of assuming OZ, and sweep the
remaining high-ceiling programmes. That converts a negative-with-caveats into either
a real finding or a defensible clearance.

## Tooling notes

- The cached catalogue's `_seg` is programme metadata, **not** the asset list, and
  does not parse (invalid escapes). Addresses must come from the live
  `cli immune scope <slug>` command. One earlier sweep script silently returned zero
  addresses because it read the cache instead.
- Nine of the 24 requested programmes returned no publishable address list
  (wormhole, chainlink, lido, gnosis, arbitrum, stacks, polymarket, curve, swell,
  pendle, morpho, eigenlayer, jupiter), so their scope is repo- or page-defined and
  needs the scope page read directly.
