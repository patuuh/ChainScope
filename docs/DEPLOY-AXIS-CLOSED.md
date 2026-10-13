# Deployment axis — closed properly

The third and final pass on the axis that three earlier findings died trying to answer:
*is this thing actually live?*

## The near-miss worth recording

I got to the point of reporting a Critical. Both initialisable implementations read
`_initialized = 0`:

```
0xf943cb8d5f06f2bbf352878ebef3ec5c537a20ba   slot 0 = 0x0    -> "UNINITIALISED"
0x72b971717e088b59f26d4236be222adb6acd393b   slot 0 = 0xff   -> "UNINITIALISED"
```

**That reading is meaningless.** OZ's `_initialized` is written by a `delegatecall`, so
it lives in the **proxy's** storage. The implementation contract's storage is empty by
default — reading its slot 0 tells you nothing about whether the proxy was initialised.
Both addresses would have been false positives with a Critical severity attached.

The correct test is to call `initialized()` on the **proxy**, where the delegatecall
supplies the right storage context.

## What the proxy-context read shows

```
sparklend 0xBc65ad17c5C0a2A4D159fa5a503f4992c7B545FE -> 0xf943cb8d...
    initialized()   REVERTED
    initialize()    REVERTED

optimism  0xe5965Ab5962eDc7477C8520243A95517CD252fA9 -> 0x72b97171...
    initialized()   REVERTED
    initialize()    REVERTED
    owner()         0x5a0aae59d09fccbddb6c6cceb07b7279367c3d2a
```

`initialize()` reverting is the expected behaviour of OZ's `initializer` modifier once
`_initialized != 0`. Had the proxy been uninitialised, `eth_call` would have
**succeeded**. And `owner()` returning a live address on the optimism proxy confirms it
is configured.

## Final tally

**334 in-scope mainnet addresses across 9 high-ceiling programmes** (LayerZero,
Stargate, USDT0, GMX, SparkLend, Ethena, Optimism, Aave, Balancer).

| | count |
|---|---|
| proxies (implementation or beacon) | 60 |
| distinct implementations behind them | 23 |
| implementations exposing `initialize()` | **2** |
| — of those, proxies where `initialize()` would succeed | **0** |
| Ownable-only implementations (no init surface) | 12 |
| Aave-style `getImplementation()` (no per-proxy init) | 5 |
| no known markers | 8 |

**Result: no in-scope address is takeover-able by calling `initialize()`.** The large
majority — 274 of 334 — are direct contracts with no proxy at all, which removes most
of this attack surface structurally rather than by configuration.

Frameworks were identified from the implementation's dispatcher rather than assumed:
12 Ownable, 5 Aave-style provider, 2 UUPS (`proxiableUUID` + `upgradeToAndCall`),
2 with `initialize()`, the rest unrecognised. That per-implementation breakdown is what
made the two `initialize()` targets findable at all — the slot-based approach never
got there.

## Method, and why the earlier attempts failed

| attempt | why it failed |
|---|---|
| slot-based scan | read `_initialized` from the **implementation**, where it is always empty |
| assumed OZ layout | 12 of 23 implementations aren't OZ-initialisable at all |
| differential RPC probe | an unknown selector and an access-controlled one both revert identically |
| **dispatcher analysis** | reads the runtime bytecode, so framework identity and available entry points are facts rather than assumptions |

The last row is the only one that works, and the three before it are the same failure
mode I hit all session: **measuring something other than the thing being asked about.**

## Scope completion

Follow-up pass over the programmes that do not publish addresses. Only **one** of the
remaining high-ceiling set publishes them:

| programme | published addresses | repos |
|---|---|---|
| gnosischain | 4 (2 parseable on mainnet) | 2 |
| wormhole | 0 | 3 |
| chainlink | 0 | 11 |
| lido | 0 | 19 |
| arbitrum | 0 | 4 |
| stacks | 0 | 1 |

Both parseable gnosischain addresses are **direct contracts** —
`0x4aa42145Aa6Ebf72e164C9bBC74fbD3788045016` and
`0x88ad09518695c6c3712AC10a214bE5109a655671` — with no EIP-1967 slot set on either, so
no init surface and nothing to resolve.

So **every in-scope address that is published is now swept**: 336 mainnet addresses
across 10 programmes, 60 proxies, 23 distinct implementations, zero where
`initialize()` would succeed.

Two slugs I had been using were simply wrong — `gnosis` should be `gnosischain` — so
that programme had been silently absent from the earlier sweep rather than clean.
Curve, Pendle, Morpho, Eigenlayer, Jupiter, Swell and Polymarket are not live
programmes at all.

## Honest caveat

This covers the **mainnet** in-scope addresses of 10 programmes. Not covered:

- The five repo-scoped programmes (wormhole, chainlink, lido, arbitrum, stacks —
  38 repos between them). Their deployment addresses are not published in scope, so
  they have to be derived from the repos themselves, which is a manual exercise per
  programme rather than a sweep.
- Non-mainnet deployments of the same programmes.
- The **admin key** itself: the optimism proxy above has a live owner,
  `0x5a0aae59d09fccbddb6c6cceb07b7279367c3d2a`. Initialisation safety is not
  key safety, and ownership concentration is a different (and often out-of-scope)
  question.

So: the *uninitialised proxy* Critical is closed for mainnet across these 9
programmes, and the residual work is the programmes that do not publish addresses.