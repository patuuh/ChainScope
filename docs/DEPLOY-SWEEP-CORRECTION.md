# Deployment verification — corrected results and why the axis is still open

Follow-up to `DEPLOY-SWEEP.md`. That document reported "68 proxies, 0 uninitialised" as
a partial negative. **Both halves of that needed correcting**, and the corrections are
the substance of this note.

## Correction 1 — I fabricated function selectors

`cs_init.py` originally hardcoded six selectors. **Three were wrong, written from
memory rather than resolved:**

| function | I had | actual |
|---|---|---|
| `initialized()` | `0xf7a05767` | `0x158ef93e` |
| `initialize()` | `0xc4d66de8` | `0x8129fc1c` |
| `setImplementation(address)` | `0x5c60da1b` | `0xd784d426` |
| `diamondCut(...)` | `0x1f931c1c` | `0x211cf82d` |

I had already reported that "every implementation reverted or lacked the selector"
and drawn a conclusion from it. **That conclusion was false — I was calling a selector
that does not exist.** Selectors are now resolved via `cast sig` at import time, which
removes the class of error.

## Correction 2 — every direct contract was counted as a beacon proxy

The first sweep reported **274 beacon proxies** out of 334 mainnet in-scope addresses.
That was a bug in `classify`: it set `model = "beacon"` whenever the implementation
slot was empty, **without checking the beacon slot was non-zero**. Every ordinary
direct contract matched that branch.

Aave's three in-scope addresses show it plainly:

```
0x8A32f49F...35c7D   impl 0x00  beacon 0x00  ->  direct
0xEFFC18fC...Ce31    impl 0x00  beacon 0x00  ->  direct
0x464C71f6...d6e18   impl 0x83b7ce...  beacon 0x00  ->  implementation proxy
```

Two direct, one implementation proxy. No beacons at all.

## What is actually established

**334 mainnet in-scope addresses across 9 high-ceiling programmes.**

| | |
|---|---|
| confirmed UNINITIALISED implementation | **0** |
| confirmed INITIALISED | **0** |
| proxy with a readable init function | **0** |
| inconclusive | all proxy candidates |

The probe itself is validated — it correctly resolves `owner()` on three known
contracts (returns data, confidence high) and correctly reports `initialized()` absent
on them. So the method works.

The problem is that **for the implementations that exist here, every selector probes
"indistinguishable from an unknown selector"** — the contract has no fallback and
behaves the same either way. That is genuine *inconclusiveness*, not absence, and my
detector reports it as such rather than calling it clean.

## Honest status of the axis

**Not cleared.** The correct statement is:

> No in-scope mainnet address across these 9 programmes was found to be a proxy whose
> implementation is initialisable and uninitialised. The large majority of in-scope
> addresses are direct contracts rather than proxies, which removes most of the attack
> surface for this class. What remains could not be resolved by RPC probing, because
> those implementations do not expose a readable initialisation entry point.

To actually close it you need **dispatcher analysis of the implementation bytecode** —
find the selector in the runtime rather than calling it — rather than differential
RPC probing. That is a small, self-contained piece of work and the tooling for it
(`cs_re.extract_selectors`) already exists and was validated earlier.

## The pattern worth naming

Four headline numbers this session turned out to be my own bugs rather than findings:
the 274 beacons, the fabricated selectors, the double-scored `floatToWei` ideal, and the
independently-bounded `min_`/`max_` pair. In every case the code under test was right.

That is now the single most reliable observation available across roughly twenty hours
of hunting: **my measurements need independent validation before they are believed, and
RPC probing of unknown contracts proves absence far less often than it appears to.**