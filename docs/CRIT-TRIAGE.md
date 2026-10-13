# Critical-first triage — class 12 (delegatecall) across the portfolio

Scoping to Critical with High accepted, rather than splitting attention three ways.
Delegatecall was the right class to start on: *delegatecall to a user-controlled
target* is the canonical Critical in Solidity, and it was the largest unreviewed
strong pool after class 11 — **109 strong hits across 16 targets**, of which only
Gamma had ever been examined (and cleared: both routers route to `immutable`
addresses behind a reverting selector ladder).

## Verdict: zero Critical, zero High

| Site | Why not |
|---|---|
| **1inch `OrderMixin.sol:73`** | `simulate()` **always reverts** with `SimulationResults(success, result)`. No state write can persist, so a user-supplied `target` buys return data and nothing else. |
| **Royco `RoycoDayEntryPoint.sol:151`** | `address(this).delegatecall` — `msg.sender` preserved (the code says so). Funds pull from `msg.sender`, `_user` receives shares. A permissionless settler for pre-authorized requests, payable only with the caller's own funds. |
| **EtherFi `WromTranseiverFlat.sol:569`** | OpenZeppelin `Address.functionDelegateCall`, copied. `internal` utility. |
| TheGraph, GMX, ENS | `address(this).delegatecall(data[i])` — self-delegatecall **preserves `msg.sender`**, so multicall grants no privilege. Low, not High. |
| USDT0, Silo | OZ `Address.functionDelegateCall` library code. |
| Origin, Gnosis, SparkleEnd, ipor, mux | Standard proxy/upgrade patterns. ipor cleared earlier this session. |
| Katana `VaultBridgeToken_patched` | `initializer_` is a fixed Wormhole address. |
| **Optimism `DummyCaller.sol:17`** | In `scripts/` — a test helper, not production. |

The 1inch case is worth keeping: it is the exact shape of a Critical
(user-controlled delegatecall target) and it is safe only because the function
discards its own effects. Reading the pattern without the `revert` would have been a
false positive.

## The pattern across both of today's full sweeps

Two classes, 22 targets, ~490 strong hits, and the headline numbers were both
artifacts of matching *canonical names* rather than risk:

- class 11: `healthFactor` — Aave's variable name (AAVE 51 → 0)
- class 20: `EntryPoint` — matched Royco's own `RoycoEntryPoint` (252 → 0)
- class 12: 109 strong — the top 16 are all safe idioms or non-production code

**Counting was never the bottleneck.** Every candidate this session died on reading,
and one died on the target's own catalogue.

## Where a Critical can still plausibly be

Having cleared delegatecall portfolio-wide, the classes whose *shape* can produce a
Critical rather than a naming artifact, and which remain unexamined:

1. **class 1 — uninitialised proxies, 387 strong.** A live uninitialised
   implementation proxy is Critical (take ownership, upgrade to arbitrary code).
   The Gamma instances were verified initialised *on-chain*; these 387 have not been.
   This is the largest remaining pool and the highest ceiling. Caveat established
   earlier: the class also over-fires on interface declarations, so the work is
   filtering, not reading.
2. **class 13 — bridge proof verification, 39 strong.** A forged delivery proof is
   Critical by definition: unbacked minting. The raw count is high (2193) but almost
   entirely relayer and test code; 39 strong is the real number.
3. **class 6 — cross-chain replay / signature malleability, 45 strong.** Replay of a
   signed message is Critical where it authorises value transfer.

Class 13 and class 6 are small enough to read properly. Class 1 is the big one, and
it needs the on-chain verification discipline that cleared Gamma — read the EIP-1967
slot, not the source.
