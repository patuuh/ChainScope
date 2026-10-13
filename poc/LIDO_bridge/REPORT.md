# Lido `L1OutboundDataParser.from` — tested

## Result

`L1OutboundDataParser.decode` branches on `msg.sender`:

```solidity
if (msg.sender != router_) {
    return (msg.sender, _parseSubmissionCostData(data_));      // safe
}
(address from, bytes memory extraData) = abi.decode(data_, (address, bytes));
return (from, _parseSubmissionCostData(extraData));            // calldata decides
```

Six tests, all passing, executed against the real library (solc 0.8.10, matching the
repo's exact pragma):

| test | establishes |
|---|---|
| `test_directCaller_isAlwaysDebited` | **direct path binds `from = msg.sender`** — calldata cannot redirect it. The safety property holds. |
| `test_directPath_rejectsRouterFormat` | the direct path rejects the router encoding outright rather than silently honouring it |
| `test_asRouter_fromComesFromCalldata` | **as router, `from` is whatever calldata says** |
| `test_asRouter_acceptsArbitraryAddress` | **any arbitrary address is accepted — not a whitelist** |
| `test_innerExtraDataMustBeEmpty` | the inner `extraData` emptiness guard holds |
| `test_malformedInnerReverts` | malformed inner encoding reverts rather than defaulting to zero cost |

**Settled by execution:** the library/gateway imposes **no constraint of its own** on
`from` when the caller is the router, and will accept an arbitrary address. The only
remaining protection on the gateway's `safeTransferFrom(from, ...)` is the ERC20
allowance.

## Still unclosed

Whether Arbitrum's canonical `L1GatewayRouter` forwards user-controlled bytes into
that slot. That contract is not in `lido-l2`, three plausible paths 404'd, the
GitHub tree API returns 401, and Lido publishes zero in-scope addresses so the
deployed `router` value cannot be read on-chain either.

A Critical requires BOTH: a router that forwards attacker-chosen `data_`, AND a user
with a live allowance on that token. The second is realistic (anyone who has bridged
has approved the gateway). The first is not established.

## Two harness traps worth recording

Both produced "confirmed" results that were wrong, and both are the same class of
error as this session's other measurement failures:

1. **`address(this)` as the router silently took the router branch.** The parser
   branches on `msg.sender` inside the library, which is whoever calls `decodeAs` — the
   test contract. Passing `address(this)` as `router_` made `msg.sender == router_`, so
   the two "direct path" tests were actually exercising the router path. Fixed by
   passing a distinct `SOME_OTHER_ROUTER`.
2. **forge-std is unusable here.** `lido-l2` pins `pragma 0.8.10` exactly and
   forge-std requires >=0.8.13, so they cannot share a compilation unit. The tests use
   hand-rolled assertions and a manually declared `Vm` interface instead.

Also worth noting: `vm.store` into `BridgingManager`'s proxy slot (needed to flip
`whenDepositsEnabled` on the full gateway) silently did nothing in this setup. Testing
the library directly avoided it, which is also the more honest test — the proxy slot is
deployment wiring, not the question being asked.

---

## 21-class recon on lido-l2, and the two class-1 hits

`cli veck scan contracts/` over 36 files: **13 hits, 3 strong** — all class 1
(uninitialised proxy), plus 4 weak class-7, 3 weak class-9, 3 weak class-13.
No class 4/15/16/18/19 hits, so no rounding, flash-mint, flash-loan, slippage or
vault-donation candidates here.

Both strong hits are guarded, and neither is a finding:

| contract | guard |
|---|---|
| `BridgingManager.sol:37` | `if (s.isInitialized) revert ErrorAlreadyInitialized();` — explicit reinit protection |
| `token/ERC20Bridged.sol:33` | no explicit flag, but the setters it calls enforce it: `_setERC20MetadataName` reverts with `ErrorNameAlreadySet()` when non-empty, so the pair can only ever be set once |

The third strong hit is `proxy/stubs/VersionizedImplementationStub.sol` — a test stub,
not production.

`ERC20Bridged.initialize` is the interesting one: **`external`, unguarded, no
`isInitialized` flag**, which is exactly the shape class 1 exists to catch. It survives
only because the metadata setters it calls refuse to overwrite. That is a real property
of the code and it held on reading, but it is load-bearing on an *empty-string* check
rather than an initialisation flag — worth noting for anyone extending the token, since
a future setter that bypasses the empty check would re-open a rename path on a bridged
token (a phishing vector on exchange listings).

Not a finding. Clean negative, and the fourth time this session a scanner hit
required reading before it could be called one.
