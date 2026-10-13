# Class 6 — cross-chain replay / signature malleability, across the Immunefi corpus

The one Critical-class pool never examined in this session. Immunefi is saturated
with bridges — LayerZero $15M, Stargate $10M, Hyperlane $2.5M, Wormhole $1M — and
replay of a signed message to authorise value transfer is Critical by definition.

## Distribution

45 strong hits, all from the shape-based pattern
`ecrecover\s*\(\s*[^,]+,\s*v\s*,\s*r\s*,\s*s\s*\)` — not a name match, so it navigates
reliably:

| target | strong |
|---|---|
| AAVE (incl. Sparklend, an Aave fork) | 32 |
| Gnosis / gearbox / EtherFi / Ethena / Silo / Origin / Optimism / ENS | 13 |

## Triage — and a false positive in my own check

My first pass reported **43 of 45 as `s`-unbounded**, which would have been a
Critical-tier finding. It was wrong, twice over:

1. My window was 14 lines above the call; the check sits 8 lines above it.
2. My regex for the mitigation didn't match OZ's actual constant form.

With the real constant (`secp256k1n/2`) and a 30-line window, **Aave's
`StakedTokenV3Flattened.sol:869` is correctly bounded** — it vendors OZ's
`ECDSA.tryRecover`:

```solidity
if (uint256(s) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) {
    return (address(0), RecoverError.InvalidSignatureS, s);
}
address signer = ecrecover(hash, v, r, s);
```

## The genuine unbound sites, and why they still aren't findings

`CurrentStakedTokenV3Flattened.sol` (and `StakedTokenV2.sol`) contain **zero**
`s`-bounding anywhere in the file, and call `ecrecover` raw:

```solidity
require(owner == ecrecover(digest, v, r, s), 'INVALID_SIGNATURE');
unchecked { _nonces[owner] = currentValidNonce + 1; }
```

**Malleability is real there and still grants nothing.** Both `(v,r,s)` and
`(v⊕1, r, n−s)` recover the *same* signer over the *same* digest. Replay protection
here is the **nonce**, which is consumed unconditionally on success — so the
malleable form is already dead on arrival. The `s` bound is hygiene and signature
uniqueness, not a security control in this design.

The naming also suggests these are historical snapshots: `Current*` versus the
newer `StakedTokenV3*`, which added the bound. If so this is a fixed hardening
change rather than a live issue.

## Verdict

**No finding.** Two independent reasons, and the distinction matters:

- The sites that bound `s` are correct and I initially mis-flagged them.
- The sites that don't bound `s` are protected by nonce-based replay protection, so
  malleability is unexploitable there.

**What this adds to the session's severity picture.** Class 6 was the last
Critical-class pool I had not touched, and it produced the same outcome as every
other one: a scanner finding that resolves to nothing on reading. Critically, the
*near-miss* was mine — a 14-line window and a wrong constant regex turned 43 correct
sites into a Critical claim. That is the fifth time this session a pattern of mine
produced a confident wrong answer, and it is a stronger argument for the
verify-by-execution discipline than any finding would have been.

Remaining unexamined Critical-class pools: class 1 (uninitialised proxies, 387
strong — Gamma cleared on-chain, the rest never read) and class 13 (bridge proof
verification, 39 strong — the raw count is inflated by relayer and test code, so the
39 is the real number and it is genuinely unread).
