# LayerZero packet proof verification — the $15M path, read in depth

LayerZero's programme is the highest Immunefi ceiling (`maxBounty 15,000,000`) and its
`updatedDate` moved to 2026-10-02 — today. Scope is 10 addresses and 4 repos; several
addresses are third-party (`0xc02ab410…` is canonical WETH, `0xD231084B…` is Uniswap V3's
position manager), so the attack surface is the repos. `devtools` (OApp/OFT) was already
cleared today. This is the core `LayerZero` repo — where packet verification actually lives.

`contracts/` is 37 files. The critical ones are the proof layer: `MPTValidator01` (172),
`RLPDecode` (387), `Buffer` (172), `FPValidator` (143), `LayerZeroPacket` (151).

**21-class recon: zero strong hits.** 115 weak class-13 (the MPT/receipt verification
paths themselves), 34 weak class-7, 2 weak class-9. So this is a read, as expected on a
bridge core.

## The chain of trust, layer by layer

**1 — Receipt root is consensus-anchored.** `validateProof` takes `_receiptsRoot` from the
caller, but it is the L1 receipts root, which consensus commits to. Every subsequent
check is relative to that root.

**2 — Each proof node is hash-committed *before* it is parsed:**

```solidity
require(hashRoot == keccak256(proofBytes), "ProofLib: invalid hashlink");
item = RLPDecode.toRlpItem(proofBytes).safeGetItemByIndex(paths[i]);
if (i < proof.length - 1) hashRoot = bytes32(item.toUint());
```

This ordering is the whole ballgame. Bytes cannot be supplied and reinterpreted; the
node is committed by hash first, then walked. Proof size is also bounded
(`paths.length == proof.length`, `proof.length > 0`).

**3 — RLP access is bounds-checked.** `safeGetItemByIndex` enforces `isList`,
`idx < numItems(item)`, and a final `require(memPtr + dataLen <= endPtr, "RLP item
overflow")`.

I looked specifically for the classic RLP decoder bug — a long-string/long-list length
prefix (`0xb8–0xbf`, `0xf8–0xff`) declaring more data than the buffer holds.
`_itemLength` does **not** bounds-check `dataLen`; it computes
`dataLen := div(mload(memPtr), exp(256, sub(32, byteLen)))` and returns it unvalidated.
But the consequence is bounded: `numItems` would under-count, the walk in
`safeGetItemByIndex` would push `memPtr` past `endPtr`, and the **final bounds check
reverts**. The out-of-bounds `mload` reads garbage from memory, but these are `pure`
functions using `mload` only — there is no `mstore`, so there is nothing to corrupt.
Unreachable as a forgery, and it reverts rather than accepting.

**4 — The packet comes from the committed log.** `log.data` is read from the verified
receipt, and `LayerZeroPacket.getPacketV2(log.data, _remoteAddressSize,
log.contractAddress)` derives `srcAddress` from the log's contract address — so the
source is bound to the chain that emitted the log, not chosen by the caller.

**5 — Stargate payloads are hardened on the way through.** `_secureStgPayload` rewrites
`toAddress` when the target is not a contract (`extcodesize == 0`), and
`_secureStgTokenPayload` redirects zero-address recipients to `0x…dEaD`. Both are
fail-safe rewrites of attacker-shaped payloads, not trust decisions.

## Verdict

**No finding.** The design is sound: a consensus-anchored root, hash-before-parse node
commits, explicit RLP bounds checks, and a source address derived from the log rather
than the caller. The one place with an unbounded length read reverts before it can
affect a result and cannot corrupt memory.

**What this is, precisely:** a deep static read, not an executed proof. For a negative
result that is legitimate evidence — there is no forgery to demonstrate. But I want to be
plain that a positive claim from this path would require a PoC, and I have not written
one. The session's only executed exploit remains mETH.

## Honest limit of the approach

LayerZero's core verification logic is not new — the MPT walk, the RLP decoder and the
packet layout have been audited repeatedly, and the post-Cancun design deliberately
pre-commits proof nodes before parsing. Reading it will not find what four prior audit
rounds and a $15M programme missed. What *would* pay is the layer I cannot see from
source: the deployed endpoints' configuration, the DVN/executor trust assumptions, and
whether the **in-scope addresses** (`0x4d73adb7…`, `0xbb2ea70c…`, `0x589dedbd…`) are
running code that matches these repos. That needs on-chain bytecode comparison — which
`cs_re`/`cs_substrate` can do, and which is the same deployment-verification gap that
closed three earlier findings.
