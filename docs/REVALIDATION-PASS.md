# Re-validation pass — prior conclusions vs corrected tooling

Triggered by retracting `extract_selectors` and `classify_reachable`, both of which
had produced *confident* wrong answers. Anything triaged with the old methods is now
suspect, so this pass re-checks what can be re-checked.

## Method note — what is and isn't sound

| Technique | Sound? |
|---|---|
| EIP-1967 / EIP-1967-beacon slot reads | **Yes.** Fixed keccak of a constant string, no heuristics. |
| Sourcify `runtimeMatch` | **Yes.** Proves bytecode matches verified source. |
| Numeric invariant checks against live `eth_call` | **Yes.** Strongest form. |
| `extract_selectors` (PUSH4 literal scan) | **No — retracted.** Range-dispatch bounds, not selectors. |
| "reverted, therefore the function exists" | **No.** Inverts on any contract with a fallback. |

## mETH — re-verified, sound

The submitted finding's evidence was re-established behaviourally. Both load-bearing
claims survive; details in [`METH-permit-frontrunning.md`](METH-permit-frontrunning.md).
The proxy's EIP-1967 slot still resolves to the implementation the finding was written
against.

## Gamma — not re-validatable, and that is the finding

My earlier note read: *"All three in-scope addresses are direct, non-proxy
contracts."* The **proxy part is sound methodologically** — corroborated here on the
two canonical Uniswap V3 addresses the repo references, both correctly `DIRECT`:

```
chain 1  0xE592427A0AEce92De3Edee1F18E0157C05861564  12070B  DIRECT  UniswapV3 SwapRouter
chain 1  0x1f98431c8ad98523631ae4a59f267346ea31f984  24535B  DIRECT  UniswapV3 Factory
```

But **the three Gamma addresses themselves are gone.** Not in `gamma-hv/hypervisor`,
not in the cached Immunefi catalog (`gamma` no longer appears at all, consistent with
the programme having been delisted), and never written into a committed doc. The only
other two addresses in the repo — `0x07ebc28f…` and `0x92f8964e…` — have **no code on
any of mainnet / optimism / arbitrum / polygon / celo**, so they are not deployed
Gamma contracts either.

**Correction, 2026-10-02.** "Lost" was wrong. The addresses are in the cached Immunefi
catalogue under `_seg.assets`; my grep missed them because `name` is null and only
`slug`/`assets` carry the data. Gamma is **live** (`pausedAt: null`, `endDate: null`,
**maxBounty $50,000**) with xGamma `0x26805021…`, Hypervisor `0xa8076ae3…`, UniProxy
`0x83de646a…`. The lesson below stands - the addresses should have been committed when
the conclusion was - but the conclusion is in fact re-checkable. See
[GAMMA-SWEEP.md](GAMMA-SWEEP.md): re-running the 21 classes found a real no-virtual-offset
pattern in the Hypervisor share math that the original proxy-only check never examined.

**The process gap is the actual finding.** IPOR and mETH have their reasoning, PoCs
and deployed evidence committed to `docs/` and `poc/`. Gamma has a cloned repo, some
audit PDFs, and a conclusion that exists only in a working note. That asymmetry is how
a wrong conclusion survives unnoticed.

Going forward: a conclusion that decides whether a target is closed is not finished
until the addresses and the evidence are committed. Recording "closed" without the
addresses makes the decision unauditable.

## Side effect — Alchemy removal, repo-wide

The disabled keys broke three things, now fixed:

- `ChainScope/.env` — five keys commented out; `core/cs_rpc.py` and
  `tools/econ_harness/script/run_drift.py` already fell back to publicnode.
- `gamma-hv/hypervisor/hardhat.config.ts` — concatenated the env var directly into the
  URL, so an undefined key produced `.../v2/undefined` and an opaque failure instead
  of falling back. Now routed through an `rpcUrl()` helper that prefers an
  authenticated endpoint and otherwise uses a verified public node.

No other file in the workspace referenced the keys.

## Recommended follow-up

The Gamma lesson generalises: **targets closed without committed evidence cannot be
re-opened or re-checked.** Two options, in order of value:

1. Re-triage Gamma properly — fetch the live programme scope, commit the addresses,
   then re-run the proxy/function-surface analysis with the corrected tooling.
2. Sweep the workspace for other targets whose conclusions have no committed
   evidence, and either commit that evidence or mark the conclusions as unverified.