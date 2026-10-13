# Hydration — $222,222, and the first substantive Rust finding

The catalog sweep ended by pointing somewhere new. `gamma-hypervisor` is not in
Hydration's scope, but Hydration's own programme is the largest in the catalog —
**maxBounty 222,222** — and it had never been touched.

## Scope

76 in-scope assets, **71 `.rs`, zero `.sol`**:

| Repo | Assets |
|---|---|
| `galacticcouncil/HydraDX-node` | 66 |
| `galacticcouncil/hydration-node` | 5 |
| `galacticcouncil/apps` | 1 |
| `galacticcouncil/Hydradx-ui` | 1 |

Pulled 69/71 in-scope files directly from `raw.githubusercontent` rather than
cloning the node — 35,849 lines across 31 pallets plus `math/`. No fork test or
local build needed to read the surface.

Surface by weight: `omnipool` (2782), `stableswap` (2356), `liquidity-mining`
(2031), `dca` (1584), `lbp` (1300), `math/stableswap` (1244), `staking` (1224),
`circuit-breaker` (1100), `ema-oracle` (1074).

## Checked and clean

**Staking access control.** `unstake` and `claim` both gate on
`ensure!(Self::is_owner(&who, position_id), Error::<T>::Forbidden)`, and `is_owner`
delegates to the NFT pallet's authoritative `owner(collection, id)` and compares —
no bypass. Arithmetic is `checked_sub` with `defensive_ok_or` throughout, and the
NFT burn is scoped `Some(&who)`. No `slash` entry point exists.

**Stableswap share math** (`math/src/stableswap/math.rs:127`) has exactly the
guard the three known-bad implementations lacked:

```rust
let updated_d = calculate_d::<D>(updated_reserves, amplification, pegs)?.checked_sub(2_u128)?;
if updated_d < initial_d { return None; }          // rejects deposits that shrink D
...
if share_issuance == 0 { Some((updated_d, fees)) } // first depositor: no division
```

`updated_d` is decremented by 2 to prevent over-minting, the imbalance fee is
deducted before the invariant is recomputed, and all of it is U256 with
`checked_*`. This is Curve stableswap done properly — the `updated_d < initial_d`
rejection is the virtual-offset equivalent that PowerToken, Hypervisor and xGamma
all lack.

## The finding: a security invariant enforced only by `debug_assert_eq!`

Hydration commit `50a55673c4`, 2026-07-15, **"ensure virtual issuance"**:

```diff
-fn debug_assert_issuance_in_sync(pool_id: T::AssetId) {
-    debug_assert_eq!(
-        ShareIssuance::<T>::get(pool_id),
-        T::Currency::total_issuance(pool_id),
-        "stableswap: virtual share issuance out of sync with total issuance for pool {pool_id:?}"
-    );
+fn ensure_issuance_in_sync(pool_id: T::AssetId) -> DispatchResult {
+    let tracked = ShareIssuance::<T>::get(pool_id);
+    let total = T::Currency::total_issuance(pool_id);
+    debug_assert_eq!(tracked, total, "...");
+    ensure!(total <= tracked, Error::<T>::UnaccountedShareIssuance);
+    Ok(())
 }
```

`debug_assert_eq!` **compiles out of release builds**, and a Substrate production
runtime is release WASM. So on every runtime deployed before 2026-07-15 there was
**no runtime enforcement** that the pallet's tracked `ShareIssuance` equalled the
actual `total_issuance` of the pool-share asset. Hydration's own test names state
this plainly — the panic tests are `#[cfg(debug_assertions)]`, and the new
production assertions are `#[cfg(not(debug_assertions))]`.

Why it matters: `calculate_shares` takes `share_issuance` as an input, so every
mint and every burn scales with the **tracked** figure. If the two desync, share
accounting is wrong in a way the runtime would not notice. The guard as written
catches `total > tracked` — shares existing that the pallet does not know about.

### Honest exploitability read

**I have not demonstrated a permissionless attack, and I do not think one is
likely.** The obvious desync routes are `pallets/tokens` `set_balance` and
`force_transfer`, both root-only in Substrate. So the realistic triggers are
migration or governance actions, not an unprivileged attacker.

That does not make it nothing. It means:

- A security-relevant invariant was enforced **only in debug builds** for the
  lifetime of the pallet, and that was invisible until someone added a release-mode
  test and found the production path missing. That is a real and reportable
  process failure even where the trigger is privileged.
- The fix on `master` closes it, so **the reportable target is not the file** — it
  is any *deployed* runtime still predating 2026-07-15.

## RESOLVED — the live deployment is fixed; finding is dead

Step 1 has been answered, without a parachain RPC at all.

**Hydration governance, via Subsquare:** referendum **#413 "Runtime upgrade
v53.0.0" — Executed.** Also #412 (moving apyUSD/PRIME feeds and four stablepool
pegs onto CheckedOracles) executed, and #419 "Dwellir — Public RPC Endpoint Service
Q3 2026" still *deciding* — which explains why no public Hydration endpoint exists:
the chain is procuring a paid one.

So the live runtime is v53.0.0, published 2026-09-22. Checking the tags directly
rather than inferring from dates:

| tag | `ensure_issuance_in_sync` | `ensure!(total <= tracked)` |
|---|---|---|
| v53.0.0 | present | 1 |
| v52.0.0 | present | 1 |
| v49.4.0 | present | 1 |
| v49.3.0 | present | 1 |

**Every current release contains the production guard.** Combined with #413 being
executed, the deployed runtime enforces the invariant. **The finding is not
exploitable against Hydration's live chain and is not a submission.**

Note the method: the deployment question was answered from governance records plus
tag contents, after the RPC route closed. Two dead ends worth recording, since they
are the obvious next things to try:

- Alchemy does not serve Substrate chains at all — empty body for
  `state_getRuntimeVersion` — so rotating those keys cannot help with Hydration.
- The relay-chain route (`ParachainHost` runtime API → parachain validation
  function) is sound in principle but not reachable here. Runtime APIs are exported
  **by hash** (`0x37c8bb1350a9a2a8`, …), so `state_call` needs the 3-param
  `(api_hash, method, data)` form; `rpc.polkadot.io`'s legacy endpoint only accepts
  `(method, data)` and rejects it with *"invalid hex character: p"*. Deriving
  `spec_version` from raw WASM would additionally need a WASM runtime, which is not
  a Python dependency this project should take on for one question.

Hydration also runs a **parathread**, not a collator, per Subscan — so even the
validation-function window is shorter than for a normal parachain.

## What would still be needed, if the scope ever changes

Nothing for the live chain. The remaining value in this code is as a *pre-merge*
observation: a security invariant on the share ledger was enforced only by
`debug_assert_eq!`, which does not exist in production WASM, and nobody noticed for
the pallet's lifetime. That pattern — a `debug_assert` standing in for an `ensure`
on a value-dependent invariant — is worth grepping for across Substrate pallets in
general, and `cs_substrate.py` now makes the deployment side answerable wherever a
parachain endpoint exists.
`core/cs_substrate.py` reads a Substrate chain's runtime identity over ordinary
HTTP JSON-RPC - `state_getRuntimeVersion` for spec_name/spec_version/apis,
`state_call("Core_version")` as an independent second route, and
`state_getStorage(":code")` for the WASM blob so it can be hashed. The two routes
are cross-checked against each other and disagreement is reported rather than
silently resolved, because a lagging archive node will happily serve an old
version from a state query while `Core_version` executes against the real runtime.

Verified working against the Polkadot relay chain: `polkadot` / `parity-polkadot`,
specVersion 2005000, both routes agreeing, confirmed on two independent endpoints.
14 offline tests.

**Hydration itself remains unread.** Alchemy does not serve Substrate chains at all
- it returns an empty body for `state_getRuntimeVersion` - so the rotated keys do
not help here. No Hydration parachain endpoint resolved from this environment:
`rpc.hydration.cloud` does not resolve, and the dwellir/onfinality/publicnode
candidates either fail or only serve the relay chain. One public node also
withholds `:code` at `latest` while serving historical blocks, which is why
`describe_runtime` reports `code_available: False` and omits `code_hash` rather
than fabricating one.

So the tooling gap is closed; the data gap is not. Hydration needs a reachable
parachain RPC endpoint.

## Verdict

Real finding, well-evidenced, **not yet a submission**. The code-level claim is
solid: a security invariant on the stableswap share ledger was enforced only by
`debug_assert_eq!`, which does not exist in production WASM. Everything above it —
the current code, the tests, the commit — is verified against upstream. What is
missing is deployment evidence and a trigger, and I would rather say that plainly
than dress it up.

The rest of the surface is well-defensive. Hydration is heavily audited and it
shows: `checked_*` everywhere, `defensive_ok_or`, explicit rounding, NFT-authoritative
ownership. The remaining 35k lines are a multi-day read, not a multi-hour one.