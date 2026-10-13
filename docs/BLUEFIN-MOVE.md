# Bluefin Coin Contracts — read in full, and the detector gap it exposed

The first real HackenProof Move target run through `cs_move.py`. Target chosen by
the asymmetry analysis: **$15,000 ceiling with 47 prior reports**, against $300,000
programmes carrying 418–428.

Repo: `fireflyprotocol/bluefin-coin-contracts`. The whole contract is
**73 lines in one file**, `sources/blue.move`, so it was read in full rather than
pattern-matched — which is the point of a target this size.

## The finding: mint authority is unfrozen

```move
struct BLUE has drop {}

struct TreasuryCapHolder<phantom T> has key, store {   // <-- `store`
    id: UID,
    treasury: TreasuryCap<T>                            // <-- unbounded mint authority
}

const MAX_SUPPLY: u64 = 1_000_000_000_000_000_000;      // 1 billion

fun init(witness: BLUE, ctx: &mut TxContext) {
    let (treasury_cap, metadata) = coin::create_currency<BLUE>(witness, 9, b"BLUE", ...);
    transfer::public_share_object(metadata);
    let holder = TreasuryCapHolder { id: object::new(ctx), treasury: treasury_cap };
    transfer::public_transfer(holder, tx_context::sender(ctx))    // <-- to sender
}

public entry fun mint_tokens(
    holder: &mut TreasuryCapHolder<BLUE>, amount: u64, recipient: address, ctx: &mut TxContext
) {
    let total_supply = coin::total_supply(&holder.treasury);
    assert!(total_supply + amount <= MAX_SUPPLY, EMaxSupplyReached);
    coin::mint_and_transfer(&mut holder.treasury, amount, recipient, ctx)   // recipient unchecked
}
```

**The contract itself is sound.** Two things that look like bugs and are not:

- `total_supply + amount` is u64 arithmetic, but **Move aborts on overflow**, so the
  max-supply check cannot be bypassed by wrapping.
- `mint_tokens` has no `ctx.sender()` check — but object ownership *is* Sui's
  authorization. Only the holder's owner can supply `&mut TreasuryCapHolder`.

**The weakness is custody.** `TreasuryCapHolder` has `store` (freely tradable),
is `public_transfer`red at init, and **nothing in the repo ever calls `freeze`**.
Meanwhile the repo's evident intent is multisig custody — `multi-sig-wallet.json`
is a **2-of-3** — but `multisig/transfer-treasury-cap.ts` moves the `TreasuryCap`
out of the multisig to a single address:

```typescript
const RECEIVER = "0x2183df5aaf6366e5445c95fa238fc223dbbda54b7c363680578b435f6571a29";
txb.transferObjects([TARGET_DEPLOYMENT.TreasuryCap], RECEIVER);
```

`0x2183df5a…` is *also* one of the three multisig signers. Compromise that one key
and up to a billion BLUE can be minted to any address, with `MAX_SUPPLY` never
meaning anything.

**Scope caveat, and it probably kills this.** HackenProof scopes `sources/`; the
transfer is in `multisig/`. So the deploy-time custody weakness is likely out of
scope, and the contract itself has no exploitable bug. Worth noting for their
operational security regardless — and `coin_registry.create` in the Sui framework
is the same shape (`@0x0`-gated, so lower risk).

## What the target found in my tooling instead

The detector returned **zero** on a 73-line token contract whose entire security
rests on a capability. Three sequential causes, each of which had to be traced
rather than guessed:

1. **M3 keyed on `UpgradeCap` only.** That is the *package upgrade* authority.
   `TreasuryCap` — the *mint* authority, which is the one that matters for a token
   — was invisible. Found by running against a real target.
2. **M3 matched only `public`/`entry` funs.** Move requires `init` to be
   *private*, and `init` is exactly where a `TreasuryCap` is created and handed to
   the deployer. Every other detector in the suite had that blind spot; this one
   cost four iterations to find.
3. **M3 keyed on the capability *type name*.** `init`'s body never contains the
   string "TreasuryCap" — it calls `coin::create_currency` and binds the result
   to a local `treasury_cap`. The right anchor is the capability *operation*.

After the fix: **1 hit on Bluefin at `blue.move:29 fn=init`** — the correct
location — and 1 on the 117-file Sui framework (`coin_registry.create`, which is
genuinely the same shape but `@0x0`-gated).

17 `cs_move` tests, **916 total**. Each of the three failures is now pinned by a
test, the last one reproducing Bluefin's exact structure.

## The honest note

Four iterations on M1 and four on M3 is the same signal twice. These are regexes
solving a problem that wants a parser — Move's structure is regular enough that a
syntactic pass would get this in one step. The detectors are useful for triage and
unreliable as a verdict, which is the same lesson as `class 20` and `class 11` in
the Solidity scanner, arriving in a new language.