# Critical-First Triage Checklist

How to spend a triage session so the effort is aimed at what actually pays.

**The bar.** A Critical on Immunefi / Sherlock / Cantina requires one of:
- loss of protocol funds (drain or insolvency)
- permanent locking of funds
- unrecoverable governance takeover

Everything below that — gas waste, temporary griefing, best practice, accounting
discrepancies with no extraction path — is **not payable**. Several programs
also list P5 as out of scope entirely.

---

## 1. Rank targets before reading code

```bash
python3 -m cli immune list --top 20            # Immunefi
python3 -m cli immune list --fresh-scope --fresh-days 30
python3 -m cli immune keizo --top 15           # fresh + payout + low dedup load
python3 -m cli immune meta <slug>              # READ THIS FIRST: published audits
```

`immune meta` is the step people skip and then regret. A program with 4 published
audits has most of its surface documented, and a report matching any of them is
ineligible regardless of merit.

**Prefer, in order:**
1. Recently-updated scope (a fresh asset list is unclaimed ground)
2. Primacy of Impact programs (unlisted assets still count — check the rule)
3. Low audit count with real payout
4. Scope you can fork-test (you need a PoC for a reward, not a write-up)

---

## 2. Run the class scanner before reading anything

```bash
python3 -m cli veck list                          # the 15 classes + why each is Critical
python3 -m cli veck scan <contracts-dir> --strong-only
python3 -m cli veck scan <dir> -c 4 -c 9          # just the share-math / token-handling classes
```

The scanner deliberately reports **no severity**. A regex cannot prove an exploit
path; it tells you where to read. Every strong hit is a prompt, not a finding.

**Class-to-target mapping** — most triage time should go here:

| If the target is… | Run first |
|---|---|
| vault / ERC-4626 / yield aggregator | 4, 9, 8 |
| lending / CDP / synthetic minting | 11, 3, 10 |
| bridge / cross-chain messaging | 13, 6 |
| staking + reward distribution | 8, 1 |
| upgradeable / proxied anything | 1, 5, 7 |
| router / account abstraction / multisig | 12, 14 |
| multi-asset or arbitrary-token vault | 9, 2 |

---

## 3. Triage mechanics

```bash
python3 -m cli immune scope <slug>              # in-scope addresses + repos
python3 -m cli immune triage <slug> --max-fetch 12   # scope -> fetch -> graph -> hotspots
```

`immune triage` gives you the graph and hotspot ranking. **The verdict stays manual.**
Then:

- **Verify the deployed code matches the source you read.** This has bitten me
  three times: Aera (earlier 0.8.3 vs 0.8.29), SSV (proved an entire round on
  non-deployed code), Lombard (a one-line comment difference, but you must check).
- **Check the live implementation address**, not just the proxy. A UUPS proxy
  without a beacon is common.
- **Read the exclusion list before you invest.** Aera, Origin, and Lombard each
  fence off large named areas as documented behaviour.

---

## 4. Confirm a candidate (invariant → state shift → fork PoC)

```bash
forge test --fork-url $MAINNET_RPC --fork-block-number <PINNED> -vvv
```

1. **State the invariant** that must never break
   (e.g. "vault assets ≥ totalShares × pricePerShare").
2. **Trace every path that moves value** and diff internal accounting against
   actual token balance. A mismatch is the bug.
3. **Prove it on a fork at a pinned block.** Show the loss path executes and
   quantify the amount at risk — most programs want **≥ USD 50k** for a Critical,
   and several require the path to have *worked on mainnet at submission*.

A fork PoC is the deliverable. A well-written report without one is unpayable on
most of these programs — it is a condition precedent, not a nicety.

---

## 5. Before you submit

- [ ] Reproduced on a fork at a **pinned block**, with the block cited
- [ ] Confirmed the **deployed bytecode** matches the source I read
- [ ] Grepped every published audit for the same root cause
- [ ] Confirmed the target is **in scope at the exact address and chain**
- [ ] Impact is drain / permanent lock / governance takeover — **not** griefing
- [ ] Quantified the loss; ≥ USD 50k if claiming Critical
- [ ] Checked it is not already in the program's known-issues list
- [ ] Not dependent on privileged keys, which every program excludes
- [ ] PoC asserts the **invariant violation**, and includes a **negative control**
      that fails when the bug is absent
- [ ] Stopped testing once the loss path was demonstrated (programs exclude
      self-exploited damage)

**The negative control is the one people skip.** A test that asserts something
because it *should* hold passes identically whether or not the bug exists. Both
invalid Aera submissions failed exactly this way.

---

## 6. Known failure modes (mine, so you can watch for them)

- **Hand-typed addresses.** EIP-55 checksum errors, repeatedly. Read addresses
  from the chain or `mainnet.json`; never type them.
- **Hand-decoding ABI returns.** `cast call` decodes correctly; my own Python
  decoder produced a bogus `epoch() = 0`. Use the tool.
- **Assuming a shape.** Assuming a getter is a tuple rather than a struct
  (Aera), or that a selector exists (`epoch()` is a struct field, not a getter).
- **Not reading the known-issues list** before ranking leads. On SSV this would
  have killed the top lead immediately; on Lombard the two juiciest findings were
  already patched in production.
- **Overwriting bytecode format.** A mainnet-read-only RPC returns the *canonical*
  metadata, not the metadata actually deployed, so byte-for-byte comparisons
  falsely report "modified" on standard releases. I hit this in the ChainScope
  test suite.

---

## 7. After a finding dies, write down why

Every round on Aera, SSV, Origin, and Lombard ended without a Critical. Those
rounds were not wasted — the *closures* are the asset. A documented
"this is the known audit finding, fixed at commit X" or "no stale root exists on
chain" saves the next session from re-deriving it.
