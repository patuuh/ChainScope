# Fresh-launch playbook

Trigger: `cs_watch` flags a NEW competition / bounty / audit. The edge is the first hours to
days (few reports), so move fast and in this order. Budget: **first 60 minutes = triage +
prior-audit subtraction + hypothesis list**; only then invest in a PoC.

## 0. Triage (10 min) - decide if it is worth the next hour
- Read the program page: scope assets, severity table, **eligibility** (rep/KYC/fee), deadline,
  PoC rule, OOS list, and the program's own "known issues / prior audits".
- Note the chain + language. If it is not EVM/Solidity and not a language we can move on fast,
  score it down.
- Kill early if: no critical/high tier, scope is only web/QA, or it is already 200+ reports.
- Record the answer to: "what is the ONE highest-value impact class here?"

## 1. Get the code (5 min)
- Clone the in-scope repo at the pinned commit. For Immunefi/HackenProof use the program's
  target URL; for contests use the repo the program links.
- Note the framework (Foundry/Hardhat/other) and whether tests run.

## 2. Subtract the already-found (15 min) - do NOT skip
- Run `cs_audits` (follows the program's "Previous Audits" links, downloads + greps reports).
- Search public prior art: 0x-auth/disclosures, Code4rena/Sherlock/Cantina reports, the repo's
  own audit PDFs, `git log` for fix commits ("audit", "fix", "H-", "M-").
- List every known/OOS issue so we never re-report it.

## 3. Hypothesize fast (20 min)
- Run `cs_sweep` (30-class attack-pattern generator) over the in-scope files.
- Read the **delta**: the newest commits / newest files / the periphery (adapters, hooks,
  periphery, new chains). That is where an un-audited bug lives.
- Prefer the program's own focus area; rank hypotheses by (impact x likelihood x our ability
  to PoC it today).

## 4. Kill-test before any PoC (5 min)
- Which exact listed impact, with a defensible USD figure at risk NOW?
- Permissionless reach from current on-chain state (no admin/ops/third-party action)?
- Intended-design check (audit finding / unit test / comment says it is by design)?
- Bar match (critical-only programs reject Mediums; PoC must be a fork/local test)?

## 5. PoC (timeboxed)
- EVM: Foundry **mainnet-fork** test against the deployed addresses (never a local replica).
- Non-EVM/other: a runnable repro (local build + script) that shows the end effect.
- If the PoC needs something we cannot get (a proving key, a live key), say so up front and
  decide whether to file on the circuit-level/static argument or drop it.

## 6. Report (30 min)
- Match the platform's rules (see `IMMUNEFI_POLICY_NOTES.md` / `HACKENPROOF_POLICY_NOTES.md`).
- Prove the END EFFECT first, then pick the impact. No overclaiming. State "no public prior art
  found" (never "novel").
- Attach the PoC; keep it private (no gists before disclosure is allowed).

## Anti-patterns (learned the hard way)
- Grinding a mature/audited codebase for a critical. If prior audits + the delta are clean, move on.
- Investing before the kill-test passes.
- Reporting the Emporium-transient / malicious-calldata / already-public classes.
- Letting the window close while perfecting a PoC: file a correct partial PoC early if the rule
  allows, but never submit a unit-test-only PoC for an SC program.

## Command quick-reference
```
export PYTHONPATH=$PWD && ./.venv/bin/python cs_watch.py --once      # any new launches?
./.venv/bin/python cs_target.py <program>                            # rank / pick target
./.venv/bin/python cs_fetch.py <repo|address>                        # pull in-scope code
./.venv/bin/python cs_audits.py <program>                            # prior audits gate
./.venv/bin/python cs_sweep.py <path>                                # 30-class hypotheses
./.venv/bin/python cs_re.py <chain:addr>                             # bytecode -> selectors (EVM)
```
