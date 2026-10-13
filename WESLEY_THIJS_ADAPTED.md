# The Rat method, adapted to ChainScope

Source: Wesley Thijs ("The XSS Rat" / "Uncle Rat") - OWASP speaker, OSCP/CNWPP, TheXSSRat,
author of the "Practical Bug Bounty Guide" and 27 courses. His material is web-app focused; this
file maps each principle to EVM/crypto hunting and to our tooling. Two of his repos matter most:
`subScraper` (recon) and `BountySkiller` (study what pays).

## His core principles (as stated)

1. **"Fingerprint, don't scan. Tools are noisy. Identify what you're hitting first (frameworks,
   headers, versions) before blasting it."**
2. **"Manually walk the application"** - the recon phase: explore functionality, note privilege
   levels, understand how the app processes requests.
3. **"When I register my account, I register using an attack vector"** - every field you control
   is a test; drop XSS/SSTI/HTML-attribute payloads into every field the moment you can.
4. **"We HAVE to do all these tests"** - systematic, exhaustive coverage of every parameter
   against every class, even when most tests find nothing. Discipline over luck.
5. **Multiple privilege levels** - create accounts at every level and test for broken access
   control / vertical privilege escalation.
6. **Study what pays** (BountySkiller) - analyze disclosed/paid reports to prioritise the bug
   classes that actually pay.
7. **Frictionless setup** - pre-configure your tooling so starting costs nothing ("the biggest
   part of any activity is getting yourself to do it").
8. **Budget-first** - free tools and real writeups before paid courses; no promises of easy bugs.

## The adaptation (EVM / ChainScope)

| Rat principle | ChainScope translation | Tool |
|---|---|---|
| Fingerprint, don't scan | Identify compiler version, proxy/upgrade pattern, libraries, oracles, integrations, roles, and the deployed-vs-repo diff BEFORE fuzzing | `cs_target`, `cs_re`, `cs_fetch` |
| Manually walk the app | Trace the intended flows end-to-end as the developer wrote them (deposit/stake/claim/withdraw, borrow/repay/liquidate); map every external entry point and its value flow | manual + `cs_scan` |
| Attack vector in every field | Call **every** external function with boundary/adversarial inputs: 0, 1, type-max, dust, self, zero-address, wrong order, reentrancy, stale deadline, self-signed, duplicate | Foundry fuzz/invariant |
| Do all the tests | Run the 30-class sweep over every in-scope file; tag each candidate with its class | `cs_sweep` |
| Multiple privilege levels | Enumerate **all** roles (owner/admin/keeper/guardian/pauser/upgrader/relayer/asset-manager) and diff each one's capabilities; hunt missing-auth / priv-esc / admin-bypass | `cs_sweep` class 1 + manual |
| Study what pays | Aggregate recent **exploited** classes (rekt.news) + the in-scope bounty catalog, so effort goes where bugs are actually landing | `cs_pays` (new) |
| Frictionless setup | Keep the venv/remappings/RPC/fork ready; fresh launch -> clone -> test in minutes | `FRESH_LAUNCH_PLAYBOOK.md` |
| Budget-first | Foundry/cast/slither/circomspect (free) + public writeups | our whole stack |

## The "attack vector in every field" checklist (EVM)

For each in-scope external function, exercise these inputs (the analog of his per-field payloads):

- **amounts**: 0, 1, dust (1 wei), type(uint).max, type(uint128).max, amount == balance, amount > balance
- **addresses**: address(0), self, the contract, the token, a blacklisted/malicious token, an EOA vs a contract
- **ordering**: call twice, reentrancy (before/after state), cross-function reentry, front-run
- **time**: expired deadline, far-future deadline, block.timestamp edges, stale oracle round
- **authorisation**: caller != owner, wrong role, no approval, self-signed / replayed signature, wrong chainId
- **accounting**: deposit then withdraw same block, fee-on-transfer token, rebasing token, donation before first deposit
- **upgrade/proxy**: call impl directly, re-init, storage collision, uninitialized proxy

## The "study what pays" loop (the BountySkiller idea)

`cs_pays` pulls the recent exploit feed (rekt.news) and the live bounty catalogs, and reports the
**bug classes currently landing** (bridge/replay, access-control, accounting desync, oracle,
governance) so we bias toward them - and it prints the fresh programs to point them at.

## The mindset

- Every field, every function, every role is a test. Do them all; most will be clean.
- Understand the app's intended behaviour first, then break the assumptions.
- Prove the end effect; never overclaim.
- Friction kills hunting - remove it before the window opens.
