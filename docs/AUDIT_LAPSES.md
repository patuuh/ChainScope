# Audit-lapse inventory

Question: where do published audits and their resolutions leave a gap that is
still exploitable?

Method per program: read the reports, separate **Acknowledged** (out of scope by
program rule, but still worth knowing) from **Fixed**, then test whether each fix
is still present in the code that is actually deployed. A fix that was later
reverted by a refactor is a *new* finding nobody has identified — that is the only
category here worth submitting.

---

## mETH — MixBytes 231030 + Hexens 230825

Audited scope, Aug–Oct 2023. `Staking.sol` and `UnstakeRequestsManager.sol` are
both named in the reports with line references.

### Fixed findings — all three verified still fixed

| ID | Fix | Verified |
|---|---|---|
| **H-3** | `latestCumulativeETHRequested` zeroed in `cancelUnfinalized` | ✓ `latestCumulativeETHRequested -= amountETHCancelled` |
| **L-4** | cumulative still updated when nothing was cancelled | ✓ guarded by `if (amountETHCancelled > 0)` |
| **M-3** | `withdrawalWallet` not upgradeable | ✓ moved to `Staking.sol:744` with `setWithdrawalWallet()` |
| **L-1** | execution-layer rewards unmonitored | identifiers refactored into `ConsensusLayerReceiver` / `ExecutionLayerReceiver`, both in Immunefi scope |

**No reverted fixes.** L-1's check was structural, not textual — the identifiers
moved, so a string match would have wrongly reported a regression.

### Acknowledged and still live (out of scope, but material)

| ID | Severity | Status |
|---|---|---|
| **H-1** Oracle report update lacks sanity checks; `ORACLE_MODIFIER_ROLE` can control `totalControlled()` and therefore the mETH exchange rate | High | Acknowledged |
| **H-2** Malicious oracle report is accounted for in the quorum | High | Acknowledged |
| **M-1** Some unstake requests can become uncancellable (`UnstakeRequestsManager.sol#L361`) | Medium | Acknowledged |
| **M-2** `numberOfBlocksToFinalize` has no upper bound | Medium | Acknowledged |
| **M-4** `cancelUnfinalizedRequests` can be DoSed by front-running | Medium | Acknowledged |
| L-2, L-3, L-5, L-6, L-7 | Low | Acknowledged |

H-1 is the one that matters: it is a genuine Critical-impact mechanism
(exchange-rate control → mint cheap, unstake dear). It is mitigated only by the
`ORACLE_MODIFIER_ROLE` never being granted at init. The admin is a **6-of-N Safe**
(`0x4E59e778A0FB77fBB305637435C62FAed9AED40F`, `masterCopy()`
`0xd9Db270c1B5E3Bd161E8c8503c55cEABeE709552`), so granting that role is a
privileged action and out of scope. **If that Safe ever grants the role, it becomes
a live Critical.**

That is the single most useful thing this corpus contains, and it is one
privileged transaction away from being reportable.

---

## IPOR — Zokyo 2208 + Ackee 2211/2301

**The audited contracts no longer exist.** Zokyo's scope was `Milton`,
`IporSwapLogic`, `SoapIndicatorLogic`, `Joseph`, `MiltonSpreadModel`, `Stanley`,
`StrategyAave`, `StrategyCompound`, `StrategyCore`, `IpToken`, `IvToken`,
`IporOracle`, `IporMath`, `IporOwnable`. Nine of them have **zero files** in the
current tree.

The current fund-holding architecture — `AmmStorage`, `AmmTreasury`,
`AmmOpenSwapService*`, `AmmCloseSwapService*`, `Auditor` — is **not covered by any
published audit.**

Four unresolved findings exist (Zokyo L-1 multiple external calls in one tx,
two Acknowledged balance-assertion issues, Ackee solc-optimizer warning) — all
against deleted contracts, so none carries over.

**Consequence:** the score of "three reports, thin coverage" I gave earlier was
wrong in the direction that mattered. It is not thin coverage, it is **no coverage
of the current code**.

---

## exactly — 32 reports, 8 firms

Newest report `ABDK Non-Collateral Markets (Sep-26)`, scope `Auditor.sol`,
`Market.sol`, `MarketExtension.sol`, `VerifiedAuditor.sol`, `VerifiedMarket.sol`,
`IPriceFeed.sol`.

Conclusion, verbatim: **"No Critical, Major, or Moderate issue stands in this
report."** Sixteen findings, all Low, 16 Acknowledged / 15 Fixed.

Nothing to regress at the top tiers. The `Critical` and `High` strings in the
document are the severity *definition* section and that conclusion sentence.

`DebtRoller.sol`, `FlashLoanAdapter.sol`, `DeadAllower.sol` and `Firewall.sol`
are **not** in this audit's scope — confirmed by scope extraction, not by filename
guessing.

---

## Result

| Program | Reverted fix found | New finding |
|---|---|---|
| mETH | none (3/3 verified) | permit front-running (separate) |
| IPOR | n/a (contracts deleted) | none — surface unaudited instead |
| exactly | none (no C/H/M) | none |

**No reverted-fix findings.** The exploitable gap is not in the resolutions — it is
in **IPOR**, where the audits are stale because the codebase was replaced wholesale,
and in mETH's **H-1**, which is one privileged action away from being live.

The lesson recorded in `docs/GATE_LESSONS.md` follows from this: audit filenames
prove nothing until you check the audited contracts still exist.
