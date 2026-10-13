# Gate lessons — checks that must run before reading code

Every one of these came from a wrong conclusion, not a missing one.

## 1. Audit coverage: verify the audited contracts still exist

Reading audit PDF filenames tells you almost nothing. IPOR's three reports were named
"IPOR protocol", "IPOR token", "IPOR liquidity mining" and I scored the coverage as "thin".
Every contract in the 2022-08 Zokyo scope — `Milton`, `IporSwapLogic`, `Joseph`,
`MiltonSpreadModel`, `Stanley`, `StrategyAave/Compound/Core`, `IvToken` — **no longer exists
in the current source**. The fund-holding `Amm*` architecture was never audited at all.

`exactly` is the same shape at a different scale: 32 PDFs, 8 firms — and reading one
contract found nothing, because the audit density was the real story.

Check: extract contract names from the audit scope, then assert they resolve in the repo.

## 2. Grep for identifiers the codebase actually uses

I claimed "no two-step ownership handover exists anywhere" after grepping
`pendingOwner|acceptOwnership|proposedOwner`. IPOR uses `appointToOwnership` /
`confirmAppointmentToOwnership` / `confirmTransferOwnership`. All 12 in-scope contracts have
two-step transfer. I had read `OwnerManager.transferOwnership`, the internal one-step
primitive, and missed the external two-step wrapper — then built a Critical on it.

The on-chain selector check killed it in one call.

## 3. Deployed bytecode, not the repository

mETH `Staking` deployed source is byte-identical to the repo (md5 `7ca18fb0…`), so the
permit finding is real on live code. In the same session I twice concluded a deployed
contract "diverged" from source — both times an artefact of comparing one contract against
a whole source tree, and once because the contract inherits `AccessControlEnumerable`
so its bytecode carries selectors no single file declares.

Selector ratios are not evidence for inherited contracts. Byte comparison is.

## 4. A "no result" from a read tool is not a result

`re uninit` returned UNKNOWN on 7 of 9 mETH contracts because initializers take structs
and the probe ABI-encoded dummy addresses. Reading UNKNOWN as "fine" would have closed
1,070,000 tokens of admin surface without ever checking it. Resolved by reading
`getRoleMember(DEFAULT_ADMIN_ROLE, 0)` instead — all 9 initialized, 6-of-N Safe.

## 5. Look for what the auditors RAISED, not just what they covered

The mETH permit bug was found because a user pointed me at a URL. Reading Lido #803 gave
both the class (paid, Medium, still unfixed upstream) and the exact missing code.

Acknowledged-and-unfixed findings are the cheapest leads in any corpus:
- mETH M-1 `UnstakeRequestsManager#L361` uncancellable requests — Acknowledged
- mETH H-1 oracle record modification → exchange-rate control — Acknowledged, mitigated
- IPOR M-2 renounce-ownership risk — Acknowledged, propagated to new unaudited contracts

## 6. Never present a test result before checking parameter scaling

IPOR gate probe: I passed thresholds `10`/`100` where `percentOf(value, rate) =
value * rate / 1e18` is WAD-scaled. I reported "fall-through confirmed" from that run. The
run was measuring my own mis-scaling. Watch for units before trusting a green test.
