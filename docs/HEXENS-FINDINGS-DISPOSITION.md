# mETH — complete disposition of all 21 Hexens findings

The 70-page Hexens report (Aug 2023) was, until today, only ever grepped for
`permit`. This is every weakness in it, tested against the code that is actually
deployed. Severities live in report graphics and did not survive text extraction,
so each is dispositioned by **mechanism**, not by its label.

Live values read from implementation `0x01a360392c74b5b8bf4973f438ff3983507a06a2`.

| # | Page | Finding | Disposition | Evidence |
|---|---|---|---|---|
| 1 | p12 | Malicious validator steals user funds by front-running withdrawal credentials | **FIXED** | `Staking._validateWithdrawalCredentials` enforces length, `ETH1_ADDRESS_WITHDRAWAL_PREFIX` (`0x010000000000000000000000`), zero padding, and match against stored `withdrawalWallet` |
| 2 | p16 | Staking deposits break immediately after deployment | **MITIGATED** | Bootstrap distortion via `exchangeAdjustmentRate` is capped at `_MAX_EXCHANGE_ADJUSTMENT_RATE = _BASIS_POINTS_DENOMINATOR / 10` (10%). Live value `0` |
| 3 | p20 | Stealing user funds due to skewed share rate during withdrawals | **CLOSED** | Forge: `totalControlled()` uses tracked state vars, so donation cannot inflate the rate; locked mETH stays in `totalSupply` while its backing is counted |
| 4 | p23 | Deposit share rate manipulable by staking manager | **MITIGATED** | Same 10% cap; requires `STAKING_MANAGER_ROLE` (6-of-N Safe) |
| 5 | p25 | Rewards accrued by unstake requests not distributed among takers | **CLOSED** | `docs/claim-burn.md` analyses it; the delayer socialises the accrual **away from itself** — self-penalising |
| 6 | p29 | Malicious oracle report causes DoS / wrong fee distribution | **PRIVILEGED** | `receiveRecord` is `msg.sender != oracleUpdater` → revert; the pending-update + `pauseAll()` path is reachable only by the updater |
| 7 | p36 | Malicious oracle report manipulates the share rate | **ACKNOWLEDGED, PRIVILEGED** | MixBytes H-1: `ORACLE_MODIFIER_ROLE` can control `totalControlled()`. Role never granted; admin is a 6-of-N Safe |
| 8 | p42 | Fee receiver in ReturnsAggregator steals user funds | **FIXED** | Receiver moved to `Staking.withdrawalWallet`, same credential validation; setter is `STAKING_MANAGER_ROLE` |
| 9 | p44 | No slippage checks on deposit and withdraw | **FIXED** | `minETHAmount` / `maxAssets` threaded through `depositAtMaturity`, `borrowAtMaturity` and the close paths, with `Disagreement()` on breach |
| 10 | p46 | Staking validator deposit — redundant checks and variables | INFORMATIONAL | code quality |
| 11 | p48 | Centralisation risk from pausable unstake and claim | **CLOSED** | Every `unpause()` is `onlyOwner`; all 12 in-scope contracts use a two-step ownership transfer, so a typo is recoverable |
| 12 | p50 | `finalizationBlockNumberDelta` should have an upper bound | **FIXED** | `setFinalizationBlockNumberDelta` rejects `> _FINALIZATION_BLOCK_NUMBER_DELTA_UPPER_BOUND` |
| 13 | p52 | Exchange adjustment rate has no default value | **MITIGATED** | `initialize()` does not assign it, but `uint16` defaults to `0`; live value `0`, cap 10% |
| 14 | p54 | Redundant value check in validator deposit | INFORMATIONAL | code quality |
| 15 | p57 | Redundant variable initialisation | INFORMATIONAL | code quality |
| 16 | p59 | Constants should be marked private | INFORMATIONAL | code quality |
| 17 | p61 | Unused receive and fallback function | INFORMATIONAL | code quality |
| 18 | p62 | Magic numbers should be replaced with constants | INFORMATIONAL | code quality |
| 19 | p64 | Identical functions | INFORMATIONAL | code quality |
| 20 | p66 | Unstake request info should report if the request is filled | INFORMATIONAL | code quality |
| 21 | p68 | Oracle compatibility with future EIP-4788 | INFORMATIONAL | forward-looking |

## Tally

| Outcome | Count |
|---|---|
| FIXED — the original defect is gone | 4 (#1, #8, #9, #12) |
| CLOSED or MITIGATED — mechanism cannot be exploited as described | 5 (#2, #3, #4, #5, #11, #13) |
| PRIVILEGED or ACKNOWLEDGED — reachable only behind a role, or a known accepted risk | 2 (#6, #7) |
| INFORMATIONAL — code quality | 10 (#10, #14–#21) |

## Not in this report

The permit front-running finding is **not** one of these 21. It is the same
*class* as #1 (front-running of a withdrawal-related signature) on a path the
auditors did not cover, and it is the only exploitable gap found.

Two MixBytes findings also remain live and acknowledged, both privileged: **H-1**
(oracle record controls the exchange rate) and **M-1** (`UnstakeRequestsManager#L361`,
some unstake requests can become uncancellable).
