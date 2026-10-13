# mETH — class-level audit gap analysis

Not "was finding X fixed" but "does the vulnerability class behind X still work".
A fix for one instance leaves the class open, and mETH's two reports overlap heavily:
Hexens p20/p23/p36 and MixBytes H-1 are all the share-rate class.

## 1. Share-rate manipulation — CLOSED
*(Hexens p20 "skewed share rate during withdrawals", p23 "deposit share rate
manipulated by staking manager", p36 "malicious oracle report can manipulate the
share rate for profit", MixBytes H-1)*

Three independent mechanisms tested:

- **Donation inflation.** `totalControlled()` sums `unallocatedETH` and
  `allocatedETHForDeposits` — tracked state variables, never `address(this).balance`.
  A raw ETH transfer to the Staking contract does not move the rate. The classic
  ERC4626 donation attack has no surface here.
- **Locked mETH double-counting.** At request, mETH is *transferred* to
  `unstakeRequestsManager`, not burned, so it stays in `mETH.totalSupply()`.
  `totalControlled()` simultaneously includes `unstakeRequestsManager.balance()`.
  Both sides move together; the rate does not shift on transfer. Burning happens at
  claim, and `totalClaimed` rises in the same step, so `balance()` falls in step.
- **Claim-delay capture.** `docs/claim-burn.md` states the delayer's stake is
  socialised to remaining holders. The mechanism is self-penalising: skipping a
  claim forfeits the accrual rather than capturing it.

Remaining vector is the oracle record (`record.currentTotalValidatorBalance`),
which is MixBytes H-1 — mitigated solely by `ORACLE_MODIFIER_ROLE` never being
granted. The admin is a 6-of-N Safe
(`0x4E59e778A0FB77fBB305637435C62FAed9AED40F`, Safe singleton
`0xd9Db270c1B5E3Bd161E8c8503c55cEABeE709552`), so granting it is privileged and
out of scope — but it is one privileged action from being a live Critical.

## 2. Withdrawal-credential front-running — CLOSED
*(Hexens p12 "malicious validator can steal user funds by front-running
withdrawal credentials")*

`Staking._validateWithdrawalCredentials` enforces length, the
`ETH1_ADDRESS_WITHDRAWAL_PREFIX` (`0x010000000000000000000000`), zero-padding,
and a match against the stored `withdrawalWallet`.

## 3. Fee-receiver theft — CLOSED
*(Hexens p42 "fee receiver in ReturnsAggregator can steal user funds")*

The fee receiver moved from `ReturnsAggregator` to `Staking.withdrawalWallet`; the
same validation applies. `setWithdrawalWallet` is `onlyRole(STAKING_MANAGER_ROLE)`.

## 4. Missing slippage checks — CLOSED
*(Hexens p44 "no slippage checks on deposit and withdraw")*

`minETHAmount` / `maxAssets` are threaded through `depositAtMaturity`,
`borrowAtMaturity` and the close paths, with `Disagreement()` on breach.

## 5. Unbounded finalisation delta — CLOSED
*(Hexens p50, MixBytes M-2)*

`setFinalizationBlockNumberDelta` rejects
`finalizationBlockNumberDelta_ > _FINALIZATION_BLOCK_NUMBER_DELTA_UPPER_BOUND`.
This one was Acknowledged/unfixed in Oct 2023 and has since been closed.

## 6. Permit front-running — OPEN (the reported finding)

`unstakeRequestWithPermit` calls `safePermit` unconditionally. `allowance` occurs
0 times in the deployed `Staking.sol`. See `METH-permit-frontrunning.md`.

## Result

Five of six classes closed, each with the mechanism that closes it. One open, and it
is the finding already drafted.
