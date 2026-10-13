# The untriaged High pools — class 15 and class 9

Critical is the rarest tier and the hardest to reach. The High-class pools had gone
entirely unread, and they are where a realistic finding is most likely.

## Class 15 — flash-mint / flash-loan accounting mismatch (35 strong)

Concentrated in three targets, which made triage tractable:

| target | strong | files |
|---|---|---|
| AAVE | 20 | `Pool.sol`, `LendingPool.sol`, `GhoFlashMinterProcedure.sol` |
| SparkleEnd | 10 | `Pool.sol`, `PoolStorage.sol` |
| Silo | 5 | `LiquidationHelper.sol` |

The failure mode is *"minted tokens retained without burning them"* — it needs a
transfer that does not revert. Two concentrations read in full.

**Aave `GhoFlashMinter.flashLoan` (157 lines)** — canonical, and sound:

```solidity
GHO_TOKEN.mint(address(receiver), amount);
require(receiver.onFlashLoan(...) == CALLBACK_SUCCESS, 'FlashMinter: Callback failed');
GHO_TOKEN.transferFrom(address(receiver), address(this), amount + fee);
GHO_TOKEN.burn(amount);
```

The burn follows the callback, so the only way to retain minted tokens is a receiver
that returns without repaying — which requires `transferFrom` to fail silently.
**It does not.** `GhoToken is ERC20` (`:13`) with **no `transferFrom` override**, so
it is OpenZeppelin's default, which reverts on insufficient balance. The whole
transaction reverts and nothing is retained. Fee handling is correct too: `amount +
fee` is pulled and only `amount` is burned, leaving the fee for
`distributeFeesToTreasury`.

**Silo `LiquidationHelper.onFlashLoan` (253 lines)** — sound, with the check that
matters stated explicitly:

```solidity
require(msg.sender == _expectedFlashLoanProvider, UnauthorizedFlashLoanCallback());
uint256 flashLoanWithFee = _maxDebtToCover + _fee;
require(flashLoanWithFee <= balance, UnableToRepayFlashloan());
IERC20(_debtAsset).forceApprove({spender: msg.sender, value: flashLoanWithFee});
```

Expected-provider guard set immediately before the flash loan is taken, so a rogue
callback cannot enter; an explicit solvency check before repaying; exact approval via
`forceApprove`. Correct.

**Not individually read:** the `Pool.sol` / `LendingPool.sol` / `PoolStorage.sol` hits
in AAVE and SparkleEnd. Recorded as open rather than implied clean.

## Class 9 — token handling / balance accounting (23 strong)

**21 of 23 are Foundry test scripts, not production.** They are all `*.s.sol`:
`WithdrawTopUpDestFundsOP3CP.s.sol`, `StockWrapInPlaceEth3CP.s.sol`,
`TopUpFactory.s.sol`. Class 9's strong pattern is
`balanceOf(...) - \w+`, which fires freely in deployment scripts that assert a
balance decreased.

The two remaining hits are one each in `AaveLib.sol` (SparkleEnd) and
`ERC721Enumerable.sol` (Silo), both incidental and not examined.

**Not a finding**, and worth recording that 21/23 of a 23-hit pool evaporates once
test scripts are excluded — the same lesson as `_sol_files` excluding vendored trees,
found on a different code path.

## Verdict

No finding in either pool, but the reads were worth doing: **both High pools
concentrate in a handful of files, so a 35-hit and a 23-hit class triage to three
files and one directory respectively.** Hit count predicts work far worse than
concentration does.

The lesson generalises the session's. Class 13 gave 39 hits → one contract read.
Class 6 gave 45 → two files resolved the entire question. Class 9 gave 23 → 21 were
test scripts. **Sorting by target concentration, then reading whole files, beats
reading hits.**
