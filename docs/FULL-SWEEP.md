# Full 21-class sweep — 32 targets, all classes

Closes a coverage gap in my own claim. The earlier portfolio sweep ran only the
rare classes (1, 4, 13, 19); **all 21 had never been run across all targets** with
the vendor/test exclusions in place. `vendor+test excluded`, 32 targets, ~55,000
Solidity files, ~4 minutes.

## Result: no new vulnerability signal — and one scanner defect

The eye-catching number was class 20 at **273 strong out of 289** — a 94% strong
ratio, which reads as extraordinarily fertile. **It was entirely an artifact of
two bad patterns**, and I nearly recorded it as the sweep's headline.

### The defect

Class 20 is *ERC-4337 paymaster gas accounting / deposit drain*. Its `strong` list
ended with:

```python
r"postOp\b",
r"EntryPoint",
```

1. **`r"EntryPoint"`** matched a bare *contract name*. Royco ships its own
   `RoycoEntryPoint` — a batching entry point with `cancelDepositRequest` and
   friends, nothing to do with ERC-4337. 247 of the 252 Royco hits were this,
   fired on `import` lines, interface declarations and deploy config.
2. **`r"postOp\b"`** matched a *local variable*. All 5 Royco `postOp` hits were
   `RoycoDayAccountant.sol`:

   ```solidity
   SyncedAccountingState memory postOp = IRoycoDayKernel(kernel).syncTrancheAccountingFromAccountant();
   ```

   The 4337 `postOp` is a paymaster hook. These are unrelated.

### The fix

Both patterns anchored to real context rather than a bare name:

```python
r"function\s+postOp\b|postOp\s*\("                       # a hook, not a variable
r"EntryPoint\s*\.\s*(?:depositTo|withdrawTo|balanceOf|addStake|unlockStake|handleOps|getUserOpHash|getNonce)",
```

Validated on real corpora:

| Target | before | after |
|---|---|---|
| Royco | 252 strong | **0** |
| Origin, Silo | all artifact | **0** |
| AAVE | — | **5 strong, genuine** |

AAVE still surfaces `validatePaymasterUserOp`, `paymasterAndData`, and
`paymentType` — real paymaster code. The artifact is gone and detection survives.

Three tests pin it, including one asserting a genuine paymaster is still caught.
Writing them caught a second problem: the shared `_scan` test helper was
**hardcoded to class 19**, so the two "no hits" class-20 assertions were passing
vacuously. That is the same vacuous-pass mode caught twice already this session,
and it is why the third test exists.

## Portfolio-wide class tally

| class | hits | strong | | class | hits | strong |
|---|---|---|---|---|---|---|
| 1 uninitialised proxy | 706 | 387 | | 12 delegatecall | 181 | **109** |
| 2 read-only reentrancy | 655 | 0 | | 13 bridge proof | 2193 | 39 |
| 3 oracle manipulation | 218 | 52 | | 14 unchecked return | 129 | 49 |
| 4 4626 rounding | 289 | 28 | | 15 flash-mint accounting | 500 | 35 |
| 5 storage collision | 242 | 0 | | 16 flashloan manipulation | 108 | 27 |
| 6 DEX price manipulation | 264 | 45 | | 17 CL pool math | 229 | 35 |
| 7 access control | 2756 | 62 | | 18 slippage/MEV | 3696 | 6 |
| 8 signature replay | 39 | 0 | | 19 vault donation | 315 | 20 |
| 9 token handling | 827 | 23 | | 20 paymaster | 289 | 273 → **0** |
| 10 flash-mint drain | 959 | 0 | | 21 modular account | 143 | 16 |
| 11 liquidation math | 424 | **137** | | | | |

## What survives, honestly

Three classes carry strong hits that are not obviously artifact-shaped and have not
been examined portfolio-wide:

- **class 12, 109 strong** — delegatecall to untrusted targets. Verified clean on
  Gamma (`SpreadRouter`, `PowerTokenRouter` both route to `immutable` addresses),
  but never checked on the other 30 targets.
- **class 11, 137 strong** — liquidation math and health factors. Never examined
  anywhere; the Rust equivalent (Hydration's liquidation pallet, flash-mint
  callback) was audited this session and found sound, but that is one
  implementation.
- **class 1, 387 strong** — uninitialised proxies. Known to over-fire on interface
  declarations (`IUniversalVault.initialize()` was the Gamma instance). The
  remainder has not been triaged.

Class 20's ratio being wrong is itself the warning: **a strong-hit count is a
prior, not evidence.** Every one of this session's would-be findings died on
reading the code, and class 20 is a demonstration of why a number that looks that
fertile can be pure noise.
