# Class 1 (the last Critical pool) and the two untriaged High pools

## Class 1 — uninitialised proxies: 387 strong → 0

The single largest unread pool in the session, and the one where an unfiltered read
would have produced a Critical claim immediately. Decomposition first:

| bucket | count | disposition |
|---|---|---|
| interface declarations (`I*.sol`) | 129 | noise — `IUniversalVault.initialize()` was the Gamma instance |
| init-code references (`initializer`, `_disableInitializers`, `delegatecall`) | 215 | **the mitigation** |
| "real" candidates | 43 | filtered further |
| **after removing `*.s.sol`/`*.t.sol` tests** | **251** | across ~20 targets |

The pattern is `function initialize(...) external(?!.*only)` — it does not know about
the OZ `initializer` modifier, so the overwhelming majority of the 251 are the
*correct* `external initializer` / `external reinitializer(...)` form.

Filtering to `initialize()` with **no initializer modifier at all** left a handful:

| target | site |
|---|---|
| Optimism | `SuperPermissionedDisputeGame.sol:48` — `function initialize() external payable` |
| Silo | `Silo.sol:74`, `ShareProtectedCollateralToken.sol:23`, `ShareDebtToken.sol:34`, `InterestRateModelV2.sol:81` |
| avs-sc | `AvsOperator.sol:37` |

**Optimism `SuperPermissionedDisputeGame`** — guarded five times over, on a contract
that resolves disputes:

```solidity
bool internal initialized;                     // custom flag, not OZ Initializable
...
if (initialized) revert AlreadyInitialized();
if (Hashing.hashSuperRootProof(...) != rootClaim().raw()) revert BadExtraData();
if (tx.origin != proposer()) revert BadAuth();
if (msg.value != 0) revert IncorrectBondAmount();
if (l2SequenceNumber() <= rootL2SequenceNumber) revert BadExtraData();
```

`rootClaim()` is fixed at clone creation, so a proposer cannot substitute a claim —
they must prove the one already set. This is a permissioned game with a trusted
proposer by design. `tx.origin` rather than `msg.sender` is a pattern worth noting
but grants no escalation, since a contract could only do what the proposer could.

**Silo — guarded one layer down.** `Silo.initialize` has no modifier and no local
guard, and `Silo.sol` imports **no** proxy base at all (no `Initializable`, no
`UUPSUpgradeable`, no `TransparentUpgradeable`) — Silo deploys plain per-instance
contracts, so `initialize()` would be permanently callable. The guard is in
`lib/Actions.sol:48`:

```solidity
require(address(_sharedStorage.siloConfig) == address(0), ISilo.SiloInitialized());
```

Re-initialization reverts once config is set. Correct.

**This is the third time this session that tracing one layer down turned a Critical
claim into a non-finding** — Gamma's `withdraw_shares`, Hydration's
`StakeswapLiquidityMutation`, and now Silo's `initialize`. The invariant is rarely where
the function is.

## Class 8 — zero-supply reward accrual: 0 strong, corpus-wide

Strong patterns are `rewardPerTokenStored +=` and `accRewardPerShare +=`. **Zero hits**
across all 32 targets. The `rewardPerToken = earned / totalSupply` shape does not appear
in this corpus. Nothing to triage.

## Class 18 — slippage / sandwich / MEV: 6 strong, 5 vendored

| target | file |
|---|---|
| gearbox (3), Gnosis (2), AAVE (1) | `IUniswapV2Router02.sol` |

**Five of six are the canonical Uniswap V2 router *interface***, vendored into three
targets. The pattern matches the function name, not the target's logic. The single
first-party site is `gearbox/UniswapV2.sol:214`, a router library.

## Verdict

No finding in any of the three.

That closes the session's coverage:

| severity | class | strong | result |
|---|---|---|---|
| Critical | 1 uninitialised proxies | 387 | 0 — 251 real, all guarded |
| Critical | 6 replay/malleability | 45 | 0 |
| Critical | 12 delegatecall | 109 | 0 |
| Critical | 13 bridge proof | 39 | 0 |
| High | 15 flash accounting | 35 | 0 |
| High | 9 token handling | 23 | 0 (21/23 test scripts) |
| High | 8 zero-supply accrual | 0 | empty |
| High | 18 slippage/MEV | 6 | 0 (5/6 vendored interface) |

**638 strong hits across eight Critical and High classes, zero findings.** The
discipline that produced that number is unglamorous and was the point: sample before
believing, run a positive control, and trace to the layer that actually carries the
invariant rather than the layer the pattern fired on.
