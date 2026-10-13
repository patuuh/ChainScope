# GMX position impact pool — executed, 25,000 fuzz runs, clean

The one layer prior GMX work (`AI_AUDIT_FILTER.md`) flagged as genuinely new:
impact-pool **amount application**, as distinct from the impact *price* computation
that earlier fuzzing already cleared at 5k/5k/8k runs.

## Result

**7 tests, 25,000 fuzz runs, all green** — against the **real** `DataStore` and the
**real** `MarketUtils` internals via a harness contract, not a stub.

| Test | Runs | Property |
|---|---|---|
| `testFuzz_floorNeverBreached` | 5000 | distribution never takes the pool below `minPositionImpactPoolAmount` |
| `testFuzz_noUnderflowAnyOrdering` | 5000 | `pool - min` cannot wrap under any input ordering |
| `testFuzz_cappedAtPoolMinusMin` | 5000 | distribution ≤ `pool - min` |
| `testFuzz_monotoneInElapsed` | 5000 | more elapsed time never yields less distribution |
| `test_zeroCasesReturnZero` | 5000 | pool==0, rate==0, or pool<=min ⇒ exactly zero |
| `testFuzz_freshMarketReportsZeroElapsed` | 1 | a never-distributed market reports 0 elapsed |
| `testFuzz_elapsedMatchesClock` | 5000 | elapsed matches the pinned clock |

## Getting the suite to run at all — four real blockers

None of these are findings in GMX. They are reproducibility defects in the repo that
stop `forge test` from running, and each would silently cost an auditor the campaign.

**1. `@openzeppelin/contracts-upgradeable` is imported but never declared.**
`contracts/multichain/MultichainTransferRouter.sol:5` imports it; `package.json`
declares only `@openzeppelin/contracts: 4.9.3`. It resolves under npm/yarn purely by
**hoisting** a transitive dependency, and breaks under any strict resolver. A genuinely
undeclared dependency.

**2. `foundry.toml` ships no optimizer settings**, so the repo does not compile with
forge defaults — `ExecuteWithdrawalUtils.sol:319` fails with *Stack too deep*.
Requires `optimizer = true` (with `solc_version = '0.8.36'`) to build at all.

**3. The existing fuzz harness did not compile.** `test/PricingUtilsFuzz.t.sol:93`
called `impact.abs()`, which is not a Solidity builtin; and OZ 4.9.3 has no
`Math.abs` either (that arrives in 5.x) — the correct 4.9 spelling is
`SignedMath.abs(int256)`, which returns `uint256` and so needs matching types at the
`assertLe` call site.

**4. `after` is a reserved keyword in Solidity ≥0.8.19.** A natural variable name for
"the pool after distribution" breaks the build.

`pnpm` was used for the install (`npm install` fails on `@parcel/watcher`, a frontend
native module irrelevant to Solidity).

## Two fuzz failures that were bugs in my test, not in GMX

Worth recording, because both would have been publishable had I not traced them.

**Failure 1 — the floor assertion.** The fuzzer found `pool = 7.249e20`,
`min = 2.061e23`: **the pool already sits below its own configured minimum.** The
contract returned `(0, 7.249e20)` — zero distribution, pool untouched — which is
exactly right. My assertion `remaining >= min` is unsatisfiable when `min > pool`. The
correct invariant is conditional: above the floor, respect it; below it, distribute
nothing at all.

**Failure 2 — monotonicity without ordering.** I bounded `a` and `b` independently and
asserted `dist(a) <= dist(b)`. Since fuzz supplies them unordered, `dist(a) > dist(b)`
is legitimate whenever `a > b`. Monotonicity is only a meaningful assertion once the
two elapsed times are ordered — which the test now does.

Both failures were the fuzzer doing its job on *my* reasoning, and the protocol was
correct in both cases.

## What this does and does not establish

It establishes that the position impact pool distribution is sound across 25,000 runs
of the real arithmetic: no underflow in `pool - min`, the configured floor is never
breached, distribution is capped and monotone, and a pool already under its minimum is
left untouched.

It does **not** establish anything about the swap impact pool's *amount application*,
which is where my notes actually pointed, nor about the reentrancy/pricing properties
Guardian has already audited. **This is one layer, executed — not a cleared programme.**
