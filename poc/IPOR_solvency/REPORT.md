# IPOR — solvency accounting, tested

**Verdict: no insolvency or theft finding in the tested surface.** The gap in this
project was reading without testing — these are the first fuzz invariants over
`AmmStorage`'s accounting, the surface behind IPOR's `Protocol insolvency` High
tier.

Unlike `poc/F1_fee_subidy/`, these suites are **not** self-contained. They import
the protocol tree and OpenZeppelin, so they run inside an `ipor-protocol` checkout
rather than standalone here.

## Running them

```bash
git clone https://github.com/IPOR-Labs/ipor-protocol
cd ipor-protocol
git submodule update --init --recursive
npm ci

cp /path/to/ChainScope/poc/IPOR_solvency/*.t.sol test/

forge test --match-contract SolvencyAccountingTest -vv
# 5 passed, 0 failed   (768 fuzz runs)
```

The copies here are the record of what was run. Upstream is at commit `434327d3`
(merge of PR #760, "CR fix. Spread appropriate for pool"). `package-lock.json`
was already dirty before this work; it is unrelated.

## Invariants that hold

| Test | Runs | Property |
|---|---|---|
| `testFuzz_roundTrip_restoresCounters` | 256 | A PayFixed open/close round trip returns every collateral counter to its starting value, for any collateral, notional and liquidation deposit |
| `testFuzz_roundTrip_receiveFixedLeg` | 256 | Same for the ReceiveFixed leg |
| `testFuzz_manyRoundTrips_conserve` | 256 | N opens then N closes still nets to zero |
| `test_doubleClose_isRejected` | 1 | A swap cannot be closed twice |

## The caller-supplied struct: tested, not assumed

`updateStorageWhenCloseSwapPayFixedInternal` takes a `Swap` **from the caller**, and
`_updateSwapsWhenClosePayFixed` reads `swap.buyer`, `swap.idsIndex` and `swap.id`
from it. `_updateBalancesWhenCloseSwapPayFixed` then uses that struct's
`collateral` and `wadLiquidationDepositAmount`. That is a trust assumption worth
probing, because the solvency-critical fields differ in how they are handled:

| Caller lies about | Result |
|---|---|
| `collateral` inflated 500x | **reverts** — arithmetic underflow |
| `buyer` forged to `0xDEAD` | **reverts** — arithmetic underflow |
| `liquidationDepositAmount` doubled | **no effect** — sourced from storage, not the struct |

So the solvency-critical fields are defensively validated by the arithmetic, and
the deposit field is simply not taken from the caller. No finding — but the
asymmetry is now pinned by tests rather than inferred from reading.

This is what the harness fights: the fuzzer's interleaved view calls consume a
single `vm.prank`, so the close lands as the router and fails with
`IPOR_008`. `vm.startPrank`/`vm.stopPrank` is the fix, and the manipulation tests
are order-sensitive for the same reason.

## The liquidation-deposit accounting

Open credits `liquidationDepositAmount * 1e12`; close debits
`wadLiquidationDepositAmount`, which is stored as
`liquidationDepositAmount * 1e12` (`AmmStorageBaseV1:136`). They agree, and the
fuzz round trips confirm the counter returns to zero.

Note the datatype: `liquidationDepositAmount` is stored as **uint32**
(`AmmStorageBaseV1:439`), so it is a small config value (e.g. 25), not an
18-decimal amount. Passing `1e18` reverts with `SafeCast: value doesn't fit in
32 bits` — which is what made the first drafts of these tests fail.

## What is NOT covered

These exercise `AmmStorage` accounting in isolation. Untested and still open:

- the floating-pool share maths on `Market` (`previewBorrow` / `previewRepay` /
  `previewRefund` round trip) — needs the full oracle/auditor/treasury stack deployed
- the oracle rate model (`spread`) and sanity checks
- `PowerToken`'s exchange rate, which is derived from a raw `balanceOf` and is
  therefore donation-sensitive in principle
- asset management and rebalance

## Why this stops here

IPOR's payout is Critical **flat $1,000** — a fixed amount, not a band. The
solvency surface is the most valuable thing in the protocol to attack, it has now
been fuzzed without a finding, and the three remaining gates mean it is blocked
regardless. `CloseSwapGateProbe.t.sol` is the earlier probe of the close-path
access gate, kept for the record; it is not part of the green suite.
