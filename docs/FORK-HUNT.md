# Fork hunt — does the vulnerable share math travel to anyone in scope?

Follows from the catalog sweep: PowerToken, Hypervisor and xGamma were three
independent instances of the same donation family, which usually means a shared
ancestor. Three known-bad implementations, so the question is who inherited them.

**Answer: no one in scope.** Closed with evidence below.

## GammaStrategies/hypervisor — 34 forks

Only one is a real project rather than an undifferentiated personal clone. The
sizes cluster tightly (8470/8471/8474KB across seven forks), which is the
signature of an unmodified copy.

| Fork | Last push | KB |
|---|---|---|
| `galacticcouncil/gamma-hypervisor` | **2026-10-02** | 9705 |
| `studiokvc/gamma-hypervisor` | 2026-09-16 | 3633 |
| `Kubudak90/hypervisor` | 2026-03-10 | 8538 |
| `Jingo-Finance/hypervisor` | 2025-10-27 | 3622 |
| `BoundFinance/hypervisor` | 2024-02-20 | 7766 |
| + 29 personal clones | | |

`galacticcouncil` is the standout — an active DeFi organisation, pushed the day
before this sweep.

## The galacticcouncil fork: same code, same bug

Cloned and diffed. `contracts/` contains the **same 20 files as upstream**, and only
two differ:

```diff
- IHypervisor(pos).token0().safeApprove(pos, MAX_UINT);
+ // HydraDX asset precompiles store balances as u128, so an approval of
+ // MAX_UINT (2**256-1) overflows and reverts.
+ IHypervisor(pos).token0().safeApprove(pos, type(uint128).max);
```

and an added `toggleDirectDeposit()` declaration to `IHypervisor.sol` that was
missing. Both are chain-specific corrections for their Substrate precompiles, not
new logic.

**`Hypervisor.sol` is byte-identical to upstream**, including the unmitigated share
price, with zero occurrences of `VIRTUAL_SHARES`, `virtualShares` or
`MINIMUM_LIQUIDITY`. The fork's divergence is operational TypeScript — `keeper/`,
`lark/`, `mainnet/`, `monitor/`, `zombienet/`.

So the bug does travel — it is faithfully inherited. The problem is scope.

## Hydration's Immunefi scope contains no Solidity

`hydration` is the rebrand of Aera and carries the **largest ceiling in the entire
catalog: maxBounty 222,222**, `pausedAt: null`, `endDate: null`. It looked like the
best target of the hunt.

Its 76 in-scope assets are:

| Extension | Count |
|---|---|
| `.rs` | **71** |
| `.sol` | **0** |

| Repo | Assets |
|---|---|
| `galacticcouncil/HydraDX-node` | 66 |
| `galacticcouncil/hydration-node` | 5 |
| `galacticcouncil/apps` | 1 |
| `galacticcouncil/Hydradx-ui` | 1 |

Every one is Rust or UI. The Substrate runtime pallets — `dca`, `asset-registry`,
`bonds`, `circuit-breaker`, `collator-rewards` — are the actual $222,222 surface.

**The hypervisor fork they maintain is not in that scope**, so the donation attack
is not reportable to Hydration no matter how cleanly it inherited it.

## Verdict

The fork hypothesis is answered and closed. The vulnerable share math *is*
propagated — galacticcouncil carries it verbatim — but it propagated into a codebase
that a high-value bounty does not cover, and into ~30 personal clones with no
programme of their own.

Two things follow. First, a promising lead died on a scope check, which is the
cheapest possible way for it to die: no fork test, no deployed state, no PoC
needed. Second, the $222,222 is real and it is in **Rust/Substrate**, which nothing
in this session's toolchain has touched — that is the genuine next frontier, not
another Solidity share-math target.

## One loose thread worth keeping

`toggleDirectDeposit()` (`Hypervisor.sol`, ~615) lets the owner flip the flag that
gates the liquidity-minting branch in `deposit`. The deployed Gamma Hypervisor has
`directDeposit() == false`. It is a governance lever rather than a bug, but it
changes which code path a deposit takes, so any future Hypervisor review should
read it both ways.