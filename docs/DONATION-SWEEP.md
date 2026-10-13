# Catalog sweep — the donation family across 33 targets

Run with the corrected class-19 detector (see `GAMMA-SWEEP.md` for how it was found)
over every local target with more than 20 Solidity files. Rare classes only —
1 uninitialised proxy, 4 rounding/inflation, 13 bridge proof, 19 donation /
first-depositor — because their presence is signal while the common classes are
structural.

**Result: no new unmitigated instance.** Every hit resolved into a mitigation, a
false positive, or one of the three already-known contracts.

## The sweep itself exposed a tool defect

First run: EtherFi 8,031 rare-class hits, Royco 8,031, `meth` class 19 at 181.
Almost all of it was other people's code — `_sol_files` had **no exclusions at
all**, so `rglob` walked `lib/`, `node_modules/`, `test/`, `mocks/`, `out/`,
`cache/`. Royco's "4,349 class-13 hits" were OpenZeppelin's `MerkleProof` mocks.

Fixed. `_sol_files` now excludes vendored dependency trees and test/mock
directories by default, with `include_tests` / `include_vendor` to opt back in.
Both directions matter: vendored code buries a real finding under thousands of hits,
and it can equally make a target *look clean* when the match landed in a vendored
copy rather than first-party code.

After exclusion:

| Target | before | after |
|---|---|---|
| EtherFi | 8,031 | 1,021 |
| Royco | 8,031 | 157 |
| Balancer class 19 | 342 | 96 |
| `meth` class 19 | 181 | 2 |
| sweep runtime | ~15 min | ~3 min |

## What the surviving hits actually are

### Royco — the best-mitigated vault in this corpus

Every class-19 strong hit is the **mitigation**, not a bug:

```solidity
/// @dev Constant for the virtual shares injected into the tranche to prevent the
///      first depositor from capturing the pre-existing backing
uint256 constant VIRTUAL_SHARES = 1;

/// @dev Constant for the virtual value backing the virtual shares, in NAV units
NAV_UNIT constant VIRTUAL_VALUE = NAV_UNIT.wrap(1);
```

Applied to both sides of the conversion:

```solidity
return (_totalSupply + VIRTUAL_SHARES).mulDiv(_value, (_totalValue + VIRTUAL_VALUE), _rounding);
```

With `MAX_MINT_DILUTION_WAD` clamping mints on top. The comment names the exact
attack this hunt spent three targets chasing. Worth recording as the reference
implementation of the fix.

### AAVE — false positive, twice over

Five strong class-19 hits, all `uint256 total = LINK.balanceOf(address(this));` in
Chainlink's `KeeperRegistryLogic`. The surrounding function is `recoverFunds()`:

```solidity
function recoverFunds() external onlyOwner {
    uint256 total = LINK.balanceOf(address(this));
    LINK.transfer(msg.sender, total - s_expectedLinkBalance);
}
```

That is an admin sweep of LINK, not a share/asset ratio. And every hit sits in
`repos/ccip/` — **Chainlink's CCIP repository vendored inside the local AAVE
aggregate**, not Aave code. The local `AAVE/` directory is a multi-repo collection,
so any AAVE conclusion needs that in mind.

### Balancer, Silo, SparkleEnd, Katana, Origin, Twyne, gearbox, Lombard

Class-19 counts of 6–96 but **zero strong hits** — all `weak`-strength, i.e. the
presence of a `totalSupply() == 0` guard or a `donat`/`skim` token. Guards and
skim functions are mitigations, not vulnerabilities. Class 13 dominates them and is
bridge-relayer code.

## What this establishes

The donation family is not unexploited — it is **understood and patched** wherever
it matters in this corpus. Three protocols still carry it (PowerToken, Hypervisor,
xGamma) and in all three the economics close it: the attacker needs `f → 1` of the
share supply, which a mature vault makes unreachable.

That reframes where to look. The live case is not a mature vault, it is a **freshly
deployed one**, so the productive targets are protocols that recently deployed a
share-pool or tranche, plus any fork of the three known-bad implementations. Royco
is the counter-example worth studying: same problem, solved.

Nothing here is submittable. The value is a negative result across 33 targets, a
10x-faster scanner, and one protocol whose mitigation should be the template.