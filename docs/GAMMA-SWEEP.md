# Gamma — 21-class sweep and the first-depositor finding

Answers "was Gamma actually covered?" **It was not.** The earlier note reverse-engineered
three addresses, concluded "direct, non-proxy", and Gamma was closed. The 21 Critical
classes and reverse engineering were never run against the Hypervisor source. Closing it
on that basis was premature. This is the correction.

## Correction — the addresses were not lost

[REVALIDATION-PASS.md](REVALIDATION-PASS.md) concluded the Gamma addresses were
unrecoverable. That was wrong: they are in the cached Immunefi catalogue under
`_seg.assets`. My grep missed them because `name` is null and only `slug`/`assets`
carry the data.

**The programme is live:** `pausedAt: null`, `endDate: null`, **maxBounty $50,000**,
launched 2021-10-08, `proofOfConceptType: required`, `primacy_of_rules`.

| Asset | Address |
|---|---|
| xGamma | `0x26805021988F1a45dC708B5FB75Fc75F21747D8c` |
| **Hypervisor** | `0xa8076ae31e4b6c64d07b1ed27889924a962a70d3` |
| UniProxy | `0x83de646a7125ac04950fea7e322481d4be66c71d` |

$50,000 is 50x IPOR's flat $1,000 Critical, and makes Gamma the highest-value target in
the portfolio. It should not have been closed on a three-address proxy check.

## 21 classes over `hypervisor/contracts` (20 files)

| Class | Hits | Note |
|---|---|---|
| 1 Uninitialized proxies | 1 | `IUniversalVault.initialize()` — an interface declaration. False positive. |
| 4 Rounding/inflation in share ratios | **1** | `ClearingV2.sol:169` — see below. |
| 19 Vault donation / first-depositor | **1** | same location. |
| 13 Bridge proof verification | 2 | No bridge in the codebase. False positive. |
| 18 Swap slippage/MEV | 4 | — |
| 3 Oracle manipulation | 12 | — |
| 9 Token handling | 14 | — |
| 16 Flash-loan price manipulation | 27 | — |
| 2 Read-only reentrancy | 44 | — |
| 7 Access control | 53 | — |
| 17 Concentrated-liquidity pool math | 112 | Every position uses `TickMath`. Structural noise. |

The rare classes are the signal, and both land on the same place.

## The finding: no virtual offset in `getTotalAmounts`

`Hypervisor.sol:490`:

```solidity
function getTotalAmounts() public view returns (uint256 total0, uint256 total1) {
    (, uint256 base0, uint256 base1) = getBasePosition();
    (, uint256 limit0, uint256 limit1) = getLimitPosition();
    total0 = token0.balanceOf(address(this)).add(base0).add(limit0);   // raw idle balance
    total1 = token1.balanceOf(address(this)).add(base1).add(limit1);
}
```

Share minting divides by exactly that (`Hypervisor.sol:139-142`):

```solidity
uint256 total = totalSupply();
if (total != 0) {
    uint256 pool0PricedInToken1 = pool0.mul(price).div(PRECISION);
    shares = shares.mul(total).div(pool0PricedInToken1.add(pool1));
}
```

No virtual offset, no dead shares, no minimum. **A plain `token.transfer` to the
Hypervisor inflates "total assets" with zero shares minted.** Withdrawals distribute the
idle balance pro-rata (`Hypervisor.sol:250-251`), so the donation is claimable by
shareholders.

Deposits are gated by `whitelistedAddress` (`:120`) and `nonReentrant`, but **a donation
needs no permission at all** — it is an ERC-20 transfer, not a call into the vault. And
the seeder can be first: `ClearingV2.getDepositAmount` returns `amountStart = 0` for an
empty vault (`:169-170`), so `clearDeposit`'s ratio check passes with 1 wei on both
sides. `Hypervisor.deposit` itself only requires `deposit0 > 0 || deposit1 > 0`.

This is precisely classes 4 and 19, and the same family as the PowerToken and sDAI
exposure — except the prize is 50x larger.

## Why it is still not exploitable on the in-scope vault

Donating `D` inflates total value `T`; a victim depositing `V` is diluted by `D/(T+D)`.
An attacker holding fraction `f` of shares nets:

```
net = -D + f * V * D/(T+D)   >  0   iff   f * V > T + D
```

Deployed state of `0xa8076ae3…`, read live:

| | |
|---|---|
| `totalSupply()` | 10,718,387,889,727,316,900 (≈10.72) |
| `getTotalAmounts()` | token0 8785.77, token1 2668.27 |
| token0 / token1 | `0xae78736c…` / `0xc02aaa39…` (stETH / WETH) |
| `directDeposit()` | false |
| `deposit0Max()` | max uint256 |

`getTotalAmounts` and `deposit(uint256,uint256,address,address,uint256[4])` are both
present in the deployed bytecode. This is a **mature vault holding ~11.45 units**, so `f`
is small for any new entrant. Working the numbers: at `f = 1%` with `D ≈ 11.45`, the
attacker must donate their way to break-even only if a victim deposits **>2,290 units
into an 11-unit vault** — a >200x whale deposit. Contrived rather than practical, and the
attacker must induce it.

**Same `f < 1` wall as PowerToken.** The donation is real backing that the donor can
recover only in proportion to the shares they hold, and holding ~all the shares is
unreachable once the vault has users.

It is live only where the attacker can be sole holder — a freshly deployed Hypervisor.
Whether new Hypervisor addresses fall inside the listed-asset scope is a scope question I
have not resolved, and it decides whether this is reportable at all.

## Verdict

A genuine hardening gap — same class as the PowerToken exposure, correctly identified by
the 21-class sweep — but **not exploitable against the in-scope deployed vault**, and
not reportable without resolving whether newly-deployed Hypervisors are in scope.

What this pass actually changes is the triage verdict, not the finding. Gamma is live,
carries a **$50,000** ceiling, and was closed on a proxy check that never examined the
share math. It should be re-opened as an active target.
---

## Follow-up: scope resolved, and the mature vault tested

### Scope — this kills the donation finding

From the programme page:

- **Total Assets in Scope: 3** — only the listed addresses. A newly-deployed
  Hypervisor is **not** in scope, which was the only condition under which the
  first-depositor attack is live.
- Critical **flat $50,000**, Medium flat $5,000, `primacy_of_rules`, PoC required,
  `pausedAt: null`, `endDate: null`.
- Two declared **out of scope**: UniProxy configurations other than the shipped one,
  and xGamma's deposit-before/withdraw-after-rebase window.
- Prohibited: testing on mainnet; all testing on **local forks**.

So the donation pattern is real code but **not reportable** — out of scope where it
would work, and `f < 1` where it is in scope.

### Mature vault — totalSupply and withdraw tested, sound

`_liquidityForShares` (`Hypervisor.sol:446`):

```solidity
return _uint128Safe(uint256(position).mul(shares).div(totalSupply()));
```

`withdraw` (`:217`) does the following, and every rounding favours the vault:

| Step | Line | Direction |
|---|---|---|
| shares → liquidity, base | 233 | down |
| shares → liquidity, limit | 242 | down |
| idle token0 pro-rata | 250 | down |
| idle token1 pro-rata | 251 | down |
| `_burnLiquidity` owed vs `amount0Min` | 430 | `require` floors the user |

`totalSupply()` is read consistently **before** `_burn` (`:259`), so the pro-rata
division is against the pre-burn supply — correct. `_burnLiquidity` enforces
`owed >= amount0Min` with `require`, so slippage cannot be under-reported.

One minor imprecision, not worth reporting: the supply cap at `:163` tests
`total` (pre-mint) rather than `total + shares`, so `maxTotalSupply` can be exceeded
by one deposit's worth. On the deployed vault `maxTotalSupply` is 0, i.e. disabled,
and `clearShares` re-checks post-mint in `UniProxy.deposit:63`.

### UniProxy (`0x83de646a…`, in scope, previously unexamined)

Read in full. No initializer, so class 1 does not apply — it is called directly by
users, not behind a proxy. `deposit` is `nonReentrant`, calls `clearDeposit` then
`Hypervisor.deposit` then `clearShares` (`:59-63`), and `onlyOwner` guards
`transferClearance` / `transferOwnership`.

`Hypervisor.withdraw` is **not** whitelisted-gated and carries only
`require(from == msg.sender, "own")` (`:258`), so anyone may withdraw their own
shares without passing through UniProxy or ClearingV2. That skips the registry check,
but not value: the caller supplies their own `minAmounts` and `_burnLiquidity`
enforces it. Not a finding — arguably intended, since proxied deposit with direct
withdraw still lets a delisted position be exited.

### Net position on Gamma

In scope there are three addresses. Two (Hypervisor, UniProxy) have now been read in
full against all 21 classes with the deployed state verified live; xGamma is in scope
but its source is **not** in this repository, so it remains unexamined.

Nothing found. The one genuinely interesting pattern — no virtual offset in
`getTotalAmounts()` — is real, correctly classified by the 21-class sweep, and
**out of scope where it would be exploitable**.

Gamma should not be closed, though: it carries a $50,000 ceiling, and xGamma is an
in-scope contract that has never been looked at in this session.

---

## xGamma (`0x26805021…`) — the third in-scope contract

Source obtained from Sourcify: `creationMatch: exact_match`, `runtimeMatch: exact_match`,
verified 2024-08-08. Single file `contracts/xGamma.sol`, 759 lines, **Solidity 0.6.12,
optimizer disabled**, `proxyResolution.isProxy: false`. So this is the *verified deployed*
source, not a repo copy.

It is a Bancor-style checkpoints rebase token, not an ERC4626:

```solidity
function enter(uint256 _amount) public {
    uint256 totalGamma = gamma.balanceOf(address(this));
    uint256 totalShares = totalSupply();
    if (totalShares == 0 || totalGamma == 0) {
        _mint(msg.sender, _amount);
    } else {
        uint256 what = _amount.mul(totalShares).div(totalGamma);
        _mint(msg.sender, what);
    }
    gamma.transferFrom(msg.sender, address(this), _amount);
}

function leave(uint256 _share) public {
    uint256 totalShares = totalSupply();
    uint256 what = _share.mul(gamma.balanceOf(address(this))).div(totalShares);
    _burn(msg.sender, _share);
    gamma.transfer(msg.sender, what);
}
```

No virtual offset, no dead shares, no minimum, and `enter`/`leave` are permissionless.
`totalGamma` is read **before** the transfer in, so a depositor cannot self-inflate the
denominator — only a third-party donation can. That is the same shape as PowerToken and
Hypervisor.

Live state, read from mainnet:

| | |
|---|---|
| `gamma()` | `0x6BeA7CFEF803D1e3d5f7C0103f7ded065644e197` |
| `totalSupply()` | 36,372,625.43 (3.637e25) |
| GAMMA held | 45,052,475.62 (4.505e25) |
| name / symbol | xGamma / xGAMMA |

### The attack is impossible for f < 1 — proven, not estimated

Attacker holds fraction `f` of shares, donates `D` into a vault of value `T`, victim
deposits `V`:

```
attacker net = -D + f * V * D/(T+D+V)  >  0   iff   V*(f-1) > T + D
```

With `f < 1`, `V*(f-1)` is **negative** while `T + D` is positive. The inequality cannot
hold. Unlike the earlier estimates, this is an algebraic impossibility, not a judgement
call about magnitudes — no donation size and no victim size change it.

It is live only at `f = 1`, i.e. the attacker is the sole holder or the first depositor.
xGamma's `totalSupply` is 3.637e25 with real backing, so neither is reachable: an
attacker cannot enter first, and cannot acquire existing shares without paying for them.

### Other angles checked and closed

- **CEI violation in `enter`** — `_mint` happens *before* `gamma.transferFrom` (`:744-749`),
  and the transfer's return value is unchecked. A token that returns `false` instead of
  reverting would hand out free shares. GAMMA **reverts** (`ERC20: transfer amount
  exceeds allowance`, `0x08c379a0…`), verified by `eth_call`, so this is not reachable.
  `gamma` is also assigned only in the constructor — the ABI has **no setter** — so a
  hostile token cannot be substituted.
- **Overflow** — 0.6.12 predates built-in checks, but `enter`/`leave` use SafeMath
  `.mul`/`.div`/`.sub`, all of which revert on overflow.
- **`totalGamma == 0` branch** — would mint 1:1 while shares exist, dilating holders.
  Unreachable: `leave` burns shares strictly in proportion to the gamma it releases, so
  backing cannot be zeroed without zeroing supply.
- **21 classes** — only class 2 (2 hits, both the `gamma.balanceOf(address(this))` reads)
  and class 9 (3 hits, ERC20 `transferFrom`). Notably classes 4 and 19 **do not fire**,
  because the scanner recognises the ERC4626 share shape but not Bancor checkpoints —
  a scanner gap worth recording, since this is the same vulnerability family.

### Gamma final position

All three in-scope assets examined, none found:

| Asset | Method | Result |
|---|---|---|
| xGamma `0x26805021…` | Sourcify exact-match source, 21 classes, algebra | Donation attack impossible for f<1; CEI and overflow closed |
| Hypervisor `0xa8076ae3…` | 21 classes, live state | No virtual offset — real, but out of scope where live; mature withdraw sound |
| UniProxy `0x83de646a…` | full read | Sound |

Gamma is now genuinely closed rather than closed-on-a-proxy-check. Worth recording that
the one real pattern here is worth $0 because of scope, not because of merit — the same
code on a fresh deployment would be the $50,000 Critical.
