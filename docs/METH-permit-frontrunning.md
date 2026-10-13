# mETH — `Staking.unstakeRequestWithPermit` can be griefed by permit front-running

**Severity:** Medium
**Program:** mETH / Instascope (Immunefi) — CRIT $500,000 · HIGH $100,000 · MEDIUM **$5,000**
**Contract in scope:** `Staking` — `0xe3cBd06D7dadB3F4e6557bAb7EdD924CD1489E8f` (chain 1)
**Implementation:** `0x01a360392c74b5b8bf4973f438ff3983507a06a2` (EIP-1967 proxy)
**Same class as:** Lido DAO issue #803 — reported via Immunefi, rated Medium, **paid**, still open with label `next upgrade`

---

## Impact

**What happens.** A user who submits a withdrawal using `unstakeRequestWithPermit` sends
their signature `(v, r, s)` as **public calldata**. Anyone watching the mempool can copy
that signature out of the pending transaction and submit the permit themselves before the
victim's transaction lands. The ERC-2612 nonce is consumed by the attacker's call. The
victim's transaction then reverts with `ERC20Permit: invalid signature`, and **their
withdrawal request is never created**.

**What the attacker gains.** Nothing directly. This is pure griefing — no profit motive,
which is exactly how mETH's own scope defines its Medium tier:

> *Medium — Griefing (e.g. no profit motive for an attacker, but damage to the users or
> the protocol)*

**Concrete damage.**
- The victim cannot unstake. They must produce a fresh signature and submit again. If a
  watcher is front-running reliably, they can repeat indefinitely.
- Withdrawal is the user's exit path. Denial of exit is a **liveness** problem for
  stakers, and it becomes materially worse the longer it persists — mETH's withdrawal
  queue already involves a finalization delay, so a user who keeps losing the race is
  delayed on top of an existing delay.
- The cost to the attacker is one `eth_call`-equivalent transaction per attempt, and they
  can automate it across all pending permit-based withdrawals.

**Impact mapping against the published impact list.** This matches **two**
listed Medium tiers, not one:

| Listed impact | Applies | Reason |
|---|---|---|
| **Medium — Griefing** (no profit motive, but damage to users) | yes | The user cannot submit their withdrawal at all |
| **Medium — Susceptibility to frontrunning** | yes | It is a frontrunning susceptibility, and only the permit path is affected |
| Critical — Permanent freezing of staked funds | **no** | A signature-free path exists (see below) |
| High — Permanent freezing of unclaimed / tokenized staking yield | **no** | same |
| High — Protocol insolvency / theft of unclaimed yield | **no** | No value moves; the victim's mETH is untouched |

**Why this is not Critical or High.** No funds are stolen, no principal is lost, and
protocol solvency is unaffected. The user's mETH is intact; only their ability to submit
one transaction is. The mitigating factor is that the non-permit path
`unstakeRequest(uint128,uint128)` exists and is unaffected — a user can approve `Staking`
once and use the plain path. That is precisely why Lido rated the identical issue Medium.

**Practical mitigation available to users today.** Call `mETH.approve(staking, X)` first,
then use `unstakeRequest`. Not stated in the NatSpec, which is why users reach for the
permit variant.

This is the single fact separating this finding from Critical, so it is verified on
deployed bytecode rather than read from source:

| Contract | Function | Selector | In deployed bytecode |
|---|---|---|---|
| mETH `0x052f52748109bae13d6319a463d64b6a2a613e52` | `approve(address,uint256)` | `0x095ea7b3` | yes |
| mETH `0x052f52748109bae13d6319a463d64b6a2a613e52` | `allowance(address,address)` | `0xdd62ed3e` | yes |
| Staking `0x01a360392c74b5b8bf4973f438ff3983507a06a2` | `unstakeRequest(uint128,uint128)` | `0x891ef43e` | yes |

Two directions were checked, and both are safe:

- `approve` can only be called by the token owner, so an attacker cannot front-run
  the victim into granting an allowance to themselves.
- `unstakeRequest` pulls `mETH` from `msg.sender`, so an attacker invoking it with a
  victim's allowance would move only their own tokens.

Note: this is trivially the piece most likely to be wrong, because `approve` lives on
the **mETH token**, not on Staking, and Staking itself is a proxy - checking the
right contract matters.

### Re-verification — 2026-10-02, behavioural rather than selector-scan

The table above was originally established by checking whether each selector appears
as a literal in the deployed bytecode. That method was later found to be unsound:
`extract_selectors` reads `PUSH4` immediates, and modern solc dispatches via a binary
search over range comparisons, so those immediates are bounds rather than selectors.
Re-verified behaviourally via `eth_call`, classifying each function by **differential
revert comparison** against an impossible selector:

| Contract | Function | Result |
|---|---|---|
| Staking impl `0x01a36039…` | `unstakeRequestWithPermit(uint128,uint128,uint256,uint8,bytes32,bytes32)` | **present** |
| Staking proxy `0xe3cBd06D…` | same | **present** |
| Staking impl `0x01a36039…` | `unstakeRequest(uint128,uint128)` | **present** |
| Staking impl `0x01a36039…` | `approve(address,uint256)` | **absent** |
| Staking impl `0x01a36039…` | `allowance(address,address)` | **absent** |
| mETH `0x052f5274…` | `approve(address,uint256)` | reachable when given real arguments |

The EIP-1967 implementation slot on the proxy was re-read and still resolves to
`0x01a360392c74b5b8bf4973f438ff3983507a06a2`, matching the implementation this
finding was written against.

**Both load-bearing claims survive.** `unstakeRequestWithPermit` is reachable on the
deployed contract, and Staking exposes no ERC-20 allowance — which is what separates
this finding from Critical. Without Staking, a front-runner's `permit` would hand the
victim's signature to a spender that could use it; with no allowance anywhere in
Staking, the signature is simply spent and the request is lost.

One methodological note worth keeping: Staking answers *every* unknown selector with
a custom error (`0x34352c73`). Read naively, `approve` reverting looked identical to
"function present, logic rejected", which would have inverted the severity limiter.
Only the differential comparison shows it is genuinely absent.

---

## Root cause

`contracts/src/Staking.sol:362` in the **deployed** implementation:

```solidity
function unstakeRequestWithPermit(
    uint128 methAmount,
    uint128 minETHAmount,
    uint256 deadline,
    uint8 v,
    bytes32 r,
    bytes32 s
) external returns (uint256) {
    SafeERC20Upgradeable.safePermit(mETH, msg.sender, address(this), methAmount, deadline, v, r, s);
    return _unstakeRequest(methAmount, minETHAmount);
}
```

`safePermit` is called **unconditionally**. There is no check for a pre-existing
allowance, so a permit is always consumed even when one was already granted.

**Evidence the check does not exist:** the string `allowance` occurs **0 times** in the
entire deployed `Staking.sol` (24,000+ lines across the file set).

Lido's fix for the identical issue is exactly the missing branch:

```solidity
if (STETH.allowance(msg.sender, address(this)) < _permit.value) {
    STETH.permit(msg.sender, address(this), _permit.value, _permit.deadline, _permit.v, _permit.r, _permit.s);
}
```

---

## Why this is not covered by the published audits

mETH's scope excludes *"Any issues identified in Published Audits"*
(docs.mantle.xyz/meth/security/audits), so this was verified rather than assumed.

Two audits cover "Token and Vault Smart Contracts", which is where `Staking.sol` lives:

| Audit | Pages | `permit` / `WithPermit` / `safePermit` / `ERC20Permit` |
|---|---|---|
| Hexens 230825 | 70 | **0** |
| MixBytes 231030 | 29 | **0** |

The MixBytes report cites line numbers in both `Staking.sol` and
`UnstakeRequestsManager.sol`, so it demonstrably covered this file — yet never mentions
permit. The three `permit` string hits in the Hexens PDF are OCR noise from the word
*"permitted"* inside code comments.

The function has existed since the first public commit (`cc90a99`, 2023-10-06), so it
was in scope for both.

MixBytes' two front-running findings are unrelated: **M-4** `cancelUnfinalizedRequests`
DoS and **L-3** `topUp` front-running.

---

## Coverage gap

The function **is** tested — but only on the happy path
(`test/Staking.t.sol:886`, `testPermitUnstakeSuccess`). The front-running case has no
coverage. That is how it survived three and a half years.

---

## Steps to reproduce

### 1. Clone and build

```bash
git clone --recurse-submodules https://github.com/mantle-lsp/contracts.git
cd contracts
forge build
```

### 2. Run the PoC

PoC file: `test/PermitFrontRunning.t.sol` (reuses the project's own `StakingTest` harness).

```bash
forge test --match-contract PermitFrontRunning -vv
```

Expected — control proves the function works normally, attack proves the griefing:

```
[PASS] testPermitUnstakeSucceedsWhenNotFrontRun()
[PASS] testPermitUnstakeGriefedByFrontRunner()
Suite result: ok. 2 passed; 0 failed; 0 skipped
```

### 3. The attack, step by step

In `testPermitUnstakeGriefedByFrontRunner`:

```solidity
// 1. Victim signs and broadcasts. (v, r, s) are calldata — anyone can read them.
SignerUtils.Permit memory permit = SignerUtils.Permit({
    owner: victim, spender: address(staking), value: methAmount,
    nonce: nonceBefore, deadline: deadline
});
(uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, SignerUtils.getTypedDataHash(mETH.DOMAIN_SEPARATOR(), permit));

// 2. ATTACKER replays the victim's own signature, front-running the request.
vm.prank(attacker);
mETH.permit(victim, address(staking), methAmount, deadline, v, r, s);

// 3. The nonce is consumed by the attacker's call.
assertGt(mETH.nonces(victim), nonceBefore, "attacker consumed the victim's permit nonce");

// 4. The victim's still-pending transaction can no longer be valid.
vm.prank(victim);
vm.expectRevert("ERC20Permit: invalid signature");
staking.unstakeRequestWithPermit(methAmount, 0, deadline, v, r, s);
```

### 4. Against a live fork

The same sequence replays on mainnet at `0xe3cBd06D…`: read a pending
`unstakeRequestWithPermit` from the mempool, extract `(v, r, s)`, submit
`mETH.permit(victim, staking, amount, deadline, v, r, s)` with higher gas, and the
victim's transaction reverts.

---

## Deployed-code verification

| Check | Result |
|---|---|
| Staking proxy | EIP-1967 → implementation `0x01a360392c74b5b8bf4973f438ff3983507a06a2` |
| Sourcify (implementation) | `exact_match`, verified 2025-10-30 |
| Deployed `Staking.sol` vs repo `Staking.sol` | **byte-identical**, md5 `7ca18fb00d4884b087e971a2674e3bac` |
| `unstakeRequestWithPermit(uint128,uint128,uint256,uint8,bytes32,bytes32)` | present on deployed bytecode |
| `permit`, `nonces` | present — standard ERC-2612, nonce-protected |
| `allowance` occurrences in deployed `Staking.sol` | **0** |

---

## Suggested fix

Adopt Lido's allowance pre-check so an already-approved allowance does not consume a fresh
permit:

```solidity
if (mETH.allowance(msg.sender, address(this)) < methAmount) {
    mETH.permit(msg.sender, address(this), methAmount, deadline, v, r, s);
}
```

Alternatively, document `approve` + `unstakeRequest` as the recommended path and
deprecate the permit variant.

---

## Note on `LRTUnstakingVault.sol#L361`

The MixBytes finding **M-1** ("some unstake requests can get uncancellable") is
**acknowledged, not fixed**, and sits in the same withdrawal path as this finding. It was
not raised here — it is a known, published issue.
