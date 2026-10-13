# Optimism `OptimismPortal2` — the class 13 Critical path, read end to end

Class 13 (bridge proof verification) was the last unread Critical-class pool. 39
strong hits across 11 Immunefi targets, and the meaningful concentration was
**Optimism (5) + AAVE (4)** on the OP Stack withdrawal path — Optimism being a
**$2,000,000** programme.

The full treatment: 21-class recon, reverse engineering, and a line-by-line read of
the proof path in `packages/contracts-bedrock/src/L1/OptimismPortal2.sol` (806 lines).

## Why this path matters

`finalizeWithdrawalTransactionExternalProof` executes **caller-chosen target,
calldata, gas and value** on L1:

```solidity
bytes32 withdrawalHash = Hashing.hashWithdrawal(_tx);
checkWithdrawal(withdrawalHash, _proofSubmitter);
finalizedWithdrawals[withdrawalHash] = true;
l2Sender = _tx.sender;
bool success = SafeCall.callWithMinGas(_tx.target, _tx.gasLimit, _tx.value, _tx.data);
```

Everything else is defensive (reentrancy guard on `l2Sender`, unsafe-target check,
custom-gas-token mode). **The entire security of a $2M bridge reduces to
`checkWithdrawal` → `proveWithdrawalTransaction`.** If a forged proof were accepted,
anyone could execute arbitrary calldata with ETH value on L1.

## The verification chain — complete and correct

`proveWithdrawalTransaction` (`:375`):

| # | Gate | Line |
|---|---|---|
| 1 | not paused | 384 |
| 2 | target is not unsafe | 387 |
| 3 | `anchorStateRegistry.isGameProper(game)` | 400 |
| 4 | `anchorStateRegistry.isGameRespected(game)` | 405 |
| 5 | game did not resolve `CHALLENGER_WINS` | 410 |
| 6 | proof timestamp > game creation | 418 |
| 7 | `outputRootClaim.raw() == Hashing.hashOutputRootProof(_outputRootProof)` | 433 |
| 8 | withdrawal hash proven in the L2 messagePasser trie | 454 |

Gates 3–5 are the post-Fault-Proof additions: the game must be an allowed type, must
have been a *respected* type when created, and must not have resolved against the
proposer. Gate 7 is the pivot — `outputRootClaim` is read from the **resolved dispute
game**, so the caller cannot choose the root; they can only produce a proof against
the game's actual root, which must then hash to that claim. Gate 8 then proves the
withdrawal hash sits in the `L2ToL1MessagePasser` subtree at the recomputed
`keccak256(withdrawalHash, 0)` slot.

`checkWithdrawal` (`:637`) adds replay protection, a proven-timestamp check, a
timestamp-vs-game-creation sanity check, `PROOF_MATURITY_DELAY_SECONDS`, and
`isGameClaimValid`. Five independent gates.

## The DoS that is not a DoS

Line 468, with the comment:

> *"A given user may re-prove a withdrawalHash multiple times, but each proof will
> reset the proof timer."*

Read cold, that is indefinite blocking of a user's withdrawal: reset
`timestamp`, and `block.timestamp - timestamp <= PROOF_MATURITY_DELAY_SECONDS` keeps
failing forever.

**It is not exploitable, and the two-dimensional key is why:**

```solidity
provenWithdrawals[withdrawalHash][msg.sender] = ProvenWithdrawal({ …, timestamp: uint64(block.timestamp) });
```

The record is keyed by *(withdrawalHash, submitter)*. A re-proof only resets **that
submitter's own** entry — it does not touch anyone else's. And `proveWithdrawalTransaction`
is `external` with no access control, so the beneficiary is never dependent on an
attacker's proof: they can simply prove it themselves and finalize against their own
entry. The reset is therefore self-limiting and cannot deny service to anyone.

Worth recording because the surface pattern reads as a Critical and the accounting
says otherwise — the same shape as the `unsafe_burn` note on Bluefin and the
`f < 1` wall on the donation family.

## Verdict

**No finding.** The OP Stack withdrawal path is correctly gated end to end: a
dispute-game-derived root, a proof that must hash to it, a trie inclusion proof for
the specific withdrawal, per-submitter proven records, replay protection, and a
maturity delay. This is the most heavily audited bridge path in the Immunefi set and
it reads that way.

One operational note rather than a finding: `proofSubmitters[withdrawalHash].push(msg.sender)`
grows without bound and is never pruned, while `provenWithdrawals` is overwritten on
re-proof. A withdrawal that many distinct submitters keep re-proving accumulates an
unbounded array. It is not reachable as an attack here, but it is the kind of storage
growth that belongs on a watchlist.
