# Lido — state after the CRIT/HIGH/MEDIUM pass

Programme rules that reshaped the approach:
- **"Only accept reports targeting deployed contracts, not latest contracts in repos."**
- Pausable components: only the **initial 1-hour** window counts. Upgrade-only: 5 days Critical, 9 days otherwise.
- Impacts are enumerated explicitly: Critical = theft of user funds, permanent freezing
  of funds, protocol insolvency, governance voting manipulation. High = theft/freezing
  of tokenized yield, **acquiring admin rights without owner action**, missing access
  controls, economic attacks, treasury loss. Medium = griefing, block stuffing for
  profit, frontrunning.

The repo is `lidofinance/core` (NOT `lido-core`, which does not exist — I got that
wrong first). 129 files / 34,421 lines.

## Resolved: the `UpgradeTemporaryAdmin` lead is out of scope

`completeSetup(...)` is `external` with **no access control** — only a one-shot
`isSetupComplete` flag and nine zero-address checks — and every target address is
caller-supplied:

```solidity
function _setupConsolidationBus(address _bus, address _migrator, address _committee) private {
    IAccessControl(_bus).grantRole(REMOVE_ROLE, _committee);   // caller-supplied
    _transferAdminToAgent(_bus);                                // admin -> AGENT
}
```

Every `grantRole` only succeeds because this contract *temporarily holds* admin, so
whoever calls first hands `REMOVE_ROLE` / `PAUSE_ROLE` / `RESUME_ROLE` on Lido's
consolidation stack to their own addresses. That maps verbatim to the named High
*"acquiring admin rights without owner action"*.

**It is not in the deployed-contracts list.** Per the programme's own rule, a repo-only
contract is not a reportable target. Closed as out of scope — cleanly, and only because
the deployment list was consulted.

## Clean negatives

- **CircuitBreaker** (`src/CircuitBreaker.sol`): every mutator is `onlyAdmin`;
  `heartbeat()`/`pause()` are pauser-gated; `pause()` unregisters the pauser *before*
  the external `pauseFor` call, so CEI holds and re-entry fails the `getPauser` check.
- **`ERC20Bridged.initialize`** — `external`, unguarded, no flag, exactly class 1's
  shape. It survives only because `_setERC20MetadataName` reverts on a non-empty value.
  Load-bearing on an empty-string check rather than an initialisation flag: a future
  setter bypassing it would re-open a rename path on a bridged token, which is a
  phishing vector on exchange listings.
- **`lido-l2`** 21-class recon: 13 hits, 3 strong, all class 1, all guarded.

## Deployment axis on 14 mainnet contracts

| contract | model | impl | init |
|---|---|---|---|
| Withdrawal Queue ERC721 | proxy | `0xe42c659dc0` | **inconclusive** |
| Withdrawal Vault | proxy | `0xfb4521bd15` | **inconclusive** |
| Accounting | proxy | `0x3aa937ac2a` | **inconclusive** |
| Consolidation Migrator | proxy | `0x6fb4c152f0` | **inconclusive** |
| Consolidation Bus | proxy | `0xffde8acab9` | **inconclusive** |
| Consolidation Gateway, CircuitBreaker, Stonks ×2, NEST ×2, Triggerable Wd Gateway, wstETH | direct | — | n/a |

One useful confirmation: the on-chain implementations match the docs'
(`Withdrawal Vault` impl `0xfB4521BD151BFB45DB6045D2d07e58e0f597e340` on-chain ==
documented), so the deployed code corresponds to what the docs publish.

**`inconclusive` is not `clean`.** Four proxies carry implementations whose
initialisation cannot be read through `eth_call`; that needs dispatcher analysis of the
implementation bytecode, which is the known open item in `cs_init`.

## Open, and what it would take

1. **`Accounting` (`0x23ED611b…`)** — "protocol insolvency" is a named Critical and this
   is the contract that decides solvency. Unread.
2. **`Withdrawal Queue`** — "permanent freezing of funds" Critical. Unread.
3. Dispatcher analysis of the four inconclusive proxies.
4. **`Stonks`** (`0x8c595aA4…` LP, `0xb368586C…` Treasury) — the LP vault, which is the
   donation/share family that has produced findings across three other protocols this
   session.

## `Accounting` solvency math — verified sound, and a near-miss of mine

Reward bands make this the contract that matters: **Critical $50k–$2M requires ≥$2M of
user funds at risk**, so the solvency math is where the money is.

`_calculateFeeDistribution` (`Accounting.sol:335`):

```solidity
uint256 moduleFeeShares = (_totalSharesToMintAsFees * moduleFee) / _totalFee;
totalModuleFeeShares += moduleFeeShares;
...
treasurySharesToMint = _totalSharesToMintAsFees - totalModuleFeeShares;   // :356
```

Concern: whether the summed per-module floors can exceed the total, underflowing that
subtraction and reverting the oracle report.

**My first property test said yes — 150,835 "violations" in 200,000 trials.** That
would have been a Critical solvency finding.

**My test was wrong.** I generated each module's fee independently, so their sum exceeded
`_totalFee`. The real precondition is that `stakingModuleFees` **partitions** `_totalFee`.

Under the correct precondition: **0 violations in 300,000 trials** — `total - sum` cannot
underflow and the distribution is sound. Line 331's `postInternalEther - feeEther`
denominator is bounded by 0.8.9 checked arithmetic, so it reverts rather than wrapping.

**No finding in Accounting.**
