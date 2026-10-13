# Cronos Public Contracts — read in full, and reverse-engineered

Chosen from the least-mined high ceilings: **$250,000 with 214 prior reports**, against
$300k–500k programmes carrying 337–428. Repo `crypto-org-chain/cronos-public-contracts`.

Small enough to read rather than pattern-match: **5 files, 758 lines** — `CRC20/ModuleCRC20.sol`
(356), `CRC21/ModuleCRC20.sol` (349), `CRC21/ModuleCRC21.sol` (24), `CRC20/CronosCRC20.sol` (17),
`CROBridge/CROBridge.sol` (12). No submodules.

**Scope caveat first:** the README describes this as "contracts, code and audit reports on
Cronos Mainnet Beta **open to the public**". So this is the public subset, and the $250k
programme almost certainly covers a wider private scope. Nothing here should be treated as
the whole attack surface.

## 21-class recon

**10 hits, all weak class-9** (standard ERC20 `transferFrom` at lines 227/230/250/254/258 in
both CRC20 and CRC21). **Zero strong hits.** Clean, and the read confirmed it.

## Reverse engineering

`DSToken` here is the DappHub/MakerDAO implementation — `DSAuth` + `DSMath` + `DSToken`,
one of the most battle-tested ERC20s in existence. Its arithmetic is the canonical
overflow-checked trio:

```solidity
function add(uint x, uint y) internal pure returns (uint z) { require((z = x + y) >= x, ...); }
function sub(uint x, uint y) internal pure returns (uint z) { require((z = x - y) <= x, ...); }
function mul(uint x, uint y) internal pure returns (uint z) { require(y == 0 || (z = x * y) / y == x, ...); }
```

The Cronos layer on top is thin:

```solidity
address constant module_address = 0x89A7EF2F08B1c018D5Cc88836249b84Dd5392905;  // sha256('cronos-evm')[:20]

function unsafe_burn(address addr, uint amount) private { … }               // no approval check
function mint_by_cronos_module(address addr, uint amount) public { require(msg.sender == module_address); mint(addr, amount); }
function burn_by_cronos_module(address addr, uint amount) public { require(msg.sender == module_address); unsafe_burn(addr, amount); }
function send_to_ethereum(address recipient, uint amount, uint bridge_fee) external { unsafe_burn(msg.sender, add(amount, bridge_fee)); … }
function send_to_ibc(string memory recipient, uint amount) public { unsafe_burn(msg.sender, amount); … }
```

## What I checked

**`unsafe_burn` is not reachable on someone else's balance without privilege.** Every
caller passes `msg.sender`; the only path taking an arbitrary `addr` is
`burn_by_cronos_module`, which is `require(msg.sender == module_address)`.

**`auth` is signature-specific, and the internal call passes the *outer* selector.**
`mint_by_cronos_module` calls `mint(addr, amount)` internally, so inside `mint`,
`msg.sender` is still `module_address` but `msg.sig` is
`mint_by_cronos_module(address,uint256)`. `isAuthorized` therefore checks the module
against the *outer* signature, so a module authorised for `mint` alone cannot mint
through this path. Correct.

**`send_to_ethereum` can only burn the caller's own tokens.** `recipient` and
`bridge_fee` are attacker-chosen but both only affect how much of the *sender's* balance
is destroyed — a caller choosing a huge fee burns their own money. Self-harm, not theft.

## Verdict

**No exploitable finding.** The ds-token base is sound and the bridge layer's privileged
paths are correctly gated.

Two trust assumptions, not bugs, and worth recording because they are where the real
risk sits:

1. **`module_address` is `sha256('cronos-evm')[:20]`** — a deterministic, publicly
   derivable address. That is deliberate (a deterministic module address can be verified
   by anyone, and the Gravity bridge pattern depends on it), but it means the entire
   mint authority for the bridged supply rests on whoever controls that key. And because
   `mint` is `auth`, whoever is `owner` can also mint directly — so the security model
   rests on the owner key as much as the module key.
2. **`send_to_ethereum` / `send_to_ibc` burn and emit an event with no on-chain effect
   beyond the burn.** There is no nonce, no replay protection, and no signature in this
   contract. The bridge module is trusted to consume each event exactly once. If it
   double-consumes, users lose funds with no recourse at this layer — a trust assumption
   in the bridge, invisible from here.

Both are architecture, not defects, and both would be out of scope for a contracts-only
programme that lists this public subset.
