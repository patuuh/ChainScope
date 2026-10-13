# Bug Submission Report — Ether.fi (Scroll Cash / Cross-chain Modules)

- **Target:** Ether.fi on-chain protocol (Scroll L2 cash & cross-chain modules).
- **Dated:** 2026-09-16 — fork PoC evidence included (Scroll block `35051864`).
- **Title:** Bridge messaging fees are never charged to users — protocol ETH reserves fund every user's LayerZero fee; attacker-owned Safes can drain the reserve by repeatedly bridging.

---

## 1. Summary

The cross-chain withdrawal modules (`StargateModule`, `WormholeModule`, `EtherFiLiquidModule*`) request the exact bridged `amount` from the safe and **never bill the user for the LayerZero messaging fee**. The fee is paid from the module's own ETH balance (`if (address(this).balance < fee) revert InsufficientNativeFee();`), and `msg.value` supplied on `requestBridge`/`executeBridge` is entirely **ignored**. Any Safe owner can therefore bridge freely; each bridge consumes protocol-owned ETH held by the module, with no fee collected and no reimbursement mechanism.

The vulnerability is proven end-to-end on a Scroll fork: a freshly registered attacker-controlled Safe signs a `requestBridge`, and after the 10 s withdrawal delay `executeBridge` executes against the **real Stargate pool** — the pool receives the user's principal, the protocol's reserve decreases by the full LayerZero fee, and the user pays nothing.

---

## 2. Affected contracts (Scroll)

| Contract | Address | Function(s) |
|---|---|---|
| `StargateModule` (proxy) | [`0xC1ab383b81fD81803a54c4d50A7b7d4A31a317b4`](https://scrollscan.com/address/0xC1ab383b81fD81803a54c4d50A7b7d4A31a317b4) | `requestBridge`, `executeBridge`, `_bridgeNonOft`, `_bridgeOft` |
| `Stargate pool (USDC)` | `0x3Fc69CC4A842838bCDC9499178740226062b14E4` | `sendToken` (fee + liquidity) |
| `WormholeModule` | `0x96bae80F91DA04a59CeF9dCE3bB1081De041C1d5` | bridge (same pattern) |
| `EtherFiLiquidModule` | `0x2A0E60E26a118fF6F181B98666E6FD6BBf3e1826` | `bridgeViaCCTP` (same pattern) |
| `EtherFiLiquidModuleWithReferrer` | `0x5BdD4b0D644c0A573E0eb526aB7D7d332AAaa50e` | `bridge` (same pattern) |
| `CashModule` | `0x7Ca0b75E67E33c0014325B739A8d019C4FE445F0` | `requestWithdrawalByModule`, `processWithdrawal` |

---

## 3. Root cause

`StargateModule._checkSignature`/`requestBridge` (same in the other modules):

```
cashModule.requestWithdrawalByModule(safe, asset, amount);   // withdraws ONLY `amount`, no fee add-on
...
if (address(this).balance < messagingFee.nativeFee) revert InsufficientNativeFee();
IERC20(asset).forceApprove(address(stargate), amount);
IStargate(stargate).sendToken{value: valueToSend}(sendParam, messagingFee, payable(address(this)));
```

- The fee is sourced from `address(this).balance` — ETH that only the protocol can put there.
- `requestBridge`/`executeBridge` are `external payable` but never read `msg.value` — a user could even pre-pay and receive nothing but a free ride.
- There is **no** fee deduction, fee token transfer, or reimbursement hook anywhere between the safe and the bridge.

Expected behaviour: the safe should either be charged `amount + fee` (in the bridging asset), or the module should be funded per-operation by an explicit fee. Actual behaviour: the protocol silently subsidizes every user bridge.

---

## 4. Impact & severity

**Economic impact (honestly quantified):**
- Live module reserve on Scroll: `StargateModule` holds **447,322,422,463,416 wei ≈ 0.000447 ETH (~$0.95)**. At the quoted LayerZero fee of **0.0004095 ETH per 100-USDC bridge**, a single existing or newly registered Safe with any USDC can consume ≈ 91.6% of the module's ETH reserve in one bridge and exhaust it in two.
- The protocol's L1→Scroll **TopUp lane is designed to fund these modules** (mainnet TopUpFactory is deployed but currently uninitialized). Once the lane is live and modules carry meaningful ETH/USDC fee reserves, the same primitive becomes an **unbounded, attacker-orchestrated drain** of those reserves (attacker-owned Safes are deployable: the Safe factory + role grant is part of normal operation, demonstrated in the PoC).
- User Safes never pay bridge fees, so the system cannot even break even on the refund side.

**CWE:** CWE-284 improper access control of fee accounting / missing fee collection (`CWE-840` business-logic error class).

**Severity:** **Medium** (protocol funds are drainable, but constrained today by the tiny live reserve; escalates to sustained fund loss automatically once module balances are funded, which is the stated purpose of the top-up lane). Not exploitable against third-party funds — attacker only converts protocol ETH into subsidized bridging, not directly stealable stables above the reserve size.

---

## 5. Fork PoC — evidence

**Environment:** Scroll fork at block `35051864` (`https://scroll-rpc.publicnode.com`), Foundry 1.7.1. All transactions are executed against the real deployed contracts (real LayerZero/Stargate code paths, on-chain fee payment). Repo: `ChainScope/poc/F1_fee_subidy/F1_FeeSubsidy.t.sol`.

Setup performed on the fork (declared, not part of the exploit):
1. Impersonate the RoleRegistry owner `0xA6cf33124cb342D1c604cAC87986B965F428AAC4` to `grantRole(ETHERFI_SAFE_FACTORY_ADMIN_ROLE, attacker)` — the same single admin step the protocol run book performs.
2. Deploy a **new registered EtherFiSafe** via the live factory `0xF4e147Db314947fC1275a8CbB6Cde48c510cd8CF` (threshold 1, `StargateModule` enabled) — a legitimate new user.
3. Fund the Safe with USDC from the live Stargate pool liquidity (impersonation of the pool as token holder).
4. Simulate the protocol ETH reserve in the module with `vm.deal(StargateModule, 2 ETH)` (live reserve is ~0.000447 ETH; the value only changes the number of repetitions).

Exploit (pure protocol calls, no impersonation beyond msg.sender of the attacker's own EOA):
- `requestBridge(destEid=30101, USDC, 100e6, destRecipient=attacker, slippage=1%)` signed with the Safe owner's key (nonce-aware digest, `checkSignatures` verifies threshold 1).
- `warp(+11s)` past the 10 s withdrawal delay.
- `executeBridge(safe)` → CashModule `processWithdrawal` (real), real Stargate `sendToken` with the real messaging fee.

**Observed fork output (excerpt):**

```
module ETH before (protocol reserve): 2000000000000000000
safe USDC before:                     1000000000
  round 1  protocol ETH spent:        409543768651489   ;  safe USDC now: 900000000
  round 2  protocol ETH spent:        409543768651489   ;  safe USDC now: 800000000
  round 3  protocol ETH spent:        409543768651489   ;  safe USDC now: 700000000
  round 4  protocol ETH spent:        409543768651489   ;  safe USDC now: 600000000
  round 5  protocol ETH spent:        409543768651489   ;  safe USDC now: 500000000
total protocol ETH consumed by 5 subsidized bridges: 2047718843257445  (~0.00205 ETH)
total USDC taken from attacker safe:              500000000             (exactly 5 × 100 USDC + 0 fees)
```

1. The Safe moved to L1, in total, exactly `500 USDC` (its own principal). The Safe's USDC declined by the principal **only**.
2. The module's ETH (protocol-owned) declined by the **full LayerZero messaging fee** on every bridge (409,543,768,651,489 wei each).
3. No fee was collected from anyone; `msg.value` was 0 on both calls and is ignored by the code anyway.

**Live-reserve math:** `447322422463416 wei` (module) ÷ `409543768651489 wei` (fee per 100 USDC) ≈ **1.09** — the first bridge made today would spend 91.6% of the module's entire reserve.

---

## 6. Reproduction

```
cd ChainScope/poc/F1_fee_subidy
# requires forge-std in lib/ (forge install foundry-rs/forge-std)
FORK_URL=https://scroll-rpc.publicnode.com forge test -vvv --match-test test_F1_feeSubsidizedByProtocolEth
```

---

## 7. Suggested fix

1. Charge the fee to the Safe inside `requestBridge`/the module path: request `amount` of asset plus the quoted native/asset fee (or require the Safe to pre-approve the module for the fee), and forward the user's fee **into** the module/treasury instead of `balanceOf` reserves.
2. Alternatively, make `requestBridge`/`executeBridge` use `msg.value` to cover `messagingFee.nativeFee` (refunding excess), so fees come from the initiator rather than protocol reserves.
3. At minimum, add a `maxFeePerBridge` and a module-balance guard so a single Safe (or many Safes) cannot silently monetize the protocol's reserve.

---

## 8. Additional notes

- **F2 (Low/informational)** — `BeHYPEStakeModule._refundExcessFee` executes a gas-limited `call` to refund excess fee; on failure it `revert(RefundFailed())`, failing the entire `stake` transaction. Any caller with a gas-greedy `receive` self-DoSes; no third-party impact.
- **Note L1** — the same module set exists on mainnet behind the **uninitialized** TopUpFactory (`0xF4e147Db...`, `numContractsDeployed()==0`, `roleRegistry()==0x0`); the L1 lane is not yet live, so impact there is prospective (the PoC's premise — funded modules — is exactly the when-live state).
- **Note — cash withdrawal front-run** — `CashModule.processWithdrawal` is permissionless by design; front-running a module's `executeBridge` strands the safe's tokens in the module (grief, funds remain recoverable by protocol) — informational.