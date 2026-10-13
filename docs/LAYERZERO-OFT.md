# LayerZero ($15M) — the highest Immunefi ceiling, checked

Switched to Immunefi-only after I asserted that access, not analysis, was the ceiling.
**That assertion was wrong** and I verified rather than assumed: the local `USDT0`
directory turned out not to be USDT0's contracts at all but a `recon/` workspace of
LayerZero OFT/OApp dependencies with no git remote.

Which redirected rather usefully. LayerZero is **maxBounty 15,000,000** — the highest
Immunefi ceiling in the catalogue — and the OFT/OApp standard in
`LayerZero-Labs/devtools` is what every LayerZero-based token bridges on, including
USDT0 at $6M.

Cloned the real sources:

| repo | .sol files |
|---|---|
| `LayerZero-Labs/devtools` | 314 |
| `LayerZero-Labs/LayerZero-v2` | 206 |

## The check that matters for a bridge OFT

An OFT's entire security model is the inbound path: if anyone can mint themselves,
it is a $15M Critical. `OFTCoreUpgradeable._lzReceive` does **no verification of its
own** — it decodes and credits unconditionally:

```solidity
address toAddress = _message.sendTo().bytes32ToAddress();
uint256 amountReceivedLD = _credit(toAddress, _toLD(_message.amountSD()), _origin.srcEid);
```

All the trust is in the base, `OAppReceiverUpgradeable.lzReceive`, and it is
correct — **two independent gates**:

```solidity
if (address(endpoint) != msg.sender) revert OnlyEndpoint(msg.sender);
if (_getPeerOrRevert(_origin.srcEid) != _origin.sender) revert OnlyPeer(_origin.srcEid, _origin.sender);
```

An attacker cannot forge an inbound packet. They would have to *be* the LayerZero
endpoint — which verifies packet integrity and signature against the DVN/executor
stack — *and* match the peer configured for that source eid. `_getPeerOrRevert`
reverts rather than returning a default, so an unconfigured source cannot slip
through.

`send()` is the mirror and is equally direct: `_debit` → `_lzSend`, with
`_removeDust` rounding **down** (`(_amountLD / rate) * rate`), which favours the
protocol rather than the sender. Standard and safe.

## 21-class recon (314 files)

| class | hits | |
|---|---|---|
| 13 bridge proof | 56 | weak — endpoint/peer verification paths |
| 7 access control | 24 | weak |
| 9 token handling | 12 | weak |
| 5 storage collision | 8 | weak |
| 2 read-only reentrancy | 5 | weak |
| **14 unchecked return** | **2** | **strong** |
| 4, 18, 19 | 1 each | weak |

**11 classes touched, 2 strong hits**, both class 14 in the PreCrime simulator:

```solidity
(bool success, bytes memory returnData) = simulator.call{ value: msg.value }(…)
```

Both *do* capture `success`, so the return value is handled — the flag is a shape
match on low-level `.call`, not an unhandled failure. Verified rather than assumed.

## Verdict

**No finding.** The OFT receive path is correctly gated by endpoint identity and peer
binding, the send path debits before sending with protocol-favouring dust rounding,
and the full 21-class sweep across the OFT/OApp packages surfaces nothing actionable.

This continues the session's pattern at the very top of the Immunefi range: the
ceiling was not the constraint. Across LayerZero ($15M), Cronos ($250k), EverValue
($37k, closed), Bluefin Move ($15k) and Hydration ($222k), every candidate has died on
scope, deployment evidence, or the target's own audit catalogue — never on analysis.
