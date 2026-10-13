# Lido `lido-l2` — a real structural lead that cannot be closed with available access

## The candidate

`contracts/arbitrum/L1ERC20TokenGateway.outboundTransfer`:

```solidity
(address from, uint256 maxSubmissionCost) = L1OutboundDataParser.decode(router, data_);
IERC20(l1Token_).safeTransferFrom(from, address(this), amount_);
```

and `L1OutboundDataParser.decode`:

```solidity
if (msg.sender != router_) {
    return (msg.sender, _parseSubmissionCostData(data_));
}
(address from, bytes memory extraData) = abi.decode(data_, (address, bytes));
return (from, _parseSubmissionCostData(extraData));
```

**Two paths:**

| path | `msg.sender` | `from` used for the pull |
|---|---|---|
| user calls the gateway directly | user | `msg.sender` — **safe** |
| router calls the gateway | `router` | **decoded from router-supplied calldata** |

So when the call comes via the router, the account that gets debited is
attacker-influenceable, and the only remaining protection is `safeTransferFrom`'s
allowance requirement.

## Why it is documented, not accidental

`contracts/arbitrum/README.md:136`:

> *"If the `msg.sender` of the method is the `router_` address, `data_` must contain
> the result of the function call:
> `abi.encode(address from, abi.encode(uint256 maxSubmissionCost, bytes emptyData))`"*

and `:139`: *"Such encoding rules are **required to be compatible with the
`L1GatewaysRouter`**."*

So calldata-derived `from` is deliberate. The security rests entirely on the router
binding `from` to its own `msg.sender` rather than forwarding the user's `_data`
verbatim — which is how Arbitrum's canonical router is understood to behave.

## Why it cannot be closed here

The deciding fact lives **outside this repository**:

- Arbitrum's `L1GatewayRouter` source is not in `lido-l2`. Three plausible paths
  404'd, and the GitHub tree API returns `401 Requires authentication`.
- **Lido's Immunefi scope publishes zero in-scope addresses** (`lido: 0
  in-scope address(es), 19 repo(s)`), so the deployed `router` value cannot be read
  on-chain to confirm which router it is.

Both routes to the deciding fact are closed, by the same two access limits that have
already cost three findings this session:

| limit | consequence |
|---|---|
| Bugcrowd brief pages are client-rendered | submission counts unobtainable |
| **Immunefi `lido` publishes no addresses** | deployed wiring unverifiable |

## Status

**A conditional lead, not a finding.** It is a Critical if — and only if — the router
forwards user-controlled `_data` verbatim. I could not establish that, and I am not
going to claim it.

## What would close it

Any one of:

1. Arbitrum's `L1GatewayRouter` source, from an unauthenticated mirror
2. Lido's deployed `L1ERC20TokenGateway` address, so `router` can be read from the
   constructor slot — requires an address from a non-published source
3. The `lido-l2` deployment JSON in their own deployment repo (not in this one)

With (1) it is a five-minute decision. Without it, reporting would be speculation,
which is the failure mode this whole session has been built to avoid.