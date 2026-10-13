// SPDX-License-Identifier: GPL-3.0
pragma solidity 0.8.10;

import {L1OutboundDataParser} from "../contracts/arbitrum/libraries/L1OutboundDataParser.sol";

/// Exposes the real internal parser. Testing the library avoids the
/// BridgingManager proxy-slot gate, which is deployment wiring, not the question.
contract ParserHarness {
    function decodeAs(address router, bytes memory data)
        external
        view
        returns (address from, uint256 maxSubmissionCost)
    {
        return L1OutboundDataParser.decode(router, data);
    }
}

/// The parser branches on `msg.sender`, so to take the router branch the CALLER
/// must be the router. This contract is deployed at the router address and is the
/// only caller of the harness, so `msg.sender` inside the library is `ROUTER`.
contract RouterCaller {
    ParserHarness internal immutable harness;

    constructor(ParserHarness harness_) {
        harness = harness_;
    }

    function relay(bytes memory data)
        external
        view
        returns (address from, uint256 cost)
    {
        return harness.decodeAs(address(this), data);
    }
}

/**
 * Does L1OutboundDataParser constrain the debited account when the caller is the
 * router? This is the whole of Lido's bridge gateway `from` handling.
 *
 * Direct call  (msg.sender != router): `from` MUST equal msg.sender, calldata cannot
 *               impose another account. This is the safety property.
 * Router call  (msg.sender == router): `from` is whatever calldata says.
 *
 * If the second holds, the gateway imposes no constraint of its own and the only
 * remaining protection on safeTransferFrom(from, ...) is the ERC20 allowance.
 * Whether Arbitrum's canonical L1GatewayRouter would forward user-controlled
 * bytes into that slot is a separate question, in a contract not in this repo.
 */
contract FromBindingTest {
    ParserHarness internal h;
    RouterCaller internal routerCaller;

    /// Must NOT equal the caller: the parser branches on `msg.sender`, and
    /// `msg.sender` inside the library is this test contract. Passing
    /// address(this) as the router silently takes the ROUTER branch, not the direct
    /// one - which is how the first version of this file "confirmed" the wrong
    /// thing.
    address internal constant SOME_OTHER_ROUTER = address(0xDEAD);
    address internal constant VICTIM = address(0xACE);
    address internal constant STRANGER = address(0xBAD);

    event FINDING(string);

    constructor() {
        h = new ParserHarness();
        routerCaller = new RouterCaller(h);
    }

    /// Router-branch encoding: abi.encode(from, abi.encode(cost, emptyBytes))
    function _routerData(address from, uint256 cost) internal pure returns (bytes memory) {
        return abi.encode(from, abi.encode(cost, bytes("")));
    }

    /// Non-router encoding: abi.encode(cost, emptyBytes)
    function _directData(uint256 cost) internal pure returns (bytes memory) {
        return abi.encode(cost, bytes(""));
    }

    /// SAFETY PROPERTY: a direct caller is always the debited account, and cannot
    /// be redirected by calldata naming someone else.
    function test_directCaller_isAlwaysDebited() public {
        (address from, ) = h.decodeAs(SOME_OTHER_ROUTER, _directData(0));
        require(from == address(this), "direct caller must be the debited account");
        emit FINDING("PASS: direct path binds from = msg.sender");
    }

    /// Confirms the direct path really does ignore the calldata address, by showing
    /// the router encoding is REJECTED there rather than silently honoured.
    function test_directPath_rejectsRouterFormat() public {
        (bool ok, ) = address(h).staticcall(
            abi.encodeWithSignature(
                "decodeAs(address,bytes)", SOME_OTHER_ROUTER, _routerData(VICTIM, 0)
            )
        );
        require(!ok, "direct path must not accept the router encoding");
        emit FINDING("PASS: direct path rejects the router encoding outright");
    }

    /// THE CASE THAT MATTERS: as the router, calldata alone decides the account.
    function test_asRouter_fromComesFromCalldata() public {
        (address from, uint256 cost) = routerCaller.relay(_routerData(VICTIM, 7));
        require(from == VICTIM, "as router, calldata account should be returned");
        require(cost == 7, "cost should decode normally");
        emit FINDING("CONFIRMED: as router, `from` is whatever calldata says");
    }

    /// Any arbitrary address, not a privileged subset.
    function test_asRouter_acceptsArbitraryAddress() public {
        (address from, ) = routerCaller.relay(_routerData(STRANGER, 0));
        require(from == STRANGER, "arbitrary address accepted verbatim");
        emit FINDING("CONFIRMED: arbitrary address accepted, not a whitelist");
    }

    /// The inner extraData must be empty - that guard does hold.
    function test_innerExtraDataMustBeEmpty() public {
        bytes memory data = abi.encode(VICTIM, abi.encode(uint256(0), bytes("deadbeef")));
        (bool ok, ) = address(routerCaller).staticcall(
            abi.encodeWithSignature("relay(bytes)", data)
        );
        require(!ok, "non-empty inner extraData must revert");
        emit FINDING("PASS: inner extraData guard holds");
    }

    /// Malformed inner encoding must revert, not silently default to a zero cost.
    function test_malformedInnerReverts() public {
        (bool ok, ) = address(routerCaller).staticcall(
            abi.encodeWithSignature("relay(bytes)", abi.encode(VICTIM, hex"1234"))
        );
        require(!ok, "malformed inner encoding must revert");
        emit FINDING("PASS: malformed inner encoding reverts rather than defaulting to 0");
    }

    function run() public {
        test_directCaller_isAlwaysDebited();
        test_directPath_rejectsRouterFormat();
        test_asRouter_fromComesFromCalldata();
        test_asRouter_acceptsArbitraryAddress();
        test_innerExtraDataMustBeEmpty();
        test_malformedInnerReverts();
        emit FINDING("ALL CONFIRMED");
    }
}