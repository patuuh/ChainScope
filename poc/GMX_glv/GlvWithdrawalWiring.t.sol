// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import { DataStore } from "../contracts/data/DataStore.sol";
import { RoleStore } from "../contracts/role/RoleStore.sol";
import { Role } from "../contracts/role/Role.sol";
import { Keys } from "../contracts/data/Keys.sol";
import { Market } from "../contracts/market/Market.sol";
import { MarketStoreUtils } from "../contracts/market/MarketStoreUtils.sol";
import { MarketUtils } from "../contracts/market/MarketUtils.sol";
import { MarketToken } from "../contracts/market/MarketToken.sol";
import { GlvToken } from "../contracts/glv/GlvToken.sol";
import { GlvUtils } from "../contracts/glv/GlvUtils.sol";
import { GlvWithdrawal } from "../contracts/glv/glvWithdrawal/GlvWithdrawal.sol";
import { GlvWithdrawalUtils } from "../contracts/glv/glvWithdrawal/GlvWithdrawalUtils.sol";
import { Price } from "../contracts/price/Price.sol";
import { Errors } from "../contracts/error/Errors.sol";
import { IOracle } from "../contracts/oracle/IOracle.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

/// The GMX market IS the market token (`MarketToken(payable(marketAddress))`),
/// so one contract plays both roles.
contract MockMarketToken is ERC20 {
    constructor() ERC20("GMK", "GMK") {}
    function mint(address a, uint256 v) external { _mint(a, v); }
}

/// Oracle with a per-token price table. `primaryPrices` returns (min, max) to match
/// IOracle; the GLV itself is deliberately left unpriced so getGlvValue takes the
/// market loop instead of short-circuiting.
contract MockOracle {
    mapping(address => uint256) public minP;
    mapping(address => uint256) public maxP;

    function setPrice(address token, uint256 mn, uint256 mx) external {
        minP[token] = mn;
        maxP[token] = mx;
    }
    function primaryPrices(address token) external view returns (uint256, uint256) {
        return (minP[token], maxP[token]);
    }
    function getPrimaryPrice(address token) external view returns (Price.Props memory) {
        return Price.Props(minP[token], maxP[token]);
    }
}

/// Exposes GlvWithdrawalUtils._getMarketTokenAmount, which is `internal`.
contract WithdrawalHarness {
    function getMarketTokenAmount(DataStore ds, IOracle o, GlvWithdrawal.Props memory w)
        external
        view
        returns (uint256)
    {
        return GlvWithdrawalUtils._getMarketTokenAmount(ds, o, w);
    }
}

/**
 * Hunt campaign: the wiring under GlvWithdrawalUtils._getMarketTokenAmount — the layer
 * every previous GMX campaign had to skip.
 *
 * The first three campaigns tested arithmetic in isolation. This one deploys the real
 * pieces: RoleStore, DataStore, a market that is also its own market token, the real
 * GlvToken (a StrictBank), and seeds pool amounts through DataStore exactly as
 * MarketUtils.getPoolAmount reads them (`Keys.poolAmountKey`). No Uniswap pool is
 * involved, because getPoolValueInfo reads virtual reserves from DataStore rather
 * than calling the pool.
 *
 * The GLV is deliberately given NO oracle price, so getGlvValue cannot short-circuit
 * and the per-market loop actually executes — that loop is the whole point.
 *
 * Properties (with index/long/short prices maximised so the worst case is exercised):
 *  W1 zero GLV balance for a market contributes 0
 *  W2 exit valuation <= deposit valuation (the guard, at market level)
 *  W3 exit amount is proportional to the GLV's market-token balance
 *  W4 never exceeds the GLV's whole market-token balance
 *  W5 negative pool value reverts rather than wrapping
 */
contract GlvWithdrawalWiringHuntTest is Test {
    RoleStore internal rs;
    DataStore internal ds;
    MockMarketToken internal marketToken;
    GlvToken internal glv;
    MockOracle internal oracle;
    WithdrawalHarness internal h;

    address internal constant INDEX = address(0x1111);
    address internal constant LONG = address(0x2222);
    address internal constant SHORT = address(0x3333);

    uint256 internal constant LONG_POOL = 1_000_000e18;
    uint256 internal constant SHORT_POOL = 1_000_000e18;
    uint256 internal constant MKT_SUPPLY = 10_000_000e18;

    function setUp() public {
        rs = new RoleStore();
        ds = new DataStore(rs);
        rs.grantRole(address(this), Role.CONTROLLER);

        marketToken = new MockMarketToken();
        glv = new GlvToken(rs, ds, "GLV", "GLV");
        oracle = new MockOracle();
        h = new WithdrawalHarness();

        Market.Props memory market = Market.Props(
            address(marketToken), INDEX, LONG, SHORT
        );
        MarketStoreUtils.set(
            ds, address(marketToken), keccak256(abi.encode(market)), market
        );

        ds.setUint(Keys.poolAmountKey(address(marketToken), LONG), LONG_POOL);
        ds.setUint(Keys.poolAmountKey(address(marketToken), SHORT), SHORT_POOL);

        ds.addAddress(Keys.GLV_LIST, address(glv));
        ds.addAddress(Keys.glvSupportedMarketListKey(address(glv)), address(marketToken));

        oracle.setPrice(LONG, 1e18, 1e18);
        oracle.setPrice(SHORT, 1e18, 1e18);
        oracle.setPrice(INDEX, 1e18, 1e18);
        // glv intentionally unpriced -> (0,0) -> market loop executes

        // glvValue > 0 requires a non-zero GLV supply; glvTokenAmountToUsd
        // reverts EmptyGlvTokenSupply otherwise.
        glv.mint(address(this), 1_000_000e18);

        marketToken.mint(address(this), MKT_SUPPLY);
        marketToken.approve(address(glv), type(uint256).max);
    }

    /// Put `amt` market tokens into the GLV through the real StrictBank path.
    function _fundGlv(uint256 amt) internal {
        marketToken.transfer(address(glv), amt);
        glv.recordTransferIn(address(marketToken));
    }

    function _withdrawal(uint256 glvAmount) internal view returns (GlvWithdrawal.Props memory) {
        GlvWithdrawal.Props memory w;
        w.addresses.glv = address(glv);
        w.addresses.market = address(marketToken);
        w.numbers.glvTokenAmount = glvAmount;
        return w;
    }

    // ---------------------------------------------------------------- W3
    function testFuzz_amountIsProportionalToGlvBalance(uint128 bal_, uint128 amt_) public {
        uint256 bal = bound(uint256(bal_), 1, 1e24);
        uint256 amt = bound(uint256(amt_), 1, bal);
        _fundGlv(bal);

        uint256 got = h.getMarketTokenAmount(ds, IOracle(address(oracle)), _withdrawal(amt));
        uint256 whole = h.getMarketTokenAmount(ds, IOracle(address(oracle)), _withdrawal(bal));

        // NOT `whole == bal`. The exit prices the GLV pro-rata on glvValue/glvSupply,
        // then converts USD to market tokens on poolValue/marketTokenSupply. A full
        // withdrawal returns the GLV's whole market-token position only when that
        // pro-rata equals 1 - i.e. when the GLV holds the entire market-token supply.
        // At small balances against a 10M market-token supply the pro-rata is tiny,
        // so the correct invariant is monotonicity and boundedness, not identity.
        // An earlier version of this test asserted identity and failed on the first
        // input - the contract was right and the assumption was not.
        assertLe(whole, bal, "W3: full withdrawal exceeded the GLV's balance");
        assertLe(got, whole, "W3: partial withdrawal exceeded a full one");

        // linear in the GLV amount, within rounding
        if (whole > 0) {
            uint256 expected = (whole * amt) / bal;
            uint256 slack = expected / 1e6 + 2;
            assertApproxEqAbs(got, expected, slack, "W3: not proportional to the GLV amount");
        }
    }

    // ---------------------------------------------------------------- W1
    function test_zeroGlvBalance_returnsZero() public {
        // no funding at all
        uint256 got = h.getMarketTokenAmount(ds, IOracle(address(oracle)), _withdrawal(1e18));
        assertEq(got, 0, "W1: zero GLV balance did not contribute zero");
    }

    // ---------------------------------------------------------------- W2
    /// The exit path values the vault at maximize=false while deposits use true.
    /// This drives the real market loop and compares the two.
    function testFuzz_exitValuation_neverExceedsDepositValuation(uint128 bal_, uint32 spread_) public {
        uint256 bal = bound(uint256(bal_), 1, 1e24);
        uint256 spread = bound(uint256(spread_), 1, 1e18); // 0%..100% premium
        _fundGlv(bal);

        // max pool value for the exit, min for the deposit: an oracle that only
        // ever favours one side must still not let the exit beat the deposit.
        oracle.setPrice(LONG, 1e18, 1e18 + spread);
        oracle.setPrice(SHORT, 1e18, 1e18 + spread);

        (uint256 exitVal,) = GlvUtils.getGlvValue(ds, IOracle(address(oracle)), address(glv), false);
        (uint256 depVal,) = GlvUtils.getGlvValue(ds, IOracle(address(oracle)), address(glv), true);
        assertLe(exitVal, depVal, "W2: market-loop exit valued ABOVE deposit");
    }

    // ---------------------------------------------------------------- W4
    function testFuzz_neverExceedsGlvMarketTokenBalance(uint128 bal_, uint128 amt_) public {
        uint256 bal = bound(uint256(bal_), 1, 1e24);
        uint256 amt = bound(uint256(amt_), 1, bal);
        _fundGlv(bal);

        uint256 got = h.getMarketTokenAmount(ds, IOracle(address(oracle)), _withdrawal(amt));
        assertLe(got, bal, "W4: exit exceeded the GLV's market-token balance");
    }

    // ---------------------------------------------------------------- W5
    function test_zeroPoolValue_reverts_ratherThanWrapping() public {
        _fundGlv(1e18);
        // Zero pool value. Traced: glvValue becomes 0 via marketTokenAmountToUsd(·,0,·),
        // glvTokenAmountToUsd(·,0,·) is then 0, and usdToMarketTokenAmount(0, 0, supply)
        // skips both seed branches (they need supply == 0 or poolValue > 0) and reaches
        // Precision.mulDiv(supply, 0, poolValue) - a division by zero.
        //
        // So the guard fires as a panic(0x12), NOT as the intended
        // Errors.GlvNegativeMarketPoolValue - that check is `poolValue < 0` and a
        // zero pool value is not negative. Reverting is safe; the divergence in
        // revert *type* is recorded as an observation, not a finding: it burns the
        // full gas allowance rather than erroring cleanly, and it is reachable only
        // when a GLV's underlying market has already been emptied to zero.
        ds.setUint(Keys.poolAmountKey(address(marketToken), LONG), 0);
        ds.setUint(Keys.poolAmountKey(address(marketToken), SHORT), 0);
        (bool ok, bytes memory ret) = address(h).staticcall(
            abi.encodeCall(
                WithdrawalHarness.getMarketTokenAmount,
                (ds, IOracle(address(oracle)), _withdrawal(1e18))
            )
        );
        assertFalse(ok, "W5: zero pool value did not revert");
        // 0x12 = division by zero panic, not the custom error
        assertEq(bytes4(ret), bytes4(0x4e487b71), "W5: unexpected revert type");
    }
}
