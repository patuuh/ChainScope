// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import "forge-std/Test.sol";
import {Diamond, DiamondDeployer, FacetA, DiamondLoupeFacet} from "../src/Diamond.sol";

/// @notice Pins the properties ChainScope's diamond branch depends on.
///
/// The analyzer detects a diamond by calling `facets()` on the address and
/// reading the returned facet list. That only proves anything if the fixture is
/// faithful: a diamond whose loupe is reachable only through the standard
/// fixed-slot storage and a fallback dispatcher, with facet logic living in
/// separate contracts. A fixture that inlined everything would validate nothing.
///
/// The first version of this fixture read its registry through
/// `IDiamondStorage(msg.sender)`, which looks equivalent but is not: under
/// `cast call` msg.sender is the zero address, and under DELEGATECALL a facet
/// sees the original caller rather than the diamond. Real loupes bind to a
/// storage slot for exactly that reason.
contract DiamondTest is Test {
    DiamondDeployer deployer;
    Diamond diamond;
    address facetA;

    function setUp() public {
        deployer = new DiamondDeployer();
        diamond = Diamond(payable(deployer.deploy()));
        facetA = address(new FacetA());
    }

    function test_loupe_resolves_through_the_fallback_dispatcher() public {
        DiamondLoupeFacet.Facet[] memory fs = DiamondLoupeFacet(address(diamond)).facets();
        assertEq(fs.length, 4, "four facets registered");
    }

    function test_facet_logic_is_reachable_through_the_fallback() public {
        // called on the diamond address: selector resolution -> delegatecall
        assertEq(FacetA(address(diamond)).facetAFunction(), 111);
    }

    function test_diamond_rejects_plain_transfers() public {
        vm.expectRevert("Diamond: no plain transfers");
        (bool ok,) = address(diamond).call{ value: 1 wei }("");
        ok;
    }
}
