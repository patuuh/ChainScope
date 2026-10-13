// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

/// @notice A minimal but standards-shaped EIP-2535 Diamond.
///
/// @dev Built to validate ChainScope's `cs_re.resolve_proxy` diamond branch
///      against the real interface, after sDAI turned out not to be a diamond
///      and no diamond was found among 143 in-scope bounty addresses.
///
///      The property that matters for the analyzer: facet logic does NOT appear
///      in the diamond's own bytecode. `diamondCut` records facet selectors in
///      storage and dispatch happens through a fallback, so bytecode selector
///      extraction on the diamond address finds only the diamond's own functions -
///      exactly the blind spot the surface caveat warns about.
contract FacetA {
    function facetAFunction() external pure returns (uint256) {
        return 111;
    }
}

contract FacetB {
    function facetBFunction(uint256 x) external pure returns (uint256) {
        return x * 2;
    }
}

/// @dev Standard EIP-2535 diamond storage at a fixed slot, so facets can read it
///      under DELEGATECALL.
///
///      The first attempt at this fixture used `IDiamondStorage(msg.sender)`, which
///      looks equivalent but is not: under `cast call` msg.sender is the zero
///      address, and under DELEGATECALL the facet sees the original caller rather
///      than the diamond. Real loupes bind to a storage slot precisely because of
///      this - msg.sender is never the diamond.
library LibDiamondStorage {
    bytes32 internal constant DIAMOND_STORAGE_POSITION =
        keccak256("diamond.standard.diamond.storage");

    struct DiamondStorage {
        mapping(address => bytes4[]) selectorTable;
        address[] facetList;
    }

    function diamondStorage() internal pure returns (DiamondStorage storage ds) {
        bytes32 slot = DIAMOND_STORAGE_POSITION;
        assembly {
            ds.slot := slot
        }
    }
}

/// @dev The diamond itself: stores the facet registry and dispatches by fallback.
contract Diamond {
    function _ds() internal pure returns (LibDiamondStorage.DiamondStorage storage ds) {
        return LibDiamondStorage.diamondStorage();
    }

    function addSelectors(address facet, bytes4[] calldata sels) external {
        bytes4[] storage sel = _ds().selectorTable[facet];
        for (uint256 i; i < sels.length; i++) {
            sel.push(sels[i]);
        }
    }

    function registerFacet(address facet) external {
        _ds().facetList.push(facet);
    }

    function getFacetList() external view returns (address[] memory) {
        return _ds().facetList;
    }

    function getSelectors(address facet) external view returns (bytes4[] memory) {
        return _ds().selectorTable[facet];
    }

    /// @dev The EIP-2535 fallback dispatcher: resolve the calldata selector
    ///      against the facet registry, then DELEGATECALL.
    ///
    ///      This is what makes the fixture valid for testing the analyzer: a real
    ///      diamond is called by selector at the diamond address, and the facet
    ///      code lives in a separate contract. Without this fallback, `facets()`
    ///      would revert and `cs_re` would never see a diamond.
    fallback() external {
        // msg.selector is unavailable in a plain `fallback()`; read the selector
        // out of calldata instead.
        require(msg.data.length >= 4, "Diamond: calldata too short");
        bytes4 sel = bytes4(msg.data[0:4]);
        LibDiamondStorage.DiamondStorage storage ds = LibDiamondStorage.diamondStorage();
        for (uint256 i; i < ds.facetList.length; i++) {
            address facet = ds.facetList[i];
            bytes4[] storage sels = ds.selectorTable[facet];
            for (uint256 j; j < sels.length; j++) {
                if (sels[j] == sel) {
                    (bool ok, bytes memory ret) = facet.delegatecall(msg.data);
                    if (!ok) {
                        assembly { revert(add(ret, 0x20), mload(ret)) }
                    }
                    assembly { return(add(ret, 0x20), mload(ret)) }
                }
            }
        }
        revert("Diamond: function not found");
    }

    receive() external payable {
        revert("Diamond: no plain transfers");
    }
}

/// @dev DiamondCut facet - the canonical entrypoint for adding facets.
contract DiamondCutFacet {
    struct FacetAddressAndSelectors {
        address facet;
        bytes4[] selectors;
    }

    function diamondCut(FacetAddressAndSelectors[] calldata _diamondCut, address, bytes calldata)
        external
    {
        LibDiamondStorage.DiamondStorage storage ds = LibDiamondStorage.diamondStorage();
        for (uint256 f; f < _diamondCut.length; f++) {
            bytes4[] storage sel = ds.selectorTable[_diamondCut[f].facet];
            for (uint256 i; i < _diamondCut[f].selectors.length; i++) {
                sel.push(_diamondCut[f].selectors[i]);
            }
        }
    }
}

/// @dev DiamondLoupe facet: facets(), facetAddresses(), facetFunctionSelectors().
contract DiamondLoupeFacet {
    struct Facet {
        address facetAddress;
        bytes4[] functionSelectors;
    }

    function facets() external view returns (Facet[] memory out) {
        LibDiamondStorage.DiamondStorage storage ds = LibDiamondStorage.diamondStorage();
        out = new Facet[](ds.facetList.length);
        for (uint256 i; i < ds.facetList.length; i++) {
            out[i].facetAddress = ds.facetList[i];
            out[i].functionSelectors = ds.selectorTable[ds.facetList[i]];
        }
    }

    function facetAddresses() external view returns (address[] memory) {
        return LibDiamondStorage.diamondStorage().facetList;
    }

    function facetFunctionSelectors(address facet) external view returns (bytes4[] memory) {
        return LibDiamondStorage.diamondStorage().selectorTable[facet];
    }
}

/// @dev Deploys a diamond with two real facets plus the loupe and cut facets.
contract DiamondDeployer {
    event DiamondDeployed(address indexed diamond, address[] facets);

    function deploy() external returns (address) {
        Diamond d = new Diamond();

        address fa = address(new FacetA());
        address fb = address(new FacetB());
        address loupe = address(new DiamondLoupeFacet());
        address cut = address(new DiamondCutFacet());

        d.registerFacet(fa);
        d.registerFacet(fb);
        d.registerFacet(loupe);
        d.registerFacet(cut);

        bytes4[] memory one = new bytes4[](1);
        one[0] = FacetA.facetAFunction.selector;
        d.addSelectors(fa, one);
        one[0] = FacetB.facetBFunction.selector;
        d.addSelectors(fb, one);

        bytes4[] memory three = new bytes4[](3);
        three[0] = DiamondLoupeFacet.facets.selector;
        three[1] = DiamondLoupeFacet.facetAddresses.selector;
        three[2] = DiamondLoupeFacet.facetFunctionSelectors.selector;
        d.addSelectors(loupe, three);

        one[0] = DiamondCutFacet.diamondCut.selector;
        d.addSelectors(cut, one);

        address[] memory fs = new address[](4);
        fs[0] = fa;
        fs[1] = fb;
        fs[2] = loupe;
        fs[3] = cut;
        emit DiamondDeployed(address(d), fs);
        return address(d);
    }
}
