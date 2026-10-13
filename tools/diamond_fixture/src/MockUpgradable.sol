// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

/// @notice Mirrors OpenZeppeli's Initializable guard closely enough to prove the
///         uninitialized-probe works in BOTH directions.
///
/// @dev The probe's whole value is telling "already initialized" apart from an
///      unrelated revert. A detector that can only ever return the safe answer
///      is worthless, so this fixture provides one address that IS initialized and
///      one that is NOT, deployed side by side.
contract MockUpgradable {
    error InvalidInitialization();
    error NotInitializing();

    address public owner;
    bool private _initialized;

    modifier initializer() {
        if (_initialized) revert InvalidInitialization();
        _initialized = true;
        _;
    }

    function initialize(address newOwner) external initializer {
        require(newOwner != address(0), "zero owner");
        owner = newOwner;
    }

    function initialize2(uint256 x) external initializer {
        owner = address(uint160(x));
    }

    function ownerOf() external view returns (address) {
        return owner;
    }
}

/// @notice Positive control for access-control inference.
///
/// @dev `onlyOwner` compiles to a CALLER comparison against the owner slot
///      followed by a conditional revert. Without a fixture that HAS such a guard,
///      an access-control detector cannot be shown to detect anything - and this
///      whole feature exists because reading modifiers by hand across ~19,000
///      lines is the work it should replace.
contract OwnableMock {
    address public owner;

    constructor(address _owner) {
        owner = _owner;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function guarded(uint256 x) external onlyOwner returns (uint256) {
        return x + 1;
    }

    function open(uint256 x) external pure returns (uint256) {
        return x + 2;
    }
}

/// @notice Negative control: reads msg.sender but never gates on it, so a naive
///         "CALLER appears somewhere" heuristic would wrongly claim a guard.
contract ReadsSenderNoGuard {
    address public lastSender;

    function recordCaller() external {
        lastSender = msg.sender;
    }
}

/// @dev Deploys the access-control fixtures in one transaction.
contract AccessControlDeployer {
    event Deployed(address indexed onlyOwnerMock, address indexed noGuard);

    function deployAll() external returns (OwnableMock o, ReadsSenderNoGuard n) {
        o = new OwnableMock(msg.sender);
        n = new ReadsSenderNoGuard();
        emit Deployed(address(o), address(n));
    }
}
