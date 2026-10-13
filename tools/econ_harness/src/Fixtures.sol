// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

/// @notice Ground-truth vaults for binding `core/cs_econ.py` to real execution.
///
/// These are deliberately minimal and deliberately one of each: a vault that is
/// known vulnerable and one that is known safe. Their only purpose is to answer
/// the question the Python models cannot answer about themselves - do the numbers
/// Python predicts match what the EVM actually does? A model that disagrees with
/// the EVM on a fixture will disagree on a real vault too, and would report a
/// confident wrong number.

interface IERC20Like {
    function totalSupply() external view returns (uint256);
    function balanceOf(address) external view returns (uint256);
    function transfer(address, uint256) external returns (bool);
    function transferFrom(address, address, uint256) external returns (bool);
}

/// @notice Minimal ERC4626 with the empty-vault branch and no virtual offset.
///         This is the vulnerable shape: the first depositor's shares become the
///         denominator for everyone, so a plain transfer to the vault inflates the
///         share price immediately.
contract NaiveVault {
    string public constant name = "NaiveVault";
    address public immutable asset;
    uint256 public totalAssets;
    uint256 public totalSupply;

    constructor(address asset_) {
        asset = asset_;
    }

    function convertToShares(uint256 assets) public view returns (uint256) {
        if (totalSupply == 0) {
            return assets;
        }
        return assets * totalSupply / totalAssets;
    }

    function convertToAssets(uint256 shares) public view returns (uint256) {
        if (totalSupply == 0) {
            return shares;
        }
        return shares * totalAssets / totalSupply;
    }

    function deposit(uint256 assets) external returns (uint256 shares) {
        shares = convertToShares(assets);
        require(shares > 0, "zero shares");
        totalAssets += assets;
        totalSupply += shares;
        IERC20Like(asset).transferFrom(msg.sender, address(this), assets);
        return shares;
    }

    function withdraw(uint256 shares) external returns (uint256 assets) {
        assets = convertToAssets(shares);
        require(assets > 0, "zero assets");
        totalAssets -= assets;
        totalSupply -= shares;
        IERC20Like(asset).transfer(msg.sender, assets);
        return assets;
    }

    /// @notice A donation is a plain transfer with no vault logic at all. This is
    ///         what makes the attack permissionless: no special role, no hook.
    function donate(uint256 assets) external {
        IERC20Like(asset).transferFrom(msg.sender, address(this), assets);
        totalAssets += assets;
    }
}

/// @notice Same interface, protected by `decimalsOffset` virtual shares and
///         liquidity, matching `erc4626_virtual` in cs_econ.py.
contract OffsetVault {
    string public constant name = "OffsetVault";
    uint8 public constant decimalsOffset = 3;
    uint256 private constant OFFSET = 10 ** 3;

    address public immutable asset;
    uint256 public totalAssets;
    uint256 public totalSupply;

    constructor(address asset_) {
        asset = asset_;
    }

    function _offset() internal pure returns (uint256) {
        return OFFSET;
    }

    function convertToShares(uint256 assets) public view returns (uint256) {
        uint256 denom = totalAssets + _offset();
        if (denom == 0) {
            return assets;
        }
        return assets * (totalSupply + _offset()) / denom;
    }

    function convertToAssets(uint256 shares) public view returns (uint256) {
        uint256 denom = totalSupply + _offset();
        if (denom == 0) {
            return shares;
        }
        return shares * (totalAssets + _offset()) / denom;
    }

    function deposit(uint256 assets) external returns (uint256 shares) {
        shares = convertToShares(assets);
        require(shares > 0, "zero shares");
        totalAssets += assets;
        totalSupply += shares;
        IERC20Like(asset).transferFrom(msg.sender, address(this), assets);
        return shares;
    }

    function withdraw(uint256 shares) external returns (uint256 assets) {
        assets = convertToAssets(shares);
        require(assets > 0, "zero assets");
        totalAssets -= assets;
        totalSupply -= shares;
        IERC20Like(asset).transfer(msg.sender, assets);
        return assets;
    }

    function donate(uint256 assets) external {
        IERC20Like(asset).transferFrom(msg.sender, address(this), assets);
        totalAssets += assets;
    }
}

contract MockToken {
    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
        totalSupply += amount;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function approve(address, uint256) external pure returns (bool) {
        return true;
    }
}
/// @notice Vault whose redemption rounds to ZERO, so every deposit/redeem cycle
///         leaves the depositor behind. Deliberately broken - it exists to prove
///         `rounding_drift` can tell a leaking vault from a correct one, which a
///         well-behaved fixture cannot (a correct vault drifts by exactly zero).
contract AsymVault {
    address public immutable asset;
    uint256 public totalAssets;
    uint256 public totalSupply;

    constructor(address asset_) {
        asset = asset_;
    }

    function convertToShares(uint256 assets) public view returns (uint256) {
        if (totalSupply == 0) return assets;
        return assets * totalSupply / totalAssets;
    }

    /// BUG: floors the redemption to zero, so the redeemer is credited nothing.
    function convertToAssets(uint256 shares) public pure returns (uint256) {
        shares;
        return 0;
    }

    function deposit(uint256 assets) external returns (uint256 shares) {
        shares = convertToShares(assets);
        totalAssets += assets;
        totalSupply += shares;
        IERC20Like(asset).transferFrom(msg.sender, address(this), assets);
    }

    function redeem(uint256 shares) external returns (uint256 assets) {
        assets = convertToAssets(shares);
        totalAssets -= assets;
        totalSupply -= shares;
    }

    function seed(uint256 assets, uint256 supply) external {
        totalAssets = assets;
        totalSupply = supply;
    }
}

/// @notice Constant-product pool used to bind the sandwich model to execution.
///         Deliberately minimal: fee on the input leg, exact integer maths, no
///         protocol fees or callbacks, so the numbers are comparable directly.
contract CPMM {
    uint256 public reserveIn;
    uint256 public reserveOut;
    uint256 public feeBps;

    constructor(uint256 rIn, uint256 rOut, uint256 fee) {
        reserveIn = rIn;
        reserveOut = rOut;
        feeBps = fee;
    }

    function amountOut(uint256 xIn) public view returns (uint256) {
        uint256 xi = (xIn * (10_000 - feeBps)) / 10_000;
        if (reserveIn + xi == 0) return 0;
        return (xi * reserveOut) / (reserveIn + xi);
    }

    /// Swap `xIn` of the input token in, returning the output amount.
    function swap(uint256 xIn) external returns (uint256 out) {
        out = amountOut(xIn);
        reserveIn += xIn;
        reserveOut -= out;
    }

    function sync(uint256 newIn, uint256 newOut) external {
        reserveIn = newIn;
        reserveOut = newOut;
    }
}
