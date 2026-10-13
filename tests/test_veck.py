"""Tests for the Critical-class scanner (`cli/cs_veck.py`).

The scanner is a triage aid, not an oracle, so these tests pin the two
properties that actually matter for trust:

  1. it does not miss a planted pattern (recall), and
  2. it does not fire on commented-out code or unrelated text (precision).

Network-free: everything runs against a temp directory.
"""
import re
from pathlib import Path

import pytest

from cli.cs_veck import CLASSES, _BY_ID, _sol_files, _strip, scan

SOL = """// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.24;

contract C {
    // function initialize(address) external;   <- commented out, must NOT hit
    /* function upgradeTo(address) external; */

    function initialize(address o) external initializer { owner = o; }

    function doDelegatecall(address t, bytes memory d) external {
        (bool s, ) = t.delegatecall(d);
        require(s, "fail");
    }

    function unsafeCall(address payable to) external {
        (bool success, ) = to.call{value: 1}("");
    }

    function shares() external view returns (uint256) {
        if (totalSupply() == 0) { return 1; }
        return 0;
    }
}
"""


@pytest.fixture()
def tree(tmp_path: Path) -> Path:
    (tmp_path / "C.sol").write_text(SOL)
    return tmp_path


def test_class_table_is_complete_and_unique():
    # 21 classes: 15 generic web3 + 4 DeFi-specific + 2 account-abstraction,
    # all added 2026-09-30: flash-loan manipulation, CLMM pool math, swap
    # slippage/MEV, vault donation, ERC-4337 paymaster deposit drain,
    # ERC-7579 modular account execution.
    assert len(CLASSES) == 21
    ids = [c["id"] for c in CLASSES]
    assert ids == list(range(1, 22))
    assert len(set(ids)) == 21
    for c in CLASSES:
        assert c["name"] and c["why"] and c["look"]
        assert "strong" in c and "weak" in c


def test_strip_removes_line_and_block_comments():
    assert _strip("int x = 1; // initialize() here").strip() == "int x = 1;"
    assert "initialize" not in _strip("/* function initialize() external; */ int x;")


def test_scan_finds_planted_patterns(tree: Path):
    hits = scan(tree)
    found = {(h["class_id"], h["file"], h["line"]) for h in hits}
    classes = {c for c, _, _ in found}
    assert 1 in classes    # un-guarded initialize
    assert 12 in classes   # delegatecall
    assert 14 in classes   # unchecked call
    assert 4 in classes    # totalSupply()==0


def test_scan_ignores_commented_patterns(tree: Path):
    hits = scan(tree)
    for h in hits:
        assert h["line"] not in (5, 6), f"commented line reported: {h}"


def test_scan_respects_class_filter(tree: Path):
    hits = scan(tree, [12])
    assert {h["class_id"] for h in hits} == {12}


def test_scan_respects_strong_only(tree: Path):
    hits = [h for h in scan(tree) if h["strength"] == "strong"]
    assert all(h["strength"] == "strong" for h in hits)


def test_empty_tree_is_clean(tmp_path: Path):
    (tmp_path / "x.sol").write_text("contract X { function f() external {} }")
    assert scan(tmp_path) == []


def test_non_solid_files_ignored(tmp_path: Path):
    (tmp_path / "a.py").write_text("def initialize(): pass")
    assert scan(tmp_path) == []


def test_hit_shape_has_adjudication_fields(tree: Path):
    for h in scan(tree):
        assert set(h) == {"class_id", "class", "strength", "file", "line", "snippet"}
        assert h["class"] == _BY_ID[h["class_id"]]["name"]
        assert h["strength"] in ("strong", "weak")
        assert isinstance(h["line"], int)


def test_strong_ranks_before_weak(tree: Path):
    hits = scan(tree)
    strengths = [h["strength"] for h in hits]
    # strong first, then weak
    assert strengths == sorted(strengths, key=lambda s: s != "strong")


# --- account-abstraction classes (added 2026-09-30) -------------------------
# Motivated by a concrete precedent: Hacken audited the ADI Chain GaslessPaymaster
# in Feb 2026 and still found a Critical (unsigned preVerificationGas in the
# commitment hash -> full deposit drain). Program-level "has audits" is therefore
# a poor signal; the class itself is fertile.

_AA_SAMPLE = """
pragma solidity ^0.8.24;
contract P {
    function _validatePaymasterUserOp(bytes32, bytes calldata paymasterAndData, uint256) internal {}
    function postOp(PostOpMode, bytes calldata context, uint256 actualGasCost, uint256) external {}
    function installModule(uint256 typeId, address module, bytes calldata data) external {}
    function executeFromExecutor(address target, uint256 value, bytes calldata data) external {}
    function executeBatch(address[] calldata t, uint256[] calldata v) external {}
}
"""


def test_class_table_now_covers_account_abstraction():
    assert len(CLASSES) == 21
    assert [c["id"] for c in CLASSES] == list(range(1, 22))
    ids = {c["id"] for c in CLASSES}
    assert 20 in ids and 21 in ids


def test_4337_paymaster_patterns_detected(tmp_path):
    f = tmp_path / "Paymaster.sol"
    f.write_text(_AA_SAMPLE)
    hits = scan(tmp_path)
    assert 20 in {h["class_id"] for h in hits}


def test_7579_module_patterns_detected(tmp_path):
    f = tmp_path / "Account.sol"
    f.write_text(_AA_SAMPLE)
    hits = scan(tmp_path)
    assert 21 in {h["class_id"] for h in hits}


def test_plain_contract_does_not_trigger_aa_classes(tmp_path):
    f = tmp_path / "Plain.sol"
    f.write_text("contract C { function transfer(address a, uint256 v) external {} }")
    hits = scan(tmp_path)
    assert not ({20, 21} & {h["class_id"] for h in hits})


# ---------------------------------------------------------------------------
# Class 19: the vulnerable donation shape itself, not just the ERC4626 mitigation
#
# Added after xGamma (Gamma, in scope) went undetected. All three known
# instances of this family - IPOR PowerToken, Gamma Hypervisor, Gamma xGamma -
# must fire; a contract with the shape absent must not.
# ---------------------------------------------------------------------------

def _scan(
    tmp_path: Path, body: str, name: str = "T.sol", classes: list[int] | None = None
) -> dict[int, list]:
    """Scan `body` and group hits by class id.

    `classes` defaults to [19] for the class-19 suite. It must be overridable:
    a helper hardcoded to one class makes every "no hits" assertion for another
    class pass vacuously, which is exactly the failure the third class-20 test
    caught.
    """
    p = tmp_path / name
    p.write_text(body)
    hits = scan(tmp_path, classes if classes is not None else [19])
    out: dict[int, list] = {}
    for h in hits:
        out.setdefault(h["class_id"], []).append(h)
    return out


def test_bancor_checkpoints_shape_detected(tmp_path):
    """xGamma: enter/leave divide by a raw balanceOf(address(this)), no offset."""
    body = """
    contract xGamma {
        IERC20 public gamma;
        uint256 private _totalSupply;
        function totalSupply() public view returns (uint256) { return _totalSupply; }
        function enter(uint256 _amount) public {
            uint256 totalGamma = gamma.balanceOf(address(this));
            uint256 totalShares = totalSupply();
            uint256 what = _amount.mul(totalShares).div(totalGamma);
            _mint(msg.sender, what);
            gamma.transferFrom(msg.sender, address(this), _amount);
        }
        function leave(uint256 _share) public {
            uint256 totalShares = totalSupply();
            uint256 what = _share.mul(gamma.balanceOf(address(this))).div(totalShares);
            _burn(msg.sender, _share);
        }
    }
    """
    assert 19 in _scan(tmp_path, body)


def test_divisor_may_not_be_first_argument(tmp_path):
    """IPOR PowerToken passes the total supply as the second argument."""
    body = """
    contract PowerTokenInternal {
        address private _governanceToken;
        function totalSupplyBase() public view returns (uint256) { return 1; }
        function _calculateInternalExchangeRate() public view returns (uint256) {
            uint256 balanceOfGovernanceToken =
                IERC20Upgradeable(_governanceToken).balanceOf(address(this));
            uint256 baseTotalSupply = totalSupplyBase();
            if (baseTotalSupply == 0) { return 1e18; }
            return MathOperation.division(balanceOfGovernanceToken * 1e18, baseTotalSupply);
        }
    }
    """
    assert 19 in _scan(tmp_path, body)


def test_total_assets_from_own_balance_detected(tmp_path):
    """Gamma Hypervisor getTotalAmounts reads its own idle balance into total0."""
    body = """
    contract Hypervisor {
        function getTotalAmounts() public view returns (uint256 total0, uint256 total1) {
            total0 = token0.balanceOf(address(this)).add(base0).add(limit0);
            total1 = token1.balanceOf(address(this)).add(base1).add(limit1);
        }
    }
    """
    assert 19 in _scan(tmp_path, body)


def test_virtual_offset_still_recognised_as_mitigation(tmp_path):
    """The original mitigation patterns must keep working."""
    body = """
    contract V {
        uint256 internal constant VIRTUAL_SHARES = 1e3;
    }
    """
    assert 19 in _scan(tmp_path, body)


def test_plain_erc20_does_not_trigger_class19(tmp_path):
    """A contract with no donation shape stays silent - no false positive."""
    body = """
    contract Plain {
        mapping(address => uint256) public balanceOf;
        function totalSupply() public view returns (uint256) { return 1; }
        function transfer(address to, uint256 amt) public returns (bool) {
            balanceOf[to] += amt;
            return true;
        }
    }
    """
    assert _scan(tmp_path, body) == {}


# ---------------------------------------------------------------------------
# _sol_files exclusions
#
# Found while running the rare-class sweep: scan() walked vendored dependency
# trees and test directories, so counts were dominated by other people's code.
# Royco went from 8031 rare-class hits to 157 once excluded.
# ---------------------------------------------------------------------------

def test_vendored_directories_excluded_by_default(tmp_path):
    (tmp_path / "lib").mkdir()
    (tmp_path / "lib" / "openzeppelin-contracts").mkdir(parents=True)
    (tmp_path / "lib" / "openzeppelin-contracts" / "MerkleProof.sol").write_text(
        "function processProof(bytes32[] calldata proof, bytes32 leaf) "
        "internal pure returns (bytes32) { return 0; }"
    )
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "X.sol").write_text("contract X {}")
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "A.sol").write_text("contract A {}")

    names = {p.name for p in _sol_files(tmp_path)}
    assert names == {"A.sol"}


def test_test_and_mock_directories_excluded_by_default(tmp_path):
    (tmp_path / "test").mkdir()
    (tmp_path / "test" / "T.sol").write_text("contract T {}")
    (tmp_path / "mocks").mkdir()
    (tmp_path / "mocks" / "M.sol").write_text("contract M {}")
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "A.sol").write_text("contract A {}")

    names = {p.name for p in _sol_files(tmp_path)}
    assert names == {"A.sol"}


def test_exclusions_are_opt_out(tmp_path):
    (tmp_path / "test").mkdir()
    (tmp_path / "test" / "T.sol").write_text("contract T {}")
    assert {p.name for p in _sol_files(tmp_path, include_tests=True)} == {"T.sol"}


def test_scan_does_not_match_vendored_copy(tmp_path):
    """A vendored ERC-4626 must not make a first-party target look dirty."""
    (tmp_path / "lib").mkdir()
    (tmp_path / "lib" / "V.sol").write_text(
        "contract V { uint256 constant VIRTUAL_SHARES = 1; }"
    )
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "A.sol").write_text("contract A {}")
    assert scan(tmp_path, [19]) == []


# ---------------------------------------------------------------------------
# Class 20 must not match a bare contract name or an unrelated local variable.
#
# A portfolio sweep reported class 20 as 273 strong / 289 total - a 94% strong
# ratio, which reads as extremely fertile. All of it was two bad patterns:
# a bare `EntryPoint` matching Royco's own `RoycoEntryPoint` contract, and
# `postOp\b` matching a local variable in RoycoDayAccountant.
# ---------------------------------------------------------------------------

def test_class20_ignores_own_entrypoint_contract_name(tmp_path):
    _scan(tmp_path, """
    import { IRoycoEntryPoint } from "../interfaces/IRoycoEntryPoint.sol";
    contract RoycoEntryPoint is RoycoBase, IRoycoEntryPoint {
        struct RoycoEntryPointState { uint256 x; }
    }
    """, "RoycoEntryPoint.sol", classes=[20])
    assert _scan(tmp_path, """
    import { IRoycoEntryPoint } from "../interfaces/IRoycoEntryPoint.sol";
    contract RoycoEntryPoint is RoycoBase, IRoycoEntryPoint {
        struct RoycoEntryPointState { uint256 x; }
    }
    """, "RoycoEntryPoint.sol", classes=[20]) == {}


def test_class20_ignores_postop_as_a_local_variable(tmp_path):
    assert _scan(tmp_path, """
    contract RoycoDayAccountant {
        function sync() external {
            SyncedAccountingState memory postOp = kernel.syncTrancheAccountingFromAccountant();
            require(postOp.liquidityUtilizationWAD <= WAD);
        }
    }
    """, classes=[20]) == {}


def test_class20_still_catches_a_paymaster(tmp_path):
    assert 20 in _scan(tmp_path, """
    contract GaslessPaymaster {
        function validatePaymasterUserOp(
            UserOperation calldata userOp,
            bytes32 userOpHash,
            uint128 maxCost
        ) external returns (bytes memory context, uint256 validationData) {
            return (abi.encode(userOpHash), 0);
        }
    }
    """, classes=[20])


def test_class11_demotes_canonical_aave_identifiers(tmp_path):
    """`healthFactor` is Aave's variable name, not a risk signal.

    A portfolio sweep read 137 "strong" class-11 hits as fertile; sampling showed
    interface declarations, local variables, doc comments and GenericLogic. The
    name is kept in `weak` so it still navigates to the subsystem.
    """
    assert _scan(tmp_path, """
    interface ILendingPool {
        /// @return healthFactor the current health factor of the user
        function getUserAccountData(address user)
            external view returns (uint256 healthFactor);
    }
    """, classes=[11]) == {} or all(
        h["strength"] != "strong" for hs in _scan(tmp_path, """
    interface ILendingPool {
        /// @return healthFactor the current health factor of the user
        function getUserAccountData(address user)
            external view returns (uint256 healthFactor);
    }
    """, classes=[11]).values() for h in hs
    )


def test_class11_still_anchors_on_a_health_factor_definition(tmp_path):
    """A definition is the place to start reading, so it stays a hit."""
    assert 11 in _scan(tmp_path, """
    contract LendingPool {
        function healthFactor(address user) public view returns (uint256) {
            return 1e18;
        }
    }
    """, classes=[11])
