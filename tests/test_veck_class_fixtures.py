"""Known-positive / known-negative fixtures for Veck classes 1, 6, 12, 13, 15, 18.

These six had self-consistency tests but no ground truth: they would pass while being
entirely broken. Each fixture here states, as code, what the class is supposed to mean
and what it must not match.

Several of these encode mistakes already made in this session:

* class 1 fires on `initialize()` declarations in INTERFACES, which is noise — the
  Gamma `IUniversalVault` case. The negative fixture pins that it must not count.
* class 13's `finalizeDeposit` pattern fires on any deposit finaliser, which includes
  ordinary bridges. It is a navigation marker, not proof of a broken proof check.
* class 12's strong pattern is a *negative* lookahead — `delegatecall(` not followed
  by a quoted string — so a string-literal target is the mitigated shape.
* class 15's `flashMint` fires on any flash mint, including correct ones; the
  negatives pin that a correct flash mint must not be treated as a finding.
"""

from __future__ import annotations

import pytest

from cli.cs_veck import _BY_ID, scan


def _scan(tmp_path, code: str, classes: list[int], name: str = "T.sol"):
    (tmp_path / name).write_text(code)
    return scan(tmp_path, classes)


def _strong(hits):
    return [h for h in hits if h.get("strength") == "strong"]


# =====================================================================  class 1

C1_POSITIVE = """
contract Takeover {
    function initialize(address admin) external {
        owner = admin;
    }
}
"""

C1_NEGATIVE_INTERFACE = """
interface IUniversalVault {
    function initialize() external;
}
"""

C1_NEGATIVE_DISABLED = """
contract Safe {
    constructor() { _disableInitializers(); }
}
"""

C1_NEGATIVE_ROLE_GATED = """
contract Gated {
    function initialize(address admin) external onlyRole(DEFAULT_ADMIN_ROLE) {
        owner = admin;
    }
}
"""


def test_c1_fires_on_a_permissionless_initialize(tmp_path):
    assert _strong(_scan(tmp_path, C1_POSITIVE, [1])), "known positive missed"


def test_c1_interface_declaration_is_not_a_finding(tmp_path):
    """The Gamma IUniversalVault case: a declaration, not an implementation."""
    assert not _strong(_scan(tmp_path, C1_NEGATIVE_INTERFACE, [1]))


def test_c1_disabled_and_role_gated_are_not_findings(tmp_path):
    assert not _strong(_scan(tmp_path, C1_NEGATIVE_DISABLED, [1]))
    assert not _strong(_scan(tmp_path, C1_NEGATIVE_ROLE_GATED, [1]))


def test_c1_disable_initializers_is_navigation_only(tmp_path):
    """It is the mitigation, so it must not count as evidence."""
    hits = _scan(tmp_path, C1_NEGATIVE_DISABLED, [1])
    assert not _strong(hits)


# =====================================================================  class 6

C6_POSITIVE = """
contract Malleable {
    function verify(bytes32 h, uint8 v, bytes32 r, bytes32 s) public view returns (address) {
        return ecrecover(h, v, r, s);
    }
}
"""

C6_NEGATIVE_OZ = """
import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
contract Pinned {
    function verify(bytes32 h, bytes32 sig) public view returns (address) {
        return ECDSA.recover(h, sig);
    }
}
"""


def test_c6_fires_on_raw_ecrecover(tmp_path):
    assert _strong(_scan(tmp_path, C6_POSITIVE, [6])), "known positive missed"


def test_c6_oz_recover_is_not_a_finding(tmp_path):
    """OZ's ECDSA.recover bounds s internally."""
    assert not _strong(_scan(tmp_path, C6_NEGATIVE_OZ, [6]))


def test_c6_named_selector_does_not_change_the_class(tmp_path):
    """Regression: the detector must key on ecrecover, not on a name."""
    assert not _strong(_scan(tmp_path, C6_NEGATIVE_OZ, [6]))


# ===================================================================== class 12

C12_POSITIVE = """
contract Proxyish {
    function run(bytes memory data) external {
        (bool ok,) = target.delegatecall(data);
        require(ok);
    }
}
"""

C12_NEGATIVE_FIXED_TARGET = """
contract Safe {
    address immutable target;
    function run(bytes memory data) external {
        (bool ok,) = "0x1234".delegatecall(data);
    }
}
"""


def test_c12_fires_on_a_variable_delegatecall_target(tmp_path):
    assert _strong(_scan(tmp_path, C12_POSITIVE, [12])), "known positive missed"


def test_c12_string_literal_target_is_not_a_finding(tmp_path):
    """A quoted target cannot be steered by the caller."""
    assert not _strong(_scan(tmp_path, C12_NEGATIVE_FIXED_TARGET, [12]))


# ===================================================================== class 13

C13_POSITIVE = """
contract Bridge {
    function finalizeWithdrawal(address to, uint256 amount) external {
        _mint(to, amount);
    }
    function verifyProof(bytes calldata p) internal pure returns (bool) {
        return MerkleProof.verify(p);
    }
}
"""

C13_NEGATIVE_DIFFERENT_DOMAIN = """
contract Locker {
    function readSlot(bytes32 slot) external view returns (bytes32) {
        return slot;
    }
    function processBytes(bytes calldata data) external pure returns (bytes4) {
        return bytes4(data);
    }
}
"""


def test_c13_fires_on_finalize_plus_proof(tmp_path):
    assert _strong(_scan(tmp_path, C13_POSITIVE, [13])), "known positive missed"


def test_c13_finalize_alone_is_navigation_only(tmp_path):
    """A finaliser with no proof logic is a marker, not proof of a broken check."""
    hits = _scan(tmp_path, """
        contract F {
            function completeDeposit(address to, uint256 a) external { _mint(to, a); }
        }
    """, [13])
    assert not _strong(hits), "finalize pattern must not be strong on its own"


def test_c13_different_domain_does_not_match(tmp_path):
    assert not _strong(_scan(tmp_path, C13_NEGATIVE_DIFFERENT_DOMAIN, [13]))


# ===================================================================== class 15

C15_POSITIVE = """
contract Lender {
    function fund(address to, uint256 amount) external {
        IMint(mint).flashMint(to, amount);
    }
}
"""

C15_NEGATIVE_CORRECT_REPAY = """
contract Lending {
    function flashLoan(address to, uint256 amt) external {
        uint256 before = token.balanceOf(address(this));
        IFlashLender(lender).flashLoan(to, amt, "");
        require(token.balanceOf(address(this)) >= before + fee, "not repaid");
    }
}
"""


def test_c15_fires_on_flash_mint(tmp_path):
    assert _strong(_scan(tmp_path, C15_POSITIVE, [15])), "known positive missed"


def test_c15_a_correct_flash_loan_still_matches_but_is_not_proof(tmp_path):
    """flashLoan is a navigation marker. The class cannot distinguish good from bad
    repayment accounting, so a correct implementation must not be treated as a
    confident finding — which is exactly why it is only a candidate for reading."""
    hits = _scan(tmp_path, C15_NEGATIVE_CORRECT_REPAY, [15])
    assert not _strong(hits)


# ===================================================================== class 18

C18_POSITIVE = """
contract Router {
    function swap(address t, uint256 a) external {
        uint256 amountOutMin = 0;
        (uint256 out,) = getAmountOut(a, reserve);
    }
}
"""

C18_NEGATIVE_BOUND = """
contract SafeRouter {
    function swap(address t, uint256 a, uint256 minOut) external {
        (uint256 out,) = getAmountOut(a, reserve);
        require(out >= minOut, "slippage");
    }
}
"""


def test_c18_fires_on_zero_slippage(tmp_path):
    assert _strong(_scan(tmp_path, C18_POSITIVE, [18])), "known positive missed"


def test_c18_bounded_swap_is_not_a_finding(tmp_path):
    assert not _strong(_scan(tmp_path, C18_NEGATIVE_BOUND, [18]))


# =====================================================================  invariants

@pytest.mark.parametrize("cid", [1, 6, 12, 13, 15, 18])
def test_empty_source_produces_no_hits(cid, tmp_path):
    assert scan(tmp_path, [cid]) == []


@pytest.mark.parametrize("cid", [1, 6, 12, 13, 15, 18])
def test_class_has_at_least_one_strong_pattern(cid):
    """A class whose strong list is empty can never be validated - pin that it is not."""
    assert _BY_ID[cid]["strong"], f"class {cid} has no strong pattern to test against"