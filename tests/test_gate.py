"""Tests for the admissibility gate.

The gate exists because seven targets were closed by hand, each on one of three
mechanical disqualifiers. These tests pin the two checks that need code:

  * reachability classification (check 3), which must be conservative - anything
    it cannot prove privileged is surfaced, never waved through;
  * audit-baseline detection (check 2), including the failure mode that would
    silently hide a real delta.

The anchor case is Gamma Strategies' Hypervisor, whose post-audit delta is real
(54 .sol commits, including the whole AutoRebal mechanism) but entirely
onlyAdvisor/onlyAdmin, and is therefore unreachable by an unprivileged attacker.
"""
from __future__ import annotations

import datetime as dt
import subprocess
from pathlib import Path

import pytest

from core.cs_gate import (
    classify_functions,
    delta_files,
    find_audits,
    gate_repo,
    reachability,
)

HYPERVISOR = Path("/home/charad7/Developments/Personal/Hacks/Immunefi/gamma-hv/hypervisor")


def _git_init(path: Path) -> None:
    subprocess.run(["git", "init", "-q"], cwd=path, check=True)
    subprocess.run(["git", "config", "user.email", "t@t"], cwd=path, check=True)
    subprocess.run(["git", "config", "user.name", "t"], cwd=path, check=True)


def _commit(path: Path, message: str, date: str) -> None:
    env_date = f"{date}T00:00:00"
    subprocess.run(
        ["git", "add", "-A"], cwd=path, check=True,
        env={**__import__("os").environ, "GIT_AUTHOR_DATE": env_date, "GIT_COMMITTER_DATE": env_date},
    )
    subprocess.run(
        ["git", "commit", "-q", "-m", message], cwd=path, check=True,
        env={**__import__("os").environ, "GIT_AUTHOR_DATE": env_date, "GIT_COMMITTER_DATE": env_date},
    )


# --------------------------------------------------------------------------- #
# reachability
# --------------------------------------------------------------------------- #


def test_modifier_guard_is_privileged():
    src = """
    contract C {
        address public admin;
        modifier onlyAdmin() { require(msg.sender == admin); _; }
        function setFee(uint256 f) external onlyAdmin { fee = f; }
    }
    """
    fns = {f["name"]: f for f in classify_functions(src)}
    assert fns["setFee"]["kind"] == "PRIVILEGED"
    assert fns["setFee"]["guard"] == "onlyAdmin"


def test_safety_modifiers_are_not_access_control():
    """nonReentrant/whenNotPaused must not be mistaken for an auth guard.

    Reading them as access control would mark an unprivileged function
    PRIVILEGED and hide exactly the entry points the gate exists to find.
    """
    src = """
    contract C {
        function withdraw(uint256 a) external nonReentrant whenNotPaused(PauseState.Frozen) {
            payable(msg.sender).transfer(a);
        }
    }
    """
    fns = {f["name"]: f for f in classify_functions(src)}
    assert fns["withdraw"]["kind"] == "PERMISSIONLESS"


def test_body_guard_is_privileged():
    src = """
    contract C {
        address owner;
        function setX(uint256 v) public {
            require(msg.sender == owner, "no");
            x = v;
        }
    }
    """
    fns = {f["name"]: f for f in classify_functions(src)}
    assert fns["setX"]["kind"] == "PRIVILEGED"


def test_unmodified_external_is_permissionless():
    src = """
    contract C {
        function deposit(uint256 a) external returns (uint256) { total += a; return total; }
    }
    """
    fns = {f["name"]: f for f in classify_functions(src)}
    assert fns["deposit"]["kind"] == "PERMISSIONLESS"


def test_views_and_internal_are_not_entry_points():
    src = """
    contract C {
        mapping(address => uint256) public bal;
        function _helper(uint256 a) internal returns (uint256) { return a; }
        function peek(address a) external view returns (uint256) { return bal[a]; }
        function pureFn() public pure returns (uint256) { return 1; }
    }
    """
    fns = {f["name"]: f["kind"] for f in classify_functions(src)}
    assert fns["_helper"] == "INTERNAL"
    assert fns["peek"] == "VIEW"
    assert fns["pureFn"] == "VIEW"


def test_multiline_signature_guard_is_found():
    """Solidity puts modifiers on their own lines; a line-scoped check would miss."""
    src = """
    contract C {
        address admin;
        function rebalance(
            uint256 amount,
            bool flag
        )
            external
            onlyAdmin
            nonReentrant
        {
            x = amount;
        }
    }
    """
    fns = {f["name"]: f for f in classify_functions(src)}
    assert fns["rebalance"]["kind"] == "PRIVILEGED"


def test_comments_do_not_create_or_hide_guards():
    src = """
    contract C {
        // function fake() external onlyOwner { }
        /* require(msg.sender == owner); */
        function open_(uint256 a) external { x = a; }
    }
    """
    fns = {f["name"]: f for f in classify_functions(src)}
    assert set(fns) == {"open_"}
    assert fns["open_"]["kind"] == "PERMISSIONLESS"


@pytest.mark.skipif(not HYPERVISOR.exists(), reason="hypervisor clone not present")
def test_hypervisor_autorebal_has_no_permissionless_entry_point():
    """The anchor case: real post-audit code, but unreachable without a role."""
    src = (HYPERVISOR / "contracts/proxy/AutoRebal.sol").read_text()
    kinds = {f["name"]: f["kind"] for f in classify_functions(src)}
    assert kinds["autoRebalance"] == "PRIVILEGED"
    assert kinds["compound"] == "PRIVILEGED"
    assert kinds["rescueERC20"] == "PRIVILEGED"
    assert "PERMISSIONLESS" not in kinds.values()


# --------------------------------------------------------------------------- #
# audit baseline
# --------------------------------------------------------------------------- #


def test_finds_audit_by_directory_membership(tmp_path):
    (tmp_path / "audits").mkdir()
    (tmp_path / "audits" / "Whatever.pdf").write_bytes(b"%PDF-")
    found = find_audits(tmp_path)
    assert len(found) == 1
    assert found[0]["file"].startswith("audits")


def test_parses_day_first_two_digit_year(tmp_path):
    (tmp_path / "ConsenSys-Diligence-Audit-28-03-22.pdf").write_bytes(b"%PDF-")
    a = find_audits(tmp_path)[0]
    assert a["date"] == "2022-03-28"
    assert a["firm"] == "ConsenSys"
    assert a["date_confidence"] == "high"


def test_firm_at_start_of_filename_is_detected(tmp_path):
    (tmp_path / "audits").mkdir()
    (tmp_path / "audits" / "Bailsec - Gamma - Vaults - Final Report.pdf").write_bytes(b"%PDF-")
    a = find_audits(tmp_path)[0]
    assert a["firm"] == "Bailsec"
    assert a["date_confidence"] == "low"  # no date in name
    # tmp_path is not a git repo, so there is no fallback date either
    assert a["date"] is None
    assert a["date_source"] is None


def test_git_date_fallback_is_marked_low_confidence(tmp_path):
    """A git date is a commit date, not an audit date.

    A bulk re-upload commits every PDF at once, which would push the baseline
    past all real code changes and hide a genuine delta.
    """
    _git_init(tmp_path)
    (tmp_path / "audits").mkdir()
    (tmp_path / "audits" / "Bailsec - Report.pdf").write_bytes(b"%PDF-")
    _commit(tmp_path, "Add files via upload", "2025-10-20")
    a = find_audits(tmp_path)[0]
    assert a["date"] == "2025-10-20"
    assert a["date_confidence"] == "low"


def test_unrelated_pdf_is_not_an_audit(tmp_path):
    (tmp_path / "logo.pdf").write_bytes(b"%PDF-")
    assert find_audits(tmp_path) == []


# --------------------------------------------------------------------------- #
# end-to-end gate
# --------------------------------------------------------------------------- #


def _repo_with_audit_and_delta(tmp_path, *, guard: str) -> None:
    _git_init(tmp_path)
    (tmp_path / "audits").mkdir()
    (tmp_path / "audits" / "ConsenSys-Audit-28-03-22.pdf").write_bytes(b"%PDF-")
    (tmp_path / "C.sol").write_text(
        "contract C {\n"
        "  address admin;\n"
        "  modifier onlyAdmin() { require(msg.sender == admin); _; }\n"
        f"  function act(uint256 a) external {guard} {{ x = a; }}\n"
        "  uint256 public x;\n"
        "}\n"
    )
    _commit(tmp_path, "initial", "2022-01-01")


def test_gate_rejects_privileged_only_delta(tmp_path):
    _repo_with_audit_and_delta(tmp_path, guard="onlyAdmin")
    g = gate_repo(tmp_path, audit_date="2021-01-01")
    assert g["delta_files"] == 1
    assert "NO_PERMISSIONLESS_ENTRY" in g["blockers"]
    assert g["verdict"] == "REJECT"


def test_gate_passes_when_delta_has_permissionless_entry(tmp_path):
    _repo_with_audit_and_delta(tmp_path, guard="")
    g = gate_repo(tmp_path, audit_date="2021-01-01")
    assert "NO_PERMISSIONLESS_ENTRY" not in g["blockers"]
    assert g["verdict"] == "PASS"
    assert g["reachability"]["has_permissionless"] is True


def test_gate_rejects_when_nothing_changed_since_audit(tmp_path):
    _repo_with_audit_and_delta(tmp_path, guard="")
    g = gate_repo(tmp_path, audit_date="2030-01-01")
    assert "NO_UNCOVERED_CODE" in g["blockers"]


def test_gate_reports_missing_audit_baseline(tmp_path):
    (tmp_path / "C.sol").write_text("contract C { function f() external {} }")
    g = gate_repo(tmp_path)
    assert "NO_AUDIT_BASELINE" in g["blockers"]


def test_undatable_audit_is_not_reported_as_no_new_code(tmp_path):
    """A false reject discards a live target, so it must not happen.

    Reports that exist but cannot be dated mean the baseline is UNKNOWN. Calling
    that "NO_UNCOVERED_CODE" asserts the opposite of what we know.
    """
    (tmp_path / "audits").mkdir()
    (tmp_path / "audits" / "Anonymous Review.pdf").write_bytes(b"%PDF-")
    (tmp_path / "C.sol").write_text("contract C { function f() external {} }")
    g = gate_repo(tmp_path)
    assert g["audit_count"] == 1
    assert "AUDIT_DATE_UNKNOWN" in g["blockers"]
    assert "NO_UNCOVERED_CODE" not in g["blockers"]
    assert any("--audit-date" in w for w in g["warnings"])


@pytest.mark.skipif(not HYPERVISOR.exists(), reason="hypervisor clone not present")
def test_hypervisor_gate_flags_low_confidence_baseline():
    """Must warn rather than assert a git-derived baseline as fact."""
    g = gate_repo(HYPERVISOR)
    assert g["audit_count"] >= 4
    assert g["baseline_low_confidence"] is True
    assert any("git-derived" in w for w in g["warnings"])