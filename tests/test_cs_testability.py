"""Tests for cli/cs_testability.py.

Each test is a defect actually hit on GMX (`poc/GMX_impact_pool/REPORT.md`), so these
are regression tests for real breakage rather than synthetic fixtures.
"""

from __future__ import annotations

import json
from pathlib import Path

from cli.cs_testability import (
    doctor,
    detect_package_manager,
    diagnose_foundry_config,
    find_undeclared_imports,
    scan_forbidden_identifiers,
)


def _repo(tmp_path: Path, deps: dict[str, str], sol: str, foundry: str | None = None) -> Path:
    (tmp_path / "package.json").write_text(json.dumps({
        "dependencies": deps, "devDependencies": {},
    }))
    (tmp_path / "contracts").mkdir(exist_ok=True)
    (tmp_path / "contracts" / "A.sol").write_text(sol)
    if foundry is not None:
        (tmp_path / "foundry.toml").write_text(foundry)
    return tmp_path


# --------------------------------------------------------- package manager


def test_detects_pnpm_lock(tmp_path):
    (tmp_path / "pnpm-lock.yaml").write_text("")
    assert detect_package_manager(tmp_path) == "pnpm"


def test_detects_yarn_lock(tmp_path):
    (tmp_path / "yarn.lock").write_text("")
    assert detect_package_manager(tmp_path) == "yarn"


def test_defaults_to_npm(tmp_path):
    assert detect_package_manager(tmp_path) == "npm"


# ------------------------------------------- the GMX blocker: undeclared import


def test_flags_undeclared_openzeppelin_upgradeable(tmp_path):
    """The exact GMX defect: imported by source, absent from package.json."""
    _repo(
        tmp_path,
        {"@openzeppelin/contracts": "4.9.3"},
        """
        import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
        import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
        contract A {}
        """,
    )
    f = find_undeclared_imports(tmp_path)
    assert f is not None
    assert f.severity == "blocker"
    assert "@openzeppelin/contracts-upgradeable" in " ".join(f.evidence)
    # the declared one must NOT be flagged
    assert "@openzeppelin/contracts " not in " ".join(f.evidence)


def test_no_finding_when_everything_declared(tmp_path):
    _repo(
        tmp_path,
        {"@openzeppelin/contracts": "4.9.3", "prb-math": "4.0.0"},
        """
        import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
        import "prb-math/contracts/PRB.sol";
        contract A {}
        """,
    )
    assert find_undeclared_imports(tmp_path) is None


def test_local_relative_imports_ignored(tmp_path):
    _repo(tmp_path, {"@openzeppelin/contracts": "4.9.3"},
          'import "../utils/Helpers.sol";\nimport "./Local.sol";\ncontract A {}')
    assert find_undeclared_imports(tmp_path) is None


def test_forge_std_ignored(tmp_path):
    _repo(tmp_path, {"@openzeppelin/contracts": "4.9.3"},
          'import "forge-std/Test.sol";\ncontract A {}')
    assert find_undeclared_imports(tmp_path) is None


def test_node_modules_content_not_scanned(tmp_path):
    """A vendored tree must not manufacture findings."""
    _repo(tmp_path, {"@openzeppelin/contracts": "4.9.3"}, "contract A {}")
    vend = tmp_path / "node_modules" / "somepkg"
    vend.mkdir(parents=True)
    (vend / "B.sol").write_text('import "totally-undeclared-pkg/x.sol";')
    assert find_undeclared_imports(tmp_path) is None


def test_no_package_json_returns_none(tmp_path):
    (tmp_path / "contracts").mkdir()
    (tmp_path / "contracts" / "A.sol").write_text('import "@openzeppelin/x/y.sol";')
    assert find_undeclared_imports(tmp_path) is None


# ------------------------------------------------------ foundry.toml issues


def test_missing_optimizer_is_warned(tmp_path):
    """The GMX blocker: no optimizer -> Stack too deep -> will not build."""
    _repo(tmp_path, {}, "contract A {}", foundry="[profile.default]\nsrc='contracts'\n")
    out = diagnose_foundry_config(tmp_path)
    assert any(f.kind == "no-optimizer" for f in out)


def test_optimizer_present_is_quiet(tmp_path):
    _repo(tmp_path, {}, "contract A {}",
          foundry="[profile.default]\noptimizer = true\noptimizer_runs = 1000000\n")
    assert diagnose_foundry_config(tmp_path) == []


def test_via_ir_alone_is_acceptable(tmp_path):
    _repo(tmp_path, {}, "contract A {}", foundry="[profile.default]\nvia_ir = true\n")
    assert diagnose_foundry_config(tmp_path) == []


# ----------------------------------------------------- reserved-keyword hits


def test_flags_after_as_identifier(tmp_path):
    """The fourth GMX blocker: `after` is reserved since 0.8.19."""
    _repo(tmp_path, {}, "contract A {}")
    t = tmp_path / "test"
    t.mkdir()
    (t / "T.t.sol").write_text(
        "contract T {\n"
        "  function f() public {\n"
        "    uint256 after = pool - dist;\n"
        "  }\n"
        "}\n"
    )
    out = scan_forbidden_identifiers(tmp_path)
    assert out and out[0].kind == "reserved-keyword-identifier"
    assert "after" in out[0].summary


def test_memory_storage_calldata_not_false_positive(tmp_path):
    _repo(tmp_path, {}, "contract A {}")
    t = tmp_path / "test"
    t.mkdir()
    (t / "T.t.sol").write_text(
        "contract T {\n"
        "  function f() public {\n"
        "    uint256 x = 1;\n"
        "    bytes memory y = hex\"00\";\n"
        "  }\n"
        "}\n"
    )
    assert scan_forbidden_identifiers(tmp_path) == []


# ------------------------------------------------------------------- doctor


def test_doctor_blocks_on_undeclared(tmp_path):
    _repo(
        tmp_path,
        {"@openzeppelin/contracts": "4.9.3"},
        'import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";\ncontract A {}',
        foundry="[profile.default]\n",
    )
    r = doctor(tmp_path)
    assert r["testable"] is False
    assert r["blockers"] >= 1
    kinds = {f["kind"] for f in r["findings"]}
    assert "undeclared-solidity-import" in kinds
    assert "no-optimizer" in kinds
    assert any(f["kind"] == "package-manager" for f in r["findings"])


def test_doctor_clean_when_fixed(tmp_path):
    _repo(
        tmp_path,
        {
            "@openzeppelin/contracts": "4.9.3",
            "@openzeppelin/contracts-upgradeable": "4.9.6",
        },
        'import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";\ncontract A {}',
        foundry="[profile.default]\noptimizer = true\n",
    )
    r = doctor(tmp_path)
    assert r["testable"] is True
    assert r["blockers"] == 0
