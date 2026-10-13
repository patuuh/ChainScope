"""Make a Solidity repo testable before hunting in it.

Every one of these classes came from actually trying to run `forge test` on GMX
(`poc/GMX_impact_pool/REPORT.md`), where four separate defects stood between an
auditor and a single fuzz campaign on a $5M programme:

  1. `@openzeppelin/contracts-upgradeable` was imported by
     `contracts/multichain/MultichainTransferRouter.sol` but never declared in
     `package.json`. It resolved under npm/yarn only because it was hoisted
     transitively via the LayerZero deps, and broke under pnpm's strict resolver.
  2. `foundry.toml` shipped no optimizer settings, so the repo did not compile with
     forge defaults - ExecuteWithdrawalUtils.sol:319 failed with *Stack too deep*.
  3. An existing test called `impact.abs()`, which is not a Solidity builtin, and the
     installed OpenZeppelin 4.9.3 has no `Math.abs` either (that arrives in 5.x).
  4. A test used `after` as a variable name, reserved since Solidity 0.8.19.

Nothing here judges the target's security. It only reports whether you *can run
anything*, which is a precondition for every other claim.

This module is deliberately a **reporter**, not an auto-fixer. Each finding carries
the evidence and the suggested remedy, and the caller decides. Auto-rewriting a
target repo to make it compile would silently change the code under audit, which
would invalidate any result produced from it.
"""

from __future__ import annotations

import json
import re
import typing as t
from dataclasses import dataclass, field
from pathlib import Path

__all__ = [
    "Finding",
    "detect_package_manager",
    "find_undeclared_imports",
    "diagnose_foundry_config",
    "scan_forbidden_identifiers",
    "doctor",
]


# --------------------------------------------------------------- findings


@dataclass
class Finding:
    kind: str          # stable slug
    severity: str      # blocker | warn | info
    summary: str
    evidence: list[str] = field(default_factory=list)
    remedy: str = ""

    def as_dict(self) -> dict[str, t.Any]:
        return {
            "kind": self.kind,
            "severity": self.severity,
            "summary": self.summary,
            "evidence": self.evidence[:12],
            "remedy": self.remedy,
        }


# ------------------------------------------------------------ package mgr

_PM_LOCKS = (
    ("pnpm-lock.yaml", "pnpm"),
    ("yarn.lock", "yarn"),
    ("package-lock.json", "npm"),
    ("bun.lockb", "bun"),
)


def detect_package_manager(root: Path) -> str:
    """Pick the package manager the repo already uses; default to npm."""
    for lock, pm in _PM_LOCKS:
        if (root / lock).exists():
            return pm
    return "npm"


# ------------------------------------------------- undeclared Solidity deps

_IMPORT = re.compile(
    r"""(?:^|\n)\s*import\s+(?:[^'"]*?from\s*)?["']([^"']+)["']""",
)

# Import roots that are expected NOT to be npm packages.
_LOCAL_PREFIXES = ("./", "../", "contracts/", "lib/", "src/", "test/", "node_modules/")
# Hardhat-style solidity helpers that ship inside a package named without the prefix.
_PACKAGE_HINTS = ("prb-math", "hardhat/", "ethers/", "solady/", "solidity-bytes-utils")

_SKIP_ROOTS = ("node_modules", ".git", "out", "cache", "cache_forge", "lib")
_SKIP_SET = frozenset(_SKIP_ROOTS)


def _import_root(imp: str) -> str:
    """`@openzeppelin/contracts/token/...` -> `@openzeppelin/contracts`."""
    if imp.startswith("@"):                     # scoped package
        parts = imp.split("/")
        return "/".join(parts[:2]) if len(parts) >= 2 else imp
    return imp.split("/")[0]


def _declared(root: Path) -> set[str]:
    pj = root / "package.json"
    if not pj.exists():
        return set()
    try:
        d = json.loads(pj.read_text())
    except json.JSONDecodeError:
        return set()
    return set(d.get("dependencies", {})) | set(d.get("devDependencies", {}))


def find_undeclared_imports(root: Path, max_files: int = 4000) -> Finding | None:
    """Solidity packages that are imported but not declared in package.json.

    This is the class that silently works under a hoisting resolver and breaks under
    a strict one, so it is usually invisible until you change package manager.
    """
    declared = _declared(root)
    if not declared:
        return None

    found: dict[str, list[str]] = {}
    scanned = 0
    for sol in root.rglob("*.sol"):
        if scanned >= max_files:
            break
        rel = sol.relative_to(root)
        if set(rel.parts) & _SKIP_SET:
            continue
        scanned += 1
        try:
            text = sol.read_text(errors="replace")
        except OSError:
            continue
        for m in _IMPORT.finditer(text):
            imp = m.group(1)
            if imp.startswith(_LOCAL_PREFIXES):
                continue
            pkg = _import_root(imp)
            if not pkg or pkg in _PACKAGE_HINTS:
                continue
            if pkg.startswith("forge-std"):
                continue
            if pkg in declared:
                continue
            # bare local helpers resolved via remappings are not packages
            if "/" not in imp and not pkg.startswith("@"):
                continue
            found.setdefault(pkg, [])
            if len(found[pkg]) < 3:
                found[pkg].append(f"{rel}: {imp}")

    if not found:
        return None
    return Finding(
        kind="undeclared-solidity-import",
        severity="blocker",
        summary=(
            f"{len(found)} Solidity package(s) imported but not declared in package.json"
        ),
        evidence=[f"{p} — e.g. {v[0]}" for p, v in sorted(found.items())],
        remedy=(
            "Install and declare them, or use a hoisting resolver. "
            "pnpm/yarn strict resolution will fail where npm hoisting hides it."
        ),
    )


# ------------------------------------------------------------ foundry config


def diagnose_foundry_config(root: Path) -> list[Finding]:
    """Compiler settings that block `forge build` out of the box."""
    out: list[Finding] = []
    ft = root / "foundry.toml"
    if not ft.exists():
        out.append(
            Finding(
                kind="no-foundry-config",
                severity="info",
                summary="no foundry.toml — forge will use defaults",
                remedy="Acceptable; defaults may still hit Stack too deep on large repos.",
            )
        )
        return out

    try:
        text = ft.read_text(errors="replace")
    except OSError:
        return out

    has_opt = re.search(r"^\s*optimizer\s*=\s*true", text, re.M) is not None
    has_via_ir = re.search(r"^\s*via_ir\s*=\s*true", text, re.M) is not None

    if not has_opt and not has_via_ir:
        out.append(
            Finding(
                kind="no-optimizer",
                severity="warn",
                summary=(
                    "foundry.toml enables neither optimizer nor via_ir — "
                    "large repos commonly fail to compile with *Stack too deep*"
                ),
                evidence=[ft.name],
                remedy=(
                    "Add `optimizer = true` (with `optimizer_runs`) and/or "
                    "`via_ir = true`. Verify against the project's own CI settings "
                    "first — changing them alters the bytecode you would be auditing."
                ),
            )
        )
    return out


# ------------------------------------------------- reserved-word collisions

_RESERVED = (
    "after", "from", "at", "of", "type", "error", "receive", "fallback", "contract",
    "library", "interface", "function", "returns", "memory", "calldata", "storage",
    "public", "private", "internal", "external", "pure", "view", "payable",
    "constructor", "modifier", "event", "using", "struct", "enum", "mapping",
    "immutable", "override", "virtual", "unchecked", "assembly", "emit", "delete",
    "new", "return", "revert", "require", "assert", "try", "catch", "while",
)


def scan_forbidden_identifiers(root: Path, names: t.Iterable[str] = ("after",)) -> list[Finding]:
    """Test files using identifiers that are reserved keywords in current solc.

    These break the build rather than the logic, and the failure message points at
    the line rather than the cause, so they cost more time than they look like.
    """
    out: list[Finding] = []
    testdir = root / "test"
    if not testdir.exists():
        return out
    rx = re.compile(
        r"\b(?:uint\d*|int\d*|bytes\d*|string|bool|address|\w+)\s+("
        + "|".join(sorted(_RESERVED))
        + r")\s*[=;),]"
    )
    for f in sorted(testdir.rglob("*.sol"))[:400]:
        try:
            text = f.read_text(errors="replace")
        except OSError:
            continue
        for i, line in enumerate(text.splitlines(), 1):
            m = rx.search(line)
            if m and "memory" not in line and "calldata" not in line and "storage" not in line:
                out.append(
                    Finding(
                        kind="reserved-keyword-identifier",
                        severity="warn",
                        summary=f"{m.group(1)!r} used as an identifier (reserved since solc 0.8.19)",
                        evidence=[f"{f.relative_to(root)}:{i}: {line.strip()[:80]}"],
                        remedy="Rename the local; this is a compile error, not a logic one.",
                    )
                )
                break
    return out


# ----------------------------------------------------------------- doctor


def doctor(root: Path) -> dict[str, t.Any]:
    """Run every check and return a single actionable report."""
    root = Path(root)
    findings: list[Finding] = []
    findings.append(
        Finding(
            kind="package-manager",
            severity="info",
            summary=f"package manager: {detect_package_manager(root)}",
            remedy=(
                "npm install can fail on frontend native modules (e.g. @parcel/watcher) "
                "that have nothing to do with Solidity; prefer pnpm for contracts-only work."
            ),
        )
    )
    und = find_undeclared_imports(root)
    if und:
        findings.append(und)
    findings.extend(diagnose_foundry_config(root))
    findings.extend(scan_forbidden_identifiers(root))

    blockers = [f for f in findings if f.severity == "blocker"]
    warns = [f for f in findings if f.severity == "warn"]
    return {
        "root": str(root),
        "blockers": len(blockers),
        "warnings": len(warns),
        "testable": not blockers,
        "findings": [f.as_dict() for f in findings],
    }