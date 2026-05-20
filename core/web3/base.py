"""Base extractor interface and chain detection utilities."""

from abc import ABC, abstractmethod
from core.web3 import ExtractResult


class BaseExtractor(ABC):
    """Interface all chain-specific extractors implement."""

    @abstractmethod
    def extract(self, tree, source_code: bytes, file_path: str) -> ExtractResult:
        """Extract nodes, edges, and state transitions from parsed AST."""
        ...

    def _make_node_id(self, file_path: str, symbol: str, params: str = "") -> str:
        """Create node ID. Appends (param_types) for overloaded functions."""
        base = f"{file_path}::{symbol}"
        return f"{base}({params})" if params else base

    def _find_enclosing_function(self, node, functions: dict) -> str | None:
        """Walk up AST to find the enclosing function node.

        `functions` must be keyed by tree-sitter node.id (int) -> node_id (str).
        Build this dict during function extraction: functions[ts_node.id] = "file::funcname"
        """
        current = node.parent
        while current:
            if current.id in functions:
                return functions[current.id]
            current = current.parent
        return None


def detect_chain(source_code: str, file_path: str, cargo_toml: str | None = None) -> str:
    """Detect which blockchain framework a file uses.

    Returns a ChainScope chain/language key such as 'solidity', 'anchor',
    'substrate', 'soroban', 'cpp', 'rust', 'go', 'java', 'move',
    'clarity', 'vyper', 'cairo', 'sway', 'ton', 'proto', 'xdr',
    'typescript', 'python', or 'generic'.
    """
    # Go files
    if file_path.endswith(".go"):
        return "go"

    if file_path.endswith(".java"):
        return "java"

    if file_path.endswith(".move"):
        return "move"

    if file_path.endswith(".clar"):
        return "clarity"

    if file_path.endswith(".vy"):
        return "vyper"

    if file_path.endswith(".cairo"):
        return "cairo"

    if file_path.endswith(".sw"):
        return "sway"

    if file_path.endswith((".fc", ".func", ".tact", ".tolk")):
        return "ton"

    if file_path.endswith(".proto"):
        return "proto"

    if file_path.endswith(".x"):
        return "xdr"

    if file_path.endswith((".ts", ".tsx", ".js", ".jsx")):
        return "typescript"

    if file_path.endswith(".py"):
        return "python"

    # C++ files
    if file_path.endswith((".cpp", ".cc", ".cxx", ".hpp", ".hxx", ".h")):
        return "cpp"

    if file_path.endswith(".sol"):
        return "solidity"

    if file_path.endswith(".rs"):
        # Check for blockchain frameworks first
        if cargo_toml:
            if "anchor-lang" in cargo_toml:
                return "anchor"
            if "frame-support" in cargo_toml or "sp-runtime" in cargo_toml:
                return "substrate"
            if "soroban-sdk" in cargo_toml:
                return "soroban"

        if "use anchor_lang" in source_code or "#[program]" in source_code:
            return "anchor"
        if "#[pallet::call]" in source_code or "#[frame_support::pallet]" in source_code:
            return "substrate"
        if "use soroban_sdk" in source_code or ("#[contract]" in source_code and "#[contractimpl]" in source_code):
            return "soroban"

        # Generic Rust
        return "rust"

    if "pragma solidity" in source_code:
        return "solidity"

    return "generic"
