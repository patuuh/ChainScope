"""Indexer orchestrator — walks repo, detects chain, extracts graph."""

import json
import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from core.schema import GraphDB
from core.web3 import ExtractResult
from core.web3.base import detect_chain

# Directories to skip during indexing
IGNORE_DIRS = {
    "node_modules", "test", "tests", "mock", "mocks", "script", "scripts",
    "build", "artifacts", "cache", "out", "target", ".git", "__pycache__",
    "lib", "forge-std", ".deps",
    # Test directories with non-standard names
    "__tests__", "__mocks__", "forge-test", "forge-tests", "forge-scripts",
    "test-utils", "testdata", "testing",
    "fixtures", "fixture", "test-fixtures", "test_fixtures",
    "poc", "pocs", "demo", "demos", "example", "examples", "sample", "samples",
    "benchmark", "benchmarks", "benches", "fuzz", "fuzzing", "fuzzer",
    "invariant", "invariants", "certora", "echidna",
    # Go test helpers / integration tests
    "testutil", "testutils", "test_helpers",
    "e2e_tests", "e2e", "integration_tests", "interchaintest",
    "test-clients",  # Hedera test clients
    # Build output
    "dist", "bin", "obj", "coverage", "report", "reports",
    ".cache", ".next", ".nuxt", ".svelte-kit", ".turbo", ".vite",
    ".parcel-cache", ".pytest_cache", ".ruff_cache", ".mypy_cache",
    ".tox", ".nox", ".gradle", ".mvn",
    # Package managers
    "vendor", ".cargo", "gitmodules", ".venv", "venv", "env", ".yarn",
    ".npm", ".pnpm", ".pnpm-store", "bower_components", "jspm_packages",
    # Generated code directories
    "api",          # Cosmos SDK protobuf codegen
    "third_party",  # vendored third-party proto files
    "generated",    # generic codegen output
    "bindings",     # generated contract/client bindings
    "gobindings",   # generated Go bindings
    "gen", "codegen", "func++",
    "typechain", "typechain-types", "generated-types", "generated-sources",
}

NOISE_DIR_TOKENS = {
    "test", "tests", "mock", "mocks", "fixture", "fixtures", "example", "examples",
    "demo", "demos", "sample", "samples", "benchmark", "benchmarks", "bench",
    "benches", "fuzz", "fuzzing", "fuzzer", "poc", "pocs", "e2e", "integration",
    "invariant", "invariants", "certora", "echidna",
}

TEST_NAME_TOKENS = {
    "test", "tests", "tester", "testing", "mock", "mocks", "fixture", "fixtures",
    "fuzz", "fuzzer", "fuzzing", "example", "examples", "demo", "poc",
}

TEST_NAME_SUBSTRINGS = {
    "testcmd", "testgen", "testperf", "testsuite", "testonly",
    "testlog", "testrand", "teststaking", "testslashing",
}

RESEARCH_DIR_NAMES = {
    "script", "scripts",
    "deploy", "deploys", "deployment", "deployments", "broadcast",
    "poc", "pocs",
    "fuzz", "fuzzing", "fuzzer",
    "invariant", "invariants",
    "certora", "echidna",
}

RESEARCH_CONTEXT_ALIASES = {
    "scripts": "script",
    "script": "script",
    "deploy": "script",
    "deploys": "script",
    "deployment": "script",
    "deployments": "script",
    "broadcast": "script",
    "pocs": "poc",
    "poc": "poc",
    "fuzzing": "fuzz",
    "fuzzer": "fuzz",
    "fuzz": "fuzz",
    "invariants": "invariant",
    "invariant": "invariant",
    "certora": "certora",
    "echidna": "echidna",
}


SCRIPT_FILE_EXTENSIONS = {".ts", ".tsx", ".js", ".jsx", ".py"}
DEPLOYMENT_FILE_TOKENS = {"deploy", "deploys", "deployment", "deployments"}
_JSON_DECODER = json.JSONDecoder()
_MISSING_JSON_VALUE = object()


def _classify_research_filename(path: Path) -> str:
    lower = path.name.lower()
    if path.suffix.lower() == ".sol" and lower.endswith(".s.sol"):
        return "script"
    if path.suffix.lower() in SCRIPT_FILE_EXTENSIONS:
        stem_tokens = _name_tokens(path.stem)
        if stem_tokens & DEPLOYMENT_FILE_TOKENS:
            return "script"
    return "production"


def _skip_json_string(raw: str, pos: int) -> int:
    pos += 1
    escaped = False
    while pos < len(raw):
        ch = raw[pos]
        if escaped:
            escaped = False
        elif ch == "\\":
            escaped = True
        elif ch == '"':
            return pos + 1
        pos += 1
    return len(raw)


def _raw_json_value(raw: str | None, key: str):
    if not isinstance(raw, str) or not key:
        return _MISSING_JSON_VALUE
    needle = json.dumps(key)
    depth = 0
    pos = 0
    while pos < len(raw):
        ch = raw[pos]
        if ch == '"':
            end = _skip_json_string(raw, pos)
            if depth == 1 and raw.startswith(needle, pos) and end == pos + len(needle):
                colon = end
                while colon < len(raw) and raw[colon] in " \t\r\n":
                    colon += 1
                if colon >= len(raw) or raw[colon] != ":":
                    pos = end
                    continue
                value_pos = colon + 1
                while value_pos < len(raw) and raw[value_pos] in " \t\r\n":
                    value_pos += 1
                try:
                    value, _end = _JSON_DECODER.raw_decode(raw[value_pos:])
                except ValueError:
                    return _MISSING_JSON_VALUE
                return value
            pos = end
            continue
        if ch in "{[":
            depth += 1
        elif ch in "}]":
            depth = max(depth - 1, 0)
        pos += 1
    return _MISSING_JSON_VALUE


def _raw_json_truthy(raw: str | None, key: str) -> bool:
    value = _raw_json_value(raw, key)
    if value is _MISSING_JSON_VALUE:
        return False
    if isinstance(value, str):
        return value.lower() not in {"", "false", "0", "none", "null"}
    return bool(value)


def _raw_json_string(raw: str | None, key: str) -> str | None:
    value = _raw_json_value(raw, key)
    if isinstance(value, str):
        return value
    return None


def classify_source_context(file_path: str) -> str:
    """Classify whether a file comes from production or research context."""
    lower = file_path.lower().replace("\\", "/")
    parts = [p for p in lower.split("/") if p]
    for part in parts[:-1]:
        if part in RESEARCH_DIR_NAMES:
            return RESEARCH_CONTEXT_ALIASES.get(part, part)
    return _classify_research_filename(Path(lower))

# File extensions per chain
CHAIN_EXTENSIONS = {
    "solidity": {".sol"},
    "anchor": {".rs"},
    "substrate": {".rs"},
    "soroban": {".rs"},
    "cpp": {".c", ".cpp", ".cc", ".cxx", ".hpp", ".hxx", ".h"},
    "rust": {".rs"},
    "go": {".go"},
    "java": {".java"},
    "move": {".move"},
    "clarity": {".clar"},
    "vyper": {".vy"},
    "cairo": {".cairo"},
    "sway": {".sw"},
    "ton": {".fc", ".func", ".tact", ".tolk"},
    "proto": {".proto"},
    "xdr": {".x"},
    "typescript": {".ts", ".tsx", ".js", ".jsx"},
    "python": {".py"},
    "generic": {
        ".sol", ".rs", ".cpp", ".cc", ".h", ".go", ".java",
        ".move", ".clar", ".vy", ".cairo", ".sw", ".fc", ".func",
        ".tact", ".tolk", ".proto", ".x", ".ts", ".tsx", ".js", ".jsx", ".py",
    },
}

# Extension -> chain mapping for multi-language detection
EXT_TO_CHAIN = {
    ".sol": "solidity",
    ".go": "go",
    ".rs": "rust",  # may be overridden to anchor/substrate
    ".c": "cpp",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".cxx": "cpp",
    ".java": "java",
    ".move": "move",
    ".clar": "clarity",
    ".vy": "vyper",
    ".cairo": "cairo",
    ".sw": "sway",
    ".fc": "ton",
    ".func": "ton",
    ".tact": "ton",
    ".tolk": "ton",
    ".proto": "proto",
    ".x": "xdr",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".js": "typescript",
    ".jsx": "typescript",
    ".py": "python",
}


PROTOCOL_SOURCE_ROOTS = {
    "src", "source", "sources",
    "contracts", "contract",
    "programs", "program",
    "pallets", "pallet",
    "crates", "crate",
    "modules", "module",
    "packages", "package",
    "cmd", "internal", "pkg",
}

LOW_SIGNAL_SOURCE_ROOTS = {
    "devtools", "tasks", "ops", "tools", "cli", "config", "configs",
    "deployment", "deployments", "deploy", "deploys",
}

CHAIN_PRIORITY = {
    "solidity": 0,
    "move": 1,
    "clarity": 2,
    "vyper": 3,
    "anchor": 4,
    "substrate": 5,
    "soroban": 6,
    "rust": 7,
    "go": 8,
    "cpp": 9,
    "java": 10,
    "ton": 11,
    "cairo": 12,
    "sway": 13,
    "typescript": 14,
    "python": 15,
    "proto": 16,
    "xdr": 17,
}


def should_skip_dir_name(dirname: str, include_research: bool = False) -> bool:
    """Return true when a directory is low-signal for security indexing."""
    lower = dirname.lower()
    if lower in RESEARCH_DIR_NAMES:
        return not include_research
    if lower in IGNORE_DIRS or lower.endswith(".egg-info"):
        return True
    tokens = lower.replace("-", "_").replace(".", "_").split("_")
    if any(token in NOISE_DIR_TOKENS for token in tokens):
        if include_research and any(token in RESEARCH_DIR_NAMES for token in tokens):
            return False
        return True
    return (
        lower.startswith(("test", "mock"))
        or lower.endswith(("test", "tests", "testing", "mock", "mocks", "fixture", "fixtures"))
    )


def _name_tokens(stem: str) -> set[str]:
    """Split snake/kebab/CamelCase names into lowercase tokens."""
    parts = re.split(r"[^A-Za-z0-9]+|(?<=[a-z0-9])(?=[A-Z])", stem)
    return {part.lower() for part in parts if part}


def classify_source_noise(file_path: str, include_research: bool = False) -> str:
    """Classify why a supported source file should not be indexed.

    Returns an empty string for indexable files. This is intentionally
    conservative and filename/path based so profile and build agree without
    opening every source file during repository walks.
    """
    path = Path(file_path)
    ext = path.suffix.lower()
    if ext not in EXT_TO_CHAIN:
        return "unsupported_extension"

    fname = path.name
    lower = fname.lower()
    stem_lower = path.stem.lower()
    stem_tokens = _name_tokens(path.stem)
    parts = [p.lower() for p in path.parts]

    for part in parts[:-1]:
        if should_skip_dir_name(part, include_research=include_research):
            return f"ignored_dir:{part}"

    if ext == ".sol" and lower.endswith(".s.sol") and not include_research:
        return "foundry_test_or_script"

    source_context = _classify_research_filename(path)
    if source_context != "production" and not include_research:
        return f"research_file:{source_context}"

    # Test/spec/integration filenames that often live outside canonical test dirs.
    test_suffixes = (
        "_test.go", "_test.rs", "_tests.rs", "_test.py", "_tests.py",
        "test.java", "tests.java", "it.java", "e2e.java",
    )
    if lower.startswith(("test_", "mock_")) or lower.endswith(test_suffixes):
        return "test_file"
    if stem_lower.startswith(("test", "mock")):
        return "test_file"
    if stem_tokens & TEST_NAME_TOKENS:
        return "test_file"
    if stem_lower.endswith(("test", "tests", "tester", "testutils", "mock", "mocks", "fixture", "fixtures")):
        return "test_file"
    if any(token in stem_lower for token in TEST_NAME_SUBSTRINGS):
        return "test_file"
    if "testnet" in stem_lower:
        return "test_file"
    if any(token in lower for token in (
        ".test.", ".spec.", ".e2e.", ".integration.", ".fixture.", ".fixtures.",
        ".mock.", ".mocks.",
    )):
        return "test_file"
    if ext == ".sol" and lower.endswith(".t.sol"):
        return "foundry_test_or_script"
    if ext == ".sol" and (
        lower.startswith(("test", "mock"))
        or lower.endswith(("test.sol", "tests.sol", "mock.sol", "mocks.sol"))
    ):
        return "test_file"
    if ext == ".py" and lower in {"conftest.py", "noxfile.py"}:
        return "test_file"

    # Generated bindings/protobuf/grpc clients are large and swamp real logic.
    generated_tokens = (
        ".pb.", ".pbjson.", ".pbgrpc.", ".grpc.", ".g.", ".gen.", ".generated.",
        ".abigen.", ".abi.", ".bind.", ".bindings.",
    )
    generated_suffixes = (
        ".pb.go", ".pb.gw.go", ".pulsar.go", ".gen.go", "_generated.go",
        ".generated.go", ".abigen.go", ".bind.go", ".pb.cc", ".pb.h",
        ".grpc.pb.cc", ".grpc.pb.h", "_pb2.py", "_pb2_grpc.py", "_pb.js",
        "_pb.ts", "_grpc_pb.js", "_grpc_pb.ts",
    )
    if lower.endswith(generated_suffixes) or any(token in lower for token in generated_tokens):
        return "generated_file"
    if ext == ".java" and lower.endswith(("proto.java", "grpc.java", "grpcservice.java")):
        return "generated_file"
    if ext in {".ts", ".tsx", ".js", ".jsx"} and lower.endswith((".d.ts", ".min.js", ".bundle.js", ".umd.js")):
        return "generated_file"

    if ext in {".fc", ".func", ".tact", ".tolk"} and lower in {
        "stdlib.fc", "stdlib.func", "classlib.fc", "classlib.func", "testutils.fc",
    }:
        return "library_file"

    # Frontend/docs/config files tend to create large TypeScript/JS graphs with
    # little protocol value. Keep hardhat/truffle config indexable for key scans.
    if ext in {".ts", ".tsx", ".js", ".jsx"}:
        if {"docs", "static"} <= set(parts) or "storybook" in parts:
            return "docs_frontend"
        if lower.endswith((".config.js", ".config.ts", ".config.mjs", ".config.cjs")):
            if lower not in {"hardhat.config.js", "hardhat.config.ts", "truffle-config.js"}:
                return "tool_config"

    return ""


def should_index_source_file(file_path: str, include_research: bool = False) -> bool:
    """Check if a file should be indexed."""
    return classify_source_noise(file_path, include_research=include_research) == ""


class Indexer:
    """Walks a repository and builds a knowledge graph."""

    def __init__(self, repo_path: str, lang_override: str | None = None, include_research: bool = False):
        self.repo_path = repo_path
        self.default_chain = lang_override
        self.include_research = include_research
        # detected_chain kept for backward compat (primary language)
        self.detected_chain, self.all_chains = self._detect_repo_chains(lang_override)

    def _detect_rust_variant(self) -> str:
        """Detect if Rust files are Anchor or Substrate based on Cargo.toml."""
        repo = Path(self.repo_path)

        # Find Cargo.toml (root or first subdir)
        cargo_toml = None
        cargo_path = repo / "Cargo.toml"
        if cargo_path.exists():
            cargo_toml = cargo_path.read_text()
        else:
            for child in sorted(repo.iterdir()):
                if child.is_dir() and (child / "Cargo.toml").exists():
                    cargo_toml = (child / "Cargo.toml").read_text()
                    break

        if not cargo_toml:
            return "rust"

        # Sample a few .rs files to detect framework
        for root, dirs, files in os.walk(self.repo_path):
            dirs[:] = [d for d in dirs if not should_skip_dir_name(d, include_research=self.include_research)]
            for fname in files:
                fpath = os.path.join(root, fname)
                rel_path = os.path.relpath(fpath, self.repo_path)
                if fname.endswith(".rs") and should_index_source_file(rel_path, include_research=self.include_research):
                    try:
                        source = Path(fpath).read_text(errors="ignore")
                        chain = detect_chain(source, fname, cargo_toml)
                        if chain in ("anchor", "substrate", "soroban"):
                            return chain
                    except Exception:
                        continue
        return "rust"

    def _detect_repo_chains(self, lang_override: str | None) -> tuple[str, set[str]]:
        """Detect all languages present in this repo.

        Returns (primary_chain, set_of_all_chains).
        """
        if lang_override:
            return lang_override, {lang_override}

        found_exts: set[str] = set()
        for root, dirs, files in os.walk(self.repo_path):
            dirs[:] = [d for d in dirs if not should_skip_dir_name(d, include_research=self.include_research)]
            for fname in files:
                fpath = os.path.join(root, fname)
                rel_path = os.path.relpath(fpath, self.repo_path)
                if should_index_source_file(rel_path, include_research=self.include_research):
                    found_exts.add(Path(fname).suffix)

        if not found_exts:
            return "generic", set()

        chains: set[str] = set()
        for ext in found_exts:
            chains.add(EXT_TO_CHAIN[ext])

        # Refine Rust variant (anchor/substrate/soroban) — keep generic rust too
        if "rust" in chains:
            variant = self._detect_rust_variant()
            if variant != "rust":
                chains.add(variant)  # add anchor/substrate/soroban alongside rust

        # Primary = first in priority order
        for prio in (
            "solidity", "move", "clarity", "vyper", "go", "anchor",
            "substrate", "soroban", "rust", "cpp", "java", "ton",
            "typescript", "python", "proto", "xdr", "cairo", "sway",
        ):
            if prio in chains:
                return prio, chains

        return "generic", chains

    def _get_extractor(self, chain: str):
        """Get the appropriate extractor for a chain."""
        if chain == "solidity":
            from core.web3.solidity import SolidityExtractor
            return SolidityExtractor()
        if chain == "anchor":
            from core.web3.anchor import AnchorExtractor
            return AnchorExtractor()
        if chain == "substrate":
            from core.web3.substrate import SubstrateExtractor
            return SubstrateExtractor()
        if chain == "soroban":
            from core.web3.soroban import SorobanExtractor
            return SorobanExtractor()
        if chain == "cpp":
            from core.web3.cpp import CppExtractor
            return CppExtractor()
        if chain == "rust":
            from core.web3.rust import RustExtractor
            return RustExtractor()
        if chain == "go":
            from core.web3.go import GoExtractor
            return GoExtractor()
        if chain == "java":
            from core.web3.java import JavaExtractor
            return JavaExtractor()
        if chain == "move":
            from core.web3.project_langs import MoveExtractor
            return MoveExtractor()
        if chain == "clarity":
            from core.web3.project_langs import ClarityExtractor
            return ClarityExtractor()
        if chain == "vyper":
            from core.web3.project_langs import VyperExtractor
            return VyperExtractor()
        if chain == "cairo":
            from core.web3.project_langs import CairoExtractor
            return CairoExtractor()
        if chain == "sway":
            from core.web3.project_langs import SwayExtractor
            return SwayExtractor()
        if chain == "ton":
            from core.web3.project_langs import TonExtractor
            return TonExtractor()
        if chain == "proto":
            from core.web3.project_langs import ProtoExtractor
            return ProtoExtractor()
        if chain == "xdr":
            from core.web3.project_langs import XdrExtractor
            return XdrExtractor()
        if chain == "typescript":
            from core.web3.project_langs import TypeScriptExtractor
            return TypeScriptExtractor()
        if chain == "python":
            from core.web3.project_langs import PythonExtractor
            return PythonExtractor()
        return None

    def _chains_for_file(self, file_path: str) -> list[str]:
        """Determine which chain/extractor(s) to use for a file.

        Returns a list — for .rs files with anchor/substrate detected,
        returns both the specialized and generic extractors.
        """
        ext = Path(file_path).suffix
        chain = EXT_TO_CHAIN.get(ext)
        if chain is None:
            return []
        if chain == "rust":
            # Run both specialized (anchor/substrate) and generic rust extractors
            result = []
            for variant in ("anchor", "substrate", "soroban"):
                if variant in self.all_chains:
                    result.append(variant)
            if "rust" in self.all_chains:
                result.append("rust")
            return result
        if chain in self.all_chains:
            return [chain]
        return []

    def _should_index(self, file_path: str) -> bool:
        """Check if a file should be indexed."""
        rel_path = os.path.relpath(file_path, self.repo_path)
        return should_index_source_file(rel_path, include_research=self.include_research)

    def _file_priority(self, file_path: str) -> tuple:
        """Sort indexable files so partial builds contain protocol signal first."""
        rel_path = os.path.relpath(file_path, self.repo_path)
        rel_norm = rel_path.replace(os.sep, "/")
        parts = [p.lower() for p in Path(rel_norm).parts]
        root = parts[0] if parts else ""
        chain = EXT_TO_CHAIN.get(Path(file_path).suffix.lower(), "generic")

        source_context = classify_source_context(rel_norm)
        context_rank = 0 if source_context == "production" else 3
        if root in PROTOCOL_SOURCE_ROOTS:
            root_rank = 0
        elif root in LOW_SIGNAL_SOURCE_ROOTS:
            root_rank = 2
        else:
            root_rank = 1

        chain_rank = CHAIN_PRIORITY.get(chain, 99)
        if chain == self.detected_chain:
            chain_rank = -1

        depth = len(parts)
        return (context_rank, root_rank, chain_rank, depth, rel_norm.lower())

    def _collect_files(self) -> list[str]:
        """Walk repo and collect indexable files."""
        files = []
        for root, dirs, fnames in os.walk(self.repo_path):
            dirs[:] = [d for d in dirs if not should_skip_dir_name(d, include_research=self.include_research)]
            for fname in fnames:
                fpath = os.path.join(root, fname)
                if self._should_index(fpath):
                    files.append(fpath)
        return sorted(files, key=self._file_priority)

    def _annotate_source_context(self, result: ExtractResult, rel_path: str) -> None:
        """Tag nodes from research-oriented files so audits can distinguish them."""
        source_context = classify_source_context(rel_path)
        if source_context == "production":
            return
        for node in result.nodes:
            try:
                meta = json.loads(node.get("metadata", "{}") or "{}")
            except Exception:
                meta = {}
            meta["source_context"] = source_context
            meta["source_kind"] = "research"
            node["metadata"] = json.dumps(meta)

    def _build_confidence_summary(
        self,
        files_considered: int,
        files_indexed: int,
        extractor_runs: int,
        extractor_failures: int,
        nodes: int,
    ) -> dict:
        """Estimate how trustworthy the resulting graph is for triage."""
        if files_considered == 0 or extractor_runs == 0:
            return {
                "score": 0,
                "tier": "empty",
                "method": "no_indexable_files",
            }

        coverage_ratio = files_indexed / files_considered
        extractor_success = 1 - (extractor_failures / extractor_runs)
        signal_factor = 1.0 if nodes > 0 else 0.25
        score = round(max(0.0, min(1.0, coverage_ratio * 0.7 + extractor_success * 0.3)) * signal_factor * 100, 1)
        if score >= 95:
            tier = "high"
        elif score >= 80:
            tier = "medium"
        elif score >= 60:
            tier = "low"
        else:
            tier = "very_low"
        return {
            "score": score,
            "tier": tier,
            "method": "70% indexed-file coverage + 30% extractor success, dampened when graph signal is sparse",
        }

    def index(self, db_path: str, deadline: float | None = None, max_files: int | None = None) -> dict:
        """Index the repository into a SQLite knowledge graph.

        Returns stats dict with keys: files_indexed, nodes, edges, transitions.
        """
        db = GraphDB(db_path)
        db.clear()  # Ensure fresh index — stale rows cause INSERT OR IGNORE to skip updates

        # Build extractors for all detected chains
        extractors: dict[str, object] = {}
        for chain in self.all_chains:
            ext = self._get_extractor(chain)
            if ext is not None:
                extractors[chain] = ext

        if not extractors:
            return {"files_indexed": 0, "nodes": 0, "edges": 0, "transitions": 0}

        files = self._collect_files()
        total_nodes = 0
        total_edges = 0
        total_transitions = 0
        files_indexed = 0
        extractor_runs = 0
        extractor_failures = 0
        failed_files: set[str] = set()
        failure_examples: list[dict] = []
        timed_out = False
        indexed_file_count = 0

        for fpath in files:
            if deadline is not None and time.monotonic() >= deadline:
                timed_out = True
                break
            if max_files is not None and indexed_file_count >= max_files:
                break

            chains = self._chains_for_file(fpath)
            if not chains:
                continue

            try:
                source = Path(fpath).read_bytes()
            except Exception as exc:
                rel_path = os.path.relpath(fpath, self.repo_path)
                failed_files.add(rel_path)
                extractor_failures += 1
                if len(failure_examples) < 20:
                    failure_examples.append({
                        "file": rel_path,
                        "extractor": "read",
                        "error": type(exc).__name__,
                    })
                continue

            rel_path = os.path.relpath(fpath, self.repo_path)
            file_extracted = False

            for chain in chains:
                if chain not in extractors:
                    continue
                extractor_runs += 1
                extractor = extractors[chain]
                try:
                    result = extractor.extract_from_source(source, rel_path)
                except Exception as exc:
                    extractor_failures += 1
                    failed_files.add(rel_path)
                    if len(failure_examples) < 20:
                        failure_examples.append({
                            "file": rel_path,
                            "extractor": chain,
                            "error": type(exc).__name__,
                        })
                    continue

                self._annotate_source_context(result, rel_path)

                if result.nodes:
                    db.insert_nodes_batch(result.nodes)
                    total_nodes += len(result.nodes)
                if result.edges:
                    db.insert_edges_batch(result.edges)
                    total_edges += len(result.edges)
                if result.transitions:
                    db.insert_transitions_batch(result.transitions)
                    total_transitions += len(result.transitions)

                if result.nodes or result.edges:
                    file_extracted = True

            if file_extracted:
                files_indexed += 1
            indexed_file_count += 1

        # Post-indexing pass 1: resolve phantom targets (param-type mismatch)
        self._resolve_phantom_targets(db)

        # Post-indexing pass 2: resolve inheritance edges (_::BaseName -> actual node)
        self._resolve_inheritance_edges(db)

        # Post-indexing pass 3: resolve unresolved call edges across files
        resolved = self._resolve_cross_file_calls(db)
        total_edges += resolved

        # Post-indexing pass 4: suppress false-positive reentrancy on guarded internals
        self._suppress_guarded_reentrancy(db)

        # Post-indexing pass 5: detect cross-function reentrancy
        self._detect_cross_function_reentrancy(db)

        confidence = self._build_confidence_summary(
            files_considered=len(files),
            files_indexed=files_indexed,
            extractor_runs=extractor_runs,
            extractor_failures=extractor_failures,
            nodes=total_nodes,
        )
        build_info = {
            "repo_path": str(Path(self.repo_path).resolve()),
            "detected_chain": self.detected_chain,
            "all_chains": sorted(self.all_chains),
            "lang_override": self.default_chain or "",
            "include_research": self.include_research,
            "built_at": datetime.now(timezone.utc).isoformat(),
            "files_considered": len(files),
            "files_indexed": files_indexed,
            "extractor_runs": extractor_runs,
            "extractor_failures": extractor_failures,
            "failed_files": len(failed_files),
            "failure_examples": failure_examples,
            "timed_out": timed_out,
            "max_files": max_files,
            "nodes": total_nodes,
            "edges": total_edges,
            "transitions": total_transitions,
            "confidence": confidence,
        }
        db.set_metadata("build_info", build_info)

        return {
            "files_considered": len(files),
            "files_indexed": files_indexed,
            "extractor_runs": extractor_runs,
            "extractor_failures": extractor_failures,
            "failed_files": len(failed_files),
            "failure_examples": failure_examples,
            "timed_out": timed_out,
            "max_files": max_files,
            "nodes": total_nodes,
            "edges": total_edges,
            "transitions": total_transitions,
            "confidence": confidence,
        }

    def _resolve_inheritance_edges(self, db: GraphDB) -> int:
        """Resolve inheritance edges from placeholder targets to real contract nodes.

        Inheritance edges use '_::ContractName' as target placeholder.
        This matches them to actual contract/interface/library nodes by label.
        """
        conn = db.get_connection()
        try:
            # Find unresolved inheritance edges
            placeholders = conn.execute("""
                SELECT rowid, source, target FROM edges
                WHERE relation = 'inherits' AND target LIKE '_::%'
            """).fetchall()

            if not placeholders:
                return 0

            # Build lookup: label -> node ID for contracts/interfaces/libraries
            contract_nodes = conn.execute("""
                SELECT id, label FROM nodes
                WHERE type IN ('contract', 'abstract', 'interface', 'library')
            """).fetchall()
            label_to_id: dict[str, str] = {}
            for row in contract_nodes:
                label_to_id[row["label"]] = row["id"]

            resolved = 0
            for edge in placeholders:
                # Extract base name from _::ContractName
                base_name = edge["target"][3:]  # strip "_::"
                if base_name in label_to_id:
                    conn.execute(
                        "UPDATE edges SET target = ? WHERE rowid = ?",
                        (label_to_id[base_name], edge["rowid"])
                    )
                    resolved += 1

            conn.commit()
            return resolved
        finally:
            conn.close()

    def _resolve_phantom_targets(self, db: GraphDB) -> int:
        """Resolve call edges whose targets don't exist as nodes.

        This happens because call edges use bare names (Contract.func)
        while node IDs may include parameter types (Contract.func(uint256)).
        Matches each phantom target to a real node with matching prefix.
        """
        conn = db.get_connection()
        try:
            # Find call edges pointing to non-existent nodes
            phantoms = conn.execute("""
                SELECT e.rowid, e.source, e.target, e.attributes
                FROM edges e
                LEFT JOIN nodes n ON e.target = n.id
                WHERE e.relation = 'calls' AND n.id IS NULL
            """).fetchall()

            if not phantoms:
                return 0

            # Build lookup: bare_id -> list of real node IDs
            # e.g., "file::Contract.func" -> ["file::Contract.func(uint256)", "file::Contract.func(bytes32)"]
            all_nodes = conn.execute("SELECT id FROM nodes WHERE type = 'function'").fetchall()
            prefix_map: dict[str, list[str]] = {}
            # Also build label-only lookup for inheritance-based resolution
            label_map: dict[str, list[str]] = {}
            for row in all_nodes:
                node_id = row["id"]
                # Strip param types to get bare ID
                paren = node_id.find("(")
                bare = node_id[:paren] if paren > 0 else node_id
                if bare not in prefix_map:
                    prefix_map[bare] = []
                prefix_map[bare].append(node_id)
                # Extract just the function name (after last '.')
                func_label = bare.split(".")[-1] if "." in bare else bare.split("::")[-1]
                if func_label not in label_map:
                    label_map[func_label] = []
                label_map[func_label].append(node_id)

            # Build inheritance lookup: contract_id -> [parent_contract_ids]
            inherit_edges = conn.execute(
                "SELECT source, target FROM edges WHERE relation = 'inherits'"
            ).fetchall()
            parent_map: dict[str, list[str]] = {}
            for ie in inherit_edges:
                src = ie["source"]
                if src not in parent_map:
                    parent_map[src] = []
                parent_map[src].append(ie["target"])

            resolved = 0
            for edge in phantoms:
                target = edge["target"]
                # Strip params from the phantom target too
                paren = target.find("(")
                bare_target = target[:paren] if paren > 0 else target
                candidates = prefix_map.get(bare_target, [])

                # If no match in same contract, try inherited contracts
                if not candidates and "::" in bare_target:
                    file_contract = bare_target.split("::")[0] + "::" + bare_target.split("::")[1].split(".")[0] if "::" in bare_target else ""
                    func_name = bare_target.split(".")[-1] if "." in bare_target else ""
                    if file_contract and func_name:
                        # Walk inheritance chain to find the function
                        visited = set()
                        search_queue = [file_contract]
                        while search_queue and not candidates:
                            contract_id = search_queue.pop(0)
                            if contract_id in visited:
                                continue
                            visited.add(contract_id)
                            # Check parent contracts for the function
                            for parent_id in parent_map.get(contract_id, []):
                                parent_label = parent_id.split("::")[-1] if "::" in parent_id else parent_id
                                parent_file = parent_id.split("::")[0] if "::" in parent_id else ""
                                # Try to find func_name in parent contract
                                parent_bare = f"{parent_file}::{parent_label}.{func_name}" if parent_file else ""
                                if parent_bare and parent_bare in prefix_map:
                                    candidates = prefix_map[parent_bare]
                                    break
                                search_queue.append(parent_id)

                if not candidates:
                    continue

                # Pick first candidate (or best match if multiple overloads)
                real_target = candidates[0]

                existing = conn.execute(
                    "SELECT 1 FROM edges WHERE source = ? AND target = ? AND relation = 'calls'",
                    (edge["source"], real_target)
                ).fetchone()
                if existing:
                    conn.execute("DELETE FROM edges WHERE rowid = ?", (edge["rowid"],))
                else:
                    conn.execute(
                        "UPDATE edges SET target = ? WHERE rowid = ?",
                        (real_target, edge["rowid"])
                    )
                resolved += 1

            conn.commit()
            return resolved
        finally:
            conn.close()

    def _suppress_guarded_reentrancy(self, db: GraphDB) -> int:
        """Remove false-positive reentrancy flags on internal functions.

        If a function is internal/private and ALL of its callers (transitively)
        are protected by a reentrancy guard, the function is also protected.
        """
        REENTRANCY_GUARDS = {"nonReentrant", "ReentrancyGuard", "noReentrant",
                             "globalNonReentrant", "nonReentrant_", "lock_"}
        conn = db.get_connection()
        try:
            # Find all functions flagged with reentrancy_risk
            flagged = conn.execute("""
                SELECT id, label, visibility, metadata FROM nodes
                WHERE metadata LIKE '%"reentrancy_risk"%' AND type = 'function'
            """).fetchall()

            if not flagged:
                return 0

            suppressed = 0
            for func in flagged:
                vis = func["visibility"]
                label = func["label"]

                # Constructors can't be reentered — suppress
                if label == "constructor" or label.endswith(".constructor"):
                    meta = json.loads(func["metadata"])
                    meta.pop("reentrancy_risk", None)
                    details = meta.pop("reentrancy_details", "")
                    meta["reentrancy_suppressed"] = f"constructor (not callable post-deploy): {details}"
                    conn.execute(
                        "UPDATE nodes SET metadata = ? WHERE id = ?",
                        (json.dumps(meta), func["id"])
                    )
                    suppressed += 1
                    continue

                # Only suppress internal/private — external/public are directly callable
                if vis in ("external", "public"):
                    continue

                # Check if all callers are guarded
                if self._all_callers_guarded(conn, func["id"], REENTRANCY_GUARDS, set()):
                    meta = json.loads(func["metadata"])
                    meta.pop("reentrancy_risk", None)
                    details = meta.pop("reentrancy_details", "")
                    meta["reentrancy_suppressed"] = f"all callers guarded: {details}"
                    conn.execute(
                        "UPDATE nodes SET metadata = ? WHERE id = ?",
                        (json.dumps(meta), func["id"])
                    )
                    suppressed += 1

            conn.commit()
            return suppressed
        finally:
            conn.close()

    def _all_callers_guarded(self, conn, node_id: str,
                             guards: set, visited: set) -> bool:
        """Recursively check if all callers of a function have reentrancy guards."""
        if node_id in visited:
            return True  # Cycle — treat as guarded to avoid infinite loop
        visited.add(node_id)

        callers = conn.execute("""
            SELECT n.id, n.visibility, n.metadata FROM edges e
            JOIN nodes n ON e.source = n.id
            WHERE e.target = ? AND e.relation = 'calls'
        """, (node_id,)).fetchall()

        if not callers:
            return False  # No callers = unreachable or entry point, not guarded

        for caller in callers:
            meta = json.loads(caller["metadata"] or "{}")
            mods = set(meta.get("modifiers", []))

            # If caller has a reentrancy guard, it's protected
            if mods & guards:
                continue

            # If caller is internal/private, check its callers recursively
            if caller["visibility"] in ("internal", "private"):
                if not self._all_callers_guarded(conn, caller["id"], guards, visited):
                    return False
            else:
                # External/public caller without guard — not protected
                return False

        return True

    def _detect_cross_function_reentrancy(self, db: GraphDB) -> int:
        """Detect cross-function reentrancy: function A does external call,
        callback re-enters function B (same contract, public/external),
        which reads/writes state that A modifies after the call.

        This catches the classic pattern where withdraw() does an external
        transfer, the callback re-enters transfer() or balanceOf() which
        reads stale balance state.
        """
        REENTRANCY_GUARDS = {"nonReentrant", "ReentrancyGuard", "noReentrant",
                             "globalNonReentrant", "nonReentrant_", "lock_"}
        conn = db.get_connection()
        try:
            # Group functions by contract (extract contract from node ID)
            # Node ID format: file.sol::Contract.functionName(params)
            funcs = conn.execute("""
                SELECT id, label, visibility, metadata, file FROM nodes
                WHERE type = 'function'
            """).fetchall()

            # Build contract -> [func_rows] mapping
            contract_funcs: dict[str, list] = {}
            for f in funcs:
                fid = f["id"]
                # Extract contract name: file::Contract.func -> "file::Contract"
                if "::" in fid:
                    parts = fid.split("::")
                    if len(parts) >= 2:
                        contract_part = parts[1].split(".")[0] if "." in parts[1] else parts[1]
                        contract_key = f"{parts[0]}::{contract_part}"
                        if contract_key not in contract_funcs:
                            contract_funcs[contract_key] = []
                        contract_funcs[contract_key].append(dict(f))

            flagged = 0
            for contract_key, func_list in contract_funcs.items():
                # For each contract, find functions with external calls (order-tracked)
                # and functions that read/write overlapping state vars
                ext_call_funcs = []  # funcs with external calls + state writes after
                entry_funcs = []     # public/external funcs that touch state

                for func in func_list:
                    meta = json.loads(func.get("metadata", "{}"))
                    mods = set(meta.get("modifiers", []))

                    # Skip if already guarded
                    if mods & REENTRANCY_GUARDS:
                        continue

                    vis = func["visibility"]
                    fid = func["id"]

                    # Get this function's edges
                    call_edges = conn.execute(
                        "SELECT target, attributes FROM edges "
                        "WHERE source = ? AND relation = 'calls'",
                        (fid,)
                    ).fetchall()
                    write_edges = conn.execute(
                        "SELECT target, attributes FROM edges "
                        "WHERE source = ? AND relation = 'writes_state'",
                        (fid,)
                    ).fetchall()
                    read_edges = conn.execute(
                        "SELECT target FROM edges "
                        "WHERE source = ? AND relation = 'reads_state'",
                        (fid,)
                    ).fetchall()

                    # Find external calls with order info
                    ext_call_orders = []
                    for ce in call_edges:
                        attrs = json.loads(ce["attributes"]) if ce["attributes"] != "{}" else {}
                        if attrs.get("unresolved") and "order" in attrs:
                            ext_call_orders.append(attrs["order"])
                        elif attrs.get("sink"):
                            ext_call_orders.append(attrs.get("order", 999))

                    # State vars written after external call
                    post_call_writes = set()
                    if ext_call_orders:
                        min_ext_order = min(ext_call_orders)
                        for we in write_edges:
                            wa = json.loads(we["attributes"]) if we["attributes"] != "{}" else {}
                            if wa.get("order", -1) > min_ext_order:
                                post_call_writes.add(we["target"])

                    if ext_call_orders and post_call_writes:
                        ext_call_funcs.append({
                            "id": fid,
                            "label": func["label"],
                            "post_call_writes": post_call_writes,
                        })

                    # Track entry points that read/write state
                    if vis in ("external", "public"):
                        state_reads = {re["target"] for re in read_edges}
                        state_writes = {we["target"] for we in write_edges}
                        if state_reads or state_writes:
                            entry_funcs.append({
                                "id": fid,
                                "label": func["label"],
                                "reads": state_reads,
                                "writes": state_writes,
                            })

                # Cross-check: for each ext_call func, find entry funcs that
                # read or write the same state vars
                for ecf in ext_call_funcs:
                    for ef in entry_funcs:
                        if ef["id"] == ecf["id"]:
                            continue  # Same function = single-func reentrancy (already detected)
                        overlap_reads = ef["reads"] & ecf["post_call_writes"]
                        overlap_writes = ef["writes"] & ecf["post_call_writes"]
                        if overlap_reads or overlap_writes:
                            # Flag the entry function with cross-function reentrancy
                            stale_vars = [v.split("::")[-1].split(".")[-1]
                                          for v in (overlap_reads | overlap_writes)]
                            node = conn.execute(
                                "SELECT metadata FROM nodes WHERE id = ?",
                                (ef["id"],)
                            ).fetchone()
                            if node:
                                meta = json.loads(node["metadata"])
                                if "cross_reentrancy" not in meta:
                                    meta["cross_reentrancy"] = []
                                meta["cross_reentrancy"].append({
                                    "via": ecf["label"],
                                    "stale_vars": stale_vars,
                                })
                                conn.execute(
                                    "UPDATE nodes SET metadata = ? WHERE id = ?",
                                    (json.dumps(meta), ef["id"])
                                )
                                flagged += 1

            conn.commit()
            return flagged
        finally:
            conn.close()

    def _resolve_cross_file_calls(self, db: GraphDB) -> int:
        """Resolve unresolved call edges by matching call_name to known functions.

        After all files are indexed, unresolved calls (e.g., obj.method())
        can be matched against the full node table by function label.
        """
        conn = db.get_connection()
        try:
            # Find all unresolved call edges
            unresolved = conn.execute("""
                SELECT rowid, source, target, attributes FROM edges
                WHERE relation = 'calls'
                  AND attributes LIKE '%"unresolved"%'
                  AND attributes LIKE '%"call_name"%'
            """).fetchall()

            if not unresolved:
                return 0

            # Build function lookup: label -> list of node IDs
            func_nodes = conn.execute(
                "SELECT id, label FROM nodes WHERE type = 'function'"
            ).fetchall()
            func_by_name: dict[str, list[str]] = {}
            for row in func_nodes:
                label = row["label"]
                if label not in func_by_name:
                    func_by_name[label] = []
                func_by_name[label].append(row["id"])

            resolved_count = 0
            for edge in unresolved:
                raw_attrs = edge["attributes"]
                if not _raw_json_truthy(raw_attrs, "unresolved"):
                    continue
                call_name = _raw_json_string(raw_attrs, "call_name") or ""
                if not call_name or call_name not in func_by_name:
                    continue

                candidates = func_by_name[call_name]
                # Pick the best candidate (prefer different file to avoid self-reference)
                source_file = edge["source"].split("::")[0] if "::" in edge["source"] else ""
                target_id = candidates[0]
                for c in candidates:
                    c_file = c.split("::")[0] if "::" in c else ""
                    if c_file != source_file:
                        target_id = c
                        break

                # Check if an edge already exists for this source->target
                existing = conn.execute(
                    "SELECT 1 FROM edges WHERE source = ? AND target = ? AND relation = 'calls'",
                    (edge["source"], target_id)
                ).fetchone()
                if existing:
                    # Edge already exists — just remove the unresolved duplicate
                    conn.execute("DELETE FROM edges WHERE rowid = ?", (edge["rowid"],))
                else:
                    # Update the edge to point to the resolved target
                    conn.execute(
                        "UPDATE edges SET target = ?, attributes = ? WHERE rowid = ?",
                        (target_id, json.dumps({"resolved_cross_file": True}), edge["rowid"])
                    )
                resolved_count += 1

            conn.commit()
            return resolved_count
        finally:
            conn.close()
