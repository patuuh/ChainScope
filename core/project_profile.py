"""Repository profiling helpers for deciding what ChainScope should index."""

from __future__ import annotations

import os
from collections import Counter, defaultdict
from pathlib import Path

from core.indexer import (
    EXT_TO_CHAIN,
    RESEARCH_DIR_NAMES,
    classify_source_noise,
    should_skip_dir_name,
)


PROJECT_MARKERS = {
    "Cargo.toml": "rust",
    "Anchor.toml": "anchor",
    "go.mod": "go",
    "package.json": "typescript",
    "foundry.toml": "solidity",
    "hardhat.config.ts": "solidity",
    "hardhat.config.js": "solidity",
    "truffle-config.js": "solidity",
    "Move.toml": "move",
    "Clarinet.toml": "clarity",
    "Scarb.toml": "cairo",
    "Forc.toml": "sway",
    "tact.config.json": "ton",
    "pom.xml": "java",
    "build.gradle": "java",
    "settings.gradle": "java",
    "CMakeLists.txt": "cpp",
    "Makefile": "native",
    "buf.yaml": "proto",
}

MARKER_FRAMEWORKS = {
    "Cargo.toml": ("cargo",),
    "Anchor.toml": ("anchor", "solana"),
    "go.mod": ("go-module",),
    "package.json": ("node-package",),
    "foundry.toml": ("foundry", "evm"),
    "hardhat.config.ts": ("hardhat", "evm"),
    "hardhat.config.js": ("hardhat", "evm"),
    "truffle-config.js": ("truffle", "evm"),
    "Move.toml": ("move-package",),
    "Clarinet.toml": ("clarinet", "stacks/clarity"),
    "Scarb.toml": ("scarb", "starknet"),
    "Forc.toml": ("forc", "fuel"),
    "tact.config.json": ("tact", "ton"),
    "pom.xml": ("maven",),
    "build.gradle": ("gradle",),
    "settings.gradle": ("gradle",),
    "CMakeLists.txt": ("cmake",),
    "Makefile": ("make",),
    "buf.yaml": ("buf", "protobuf/grpc"),
}

LANGUAGE_FRAMEWORKS = {
    "solidity": ("evm",),
    "vyper": ("evm",),
    "move": ("move",),
    "clarity": ("stacks/clarity",),
    "ton": ("ton",),
    "anchor": ("anchor", "solana"),
    "substrate": ("substrate",),
    "soroban": ("stellar/soroban",),
    "cairo": ("starknet",),
    "sway": ("fuel",),
    "xdr": ("stellar/xdr",),
    "proto": ("protobuf/grpc",),
}

PATH_FRAMEWORK_HINTS = (
    (("layerzero", "wormhole"), ("cross-chain/messaging",)),
    (("axelar",), ("cosmos-sdk", "cross-chain/messaging")),
    (("chainlink",), ("oracle",)),
    (("lido", "aave", "compound", "uniswap", "curve", "balancer", "makerdao", "eigenlayer"), ("defi-protocol",)),
    (("op-geth", "op-node", "op-batcher", "op-proposer", "op-program", "optimism", "op-stack"), ("op-stack",)),
    (("geth", "go-ethereum", "erigon", "reth", "nethermind", "bera-geth", "l2geth"), ("evm-node", "geth-family")),
    (("cosmos", "cosmos-sdk", "tendermint", "cometbft", "ibc-go", "osmosis", "injective", "sei", "xion", "celestia"), ("cosmos-sdk",)),
    (("sui",), ("sui-move",)),
    (("aptos",), ("aptos-move",)),
    (("solana", "jito"), ("solana",)),
    (("stellar", "stellar-core"), ("stellar",)),
    (("soroban",), ("stellar/soroban",)),
    (("stacks",), ("stacks/clarity",)),
    (("substrate", "polkadot", "parity", "moonbeam", "hydradx", "bifrost"), ("substrate/polkadot",)),
    (("ton",), ("ton",)),
    (("hedera", "hiero"), ("hedera",)),
    (("avalanche", "subnet-evm"), ("avalanche",)),
    (("near",), ("near",)),
    (("monad",), ("monad", "evm-node")),
    (("polygon", "matic", "bor"), ("polygon",)),
    (("scroll",), ("scroll", "zk-rollup")),
    (("zksync",), ("zksync", "zk-rollup")),
    (("starknet", "starkware"), ("starknet",)),
    (("fuel",), ("fuel",)),
)

RISK_TAGS = {
    "solidity": "EVM contracts",
    "vyper": "EVM contracts",
    "move": "Move assets/modules",
    "clarity": "Stacks public functions/state",
    "ton": "TON message handlers/value flow",
    "anchor": "Solana account validation/CPI",
    "substrate": "Substrate pallets/runtime",
    "soroban": "Soroban auth/state",
    "cairo": "Starknet contracts",
    "sway": "Fuel contracts",
    "xdr": "Stellar protocol schemas",
    "proto": "RPC/protocol boundaries",
    "go": "node/keeper services",
    "rust": "node/runtime services",
    "java": "services/JVM protocol code",
    "cpp": "native consensus/runtime code",
    "typescript": "client/scripts/key handling",
    "python": "ops/scripts",
}

SOURCE_PRIORITIES = {
    "solidity": 100,
    "move": 95,
    "clarity": 95,
    "vyper": 95,
    "anchor": 92,
    "substrate": 90,
    "soroban": 90,
    "ton": 88,
    "cairo": 86,
    "sway": 86,
    "go": 82,
    "rust": 80,
    "java": 72,
    "cpp": 70,
    "proto": 62,
    "xdr": 61,
    "typescript": 55,
    "python": 50,
}

CONTRACT_SCHEMA_LANGS = {
    "solidity", "vyper", "move", "clarity", "ton", "anchor",
    "substrate", "soroban", "cairo", "sway", "xdr", "proto",
}

DEFAULT_BUILD_LIMIT = 8
BOUNTY_FRAMEWORK_BOOSTS = {
    "cross-chain/messaging": 2200,
    "defi-protocol": 1600,
    "evm": 1000,
    "foundry": 700,
    "hardhat": 500,
    "anchor": 900,
    "solana": 900,
    "sui-move": 900,
    "aptos-move": 900,
    "stacks/clarity": 800,
    "ton": 800,
    "stellar/soroban": 800,
}
RESEARCH_SIGNAL_DIRS = {
    "poc",
    "pocs",
    "fuzz",
    "fuzzing",
    "fuzzer",
    "invariant",
    "invariants",
    "certora",
    "echidna",
    "scripts",
    "script",
}


def _chain_for_file(path: Path) -> str:
    return EXT_TO_CHAIN.get(path.suffix.lower(), "")


def _project_bucket(root: Path, file_path: Path) -> str:
    try:
        rel = file_path.relative_to(root)
    except ValueError:
        return "."
    return rel.parts[0] if len(rel.parts) > 1 else "."


def _find_package_roots(root: Path) -> dict[Path, Counter[str]]:
    """Find directories with project marker files."""
    roots: dict[Path, Counter[str]] = defaultdict(Counter)
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if not should_skip_dir_name(d)]
        markers = [f for f in filenames if f in PROJECT_MARKERS]
        if markers:
            p = Path(dirpath)
            for marker in markers:
                roots[p][marker] += 1
    return roots


def _nearest_package_root(root: Path, package_roots: set[Path], file_path: Path) -> str:
    """Assign a file to the nearest ancestor package root, or top-level bucket."""
    parent = file_path.parent
    while True:
        if parent in package_roots:
            try:
                rel = parent.relative_to(root)
                return "." if str(rel) == "." else str(rel)
            except ValueError:
                return "."
        if parent == root or parent.parent == parent:
            break
        parent = parent.parent
    return _project_bucket(root, file_path)


def _path_hint_matches(path: str, pattern: str) -> bool:
    normalized = path.lower().replace("\\", "/")
    segments = {part for part in normalized.split("/") if part and part != "."}
    pattern = pattern.lower()
    if "/" in pattern:
        return pattern in normalized
    for segment in segments:
        if segment == pattern:
            return True
        if segment.startswith((f"{pattern}-", f"{pattern}_")):
            return True
        if segment.endswith((f"-{pattern}", f"_{pattern}")):
            return True
    return False


def _add_unique(items: list[str], values) -> None:
    for value in values:
        if value and value not in items:
            items.append(value)


def _framework_hints(bucket: str, chains: Counter[str], markers: Counter[str]) -> list[str]:
    """Infer project ecosystem/framework hints from markers, languages, and path."""
    hints: list[str] = []

    for marker in markers:
        _add_unique(hints, MARKER_FRAMEWORKS.get(marker, ()))

    for chain in chains:
        _add_unique(hints, LANGUAGE_FRAMEWORKS.get(chain, ()))

    for patterns, values in PATH_FRAMEWORK_HINTS:
        if any(_path_hint_matches(bucket, pattern) for pattern in patterns):
            _add_unique(hints, values)

    return hints


def _db_path(root: Path, bucket: str) -> str:
    name = bucket.replace("/", "_").replace(".", "root")
    return str(root / ".chainscope" / f"{name}.db")


def _next_queries(languages: dict[str, int], frameworks: list[str]) -> list[str]:
    queries = ["cs_hotspots", "cs_audit"]
    language_set = set(languages)
    framework_set = set(frameworks)

    if language_set & CONTRACT_SCHEMA_LANGS:
        queries.extend(["cs_cross", "cs_state"])
    if language_set & {"solidity", "vyper", "move", "clarity", "ton", "cairo", "sway"}:
        queries.append("cs_defi")
    if language_set & {"rust", "anchor", "substrate", "soroban", "go", "java", "cpp", "typescript", "python"}:
        queries.append("cs_unsafe")
    if framework_set & {"cross-chain/messaging", "op-stack", "evm-node", "cosmos-sdk"}:
        queries.append("cs_paths")

    return list(dict.fromkeys(queries))


def _build_plan_entry(target: dict, why: str, include_research: bool = False) -> dict:
    path = target["path"]
    db = target["suggested_db"]
    languages = target.get("languages") or target.get("project_languages") or {}
    frameworks = target.get("frameworks", [])
    return {
        "path": path,
        "db": db,
        "why": why,
        "languages": languages,
        "frameworks": frameworks,
        "tool_call": {
            "tool": "cs_build",
            "repo_path": path,
            "db": db,
            "include_research": include_research,
        },
        "next_queries": _next_queries(languages, frameworks),
    }


def _build_plan(
    recommended: list[dict],
    risk_first_targets: list[dict],
    limit: int,
    include_research: bool = False,
) -> list[dict]:
    plan = []
    seen: set[str] = set()

    for target in recommended[: min(5, limit)]:
        plan.append(_build_plan_entry(target, "top risk-weighted package root", include_research=include_research))
        seen.add(target["path"])

    for target in risk_first_targets:
        if len(plan) >= limit:
            break
        path = target["path"]
        if path in seen:
            continue
        language = target.get("language", "supported source")
        focus = RISK_TAGS.get(language, language)
        plan.append(_build_plan_entry(target, f"risk-first {focus} target", include_research=include_research))
        seen.add(path)

    return plan


def _bounty_priority(chains: Counter[str], frameworks: list[str], markers: Counter[str]) -> int:
    """Bias toward likely exploit surfaces instead of repo size alone."""
    weighted = sum(SOURCE_PRIORITIES.get(chain, 10) * count for chain, count in chains.items())
    contract_files = sum(count for chain, count in chains.items() if chain in CONTRACT_SCHEMA_LANGS)
    infra_files = sum(
        count for chain, count in chains.items()
        if chain in {"go", "rust", "java", "cpp", "typescript", "python", "proto"}
    )
    marker_bonus = sum(SOURCE_PRIORITIES.get(PROJECT_MARKERS.get(m, ""), 0) for m in markers)
    framework_bonus = sum(BOUNTY_FRAMEWORK_BOOSTS.get(framework, 0) for framework in frameworks)

    score = weighted + marker_bonus + framework_bonus
    score += contract_files * 140
    if contract_files:
        score += 3000
    if contract_files and "cross-chain/messaging" in frameworks:
        score += 1200
    if contract_files and "defi-protocol" in frameworks:
        score += 900
    if not contract_files:
        score -= min(infra_files * 25, 15000)
    return score


def _recommended_targets(
    root: Path,
    project_summaries: list[dict],
    risk_first_targets: list[dict],
    top: int,
    strategy: str,
) -> list[dict]:
    if strategy == "bounty":
        ordered: list[dict] = []
        seen: set[str] = set()
        for target in risk_first_targets:
            path = target["path"]
            if path in seen:
                continue
            ordered.append({
                "path": path,
                "dominant": target.get("language", next(iter(target.get("project_languages", {})), "")),
                "source_files": target["source_files"],
                "languages": target.get("project_languages", {}),
                "frameworks": target["frameworks"],
                "skipped_noise": target["skipped_noise"],
                "risk_focus": target["risk_focus"],
                "suggested_db": target["suggested_db"],
                "selection_reason": f"risk-first {RISK_TAGS.get(target.get('language', ''), target.get('language', 'target'))}",
            })
            seen.add(path)
            if len(ordered) >= top:
                return ordered[:top]

        for item in project_summaries:
            path = str(root / item["path"]) if item["path"] != "." else str(root)
            if path in seen:
                continue
            dominant = next(iter(item["languages"]), "")
            ordered.append({
                "path": path,
                "dominant": dominant,
                "source_files": item["source_files"],
                "languages": item["languages"],
                "frameworks": item["frameworks"],
                "skipped_noise": item["skipped_noise"],
                "risk_focus": item["risk_focus"],
                "suggested_db": _db_path(root, item["path"]),
                "selection_reason": "bounty-prioritized package root",
            })
            seen.add(path)
            if len(ordered) >= top:
                break
        return ordered[:top]

    recommended = []
    for item in project_summaries[:top]:
        dominant = next(iter(item["languages"]), "")
        recommended.append({
            "path": str(root / item["path"]) if item["path"] != "." else str(root),
            "dominant": dominant,
            "source_files": item["source_files"],
            "languages": item["languages"],
            "frameworks": item["frameworks"],
            "skipped_noise": item["skipped_noise"],
            "risk_focus": item["risk_focus"],
            "suggested_db": _db_path(root, item["path"]),
            "selection_reason": "top risk-weighted package root",
        })
    return recommended


def _workspace_cluster(bucket: str) -> str:
    if not bucket or bucket == ".":
        return "."
    return bucket.split("/", 1)[0]


def _workspace_summaries(project_summaries: list[dict], root: Path, top: int) -> tuple[list[dict], list[dict]]:
    clusters: dict[str, dict] = {}
    for item in project_summaries:
        cluster_name = _workspace_cluster(item["path"])
        cluster = clusters.setdefault(cluster_name, {
            "cluster": cluster_name,
            "path": str(root / cluster_name) if cluster_name != "." else str(root),
            "project_count": 0,
            "source_files": 0,
            "languages": Counter(),
            "frameworks": Counter(),
            "priority_score": 0,
            "bounty_priority_score": 0,
            "top_projects": [],
        })
        cluster["project_count"] += 1
        cluster["source_files"] += item["source_files"]
        cluster["languages"].update(item["languages"])
        cluster["frameworks"].update(item["frameworks"])
        cluster["priority_score"] = max(cluster["priority_score"], item["priority_score"])
        cluster["bounty_priority_score"] = max(cluster["bounty_priority_score"], item["bounty_priority_score"])
        if len(cluster["top_projects"]) < 3:
            cluster["top_projects"].append(item["abs_path"])

    summarized = []
    for cluster in clusters.values():
        summarized.append({
            "cluster": cluster["cluster"],
            "path": cluster["path"],
            "project_count": cluster["project_count"],
            "source_files": cluster["source_files"],
            "languages": dict(cluster["languages"].most_common()),
            "frameworks": [name for name, _ in cluster["frameworks"].most_common(6)],
            "priority_score": cluster["priority_score"],
            "bounty_priority_score": cluster["bounty_priority_score"],
            "top_projects": cluster["top_projects"],
        })

    summarized.sort(key=lambda c: (c["bounty_priority_score"], c["source_files"]), reverse=True)
    recommended = summarized[:top]
    return summarized[:top], recommended


def profile_repository(
    repo_path: str,
    top: int = 20,
    strategy: str = "balanced",
    include_research: bool = False,
) -> dict:
    """Return a fast language/project inventory without building a graph."""
    root = Path(repo_path)
    if not root.is_dir():
        return {"error": f"{repo_path} is not a directory"}
    strategy = (strategy or "balanced").lower()
    if strategy not in {"balanced", "bounty"}:
        return {"error": f"unknown strategy: {strategy}"}

    ext_counts: Counter[str] = Counter()
    chain_counts: Counter[str] = Counter()
    marker_counts: Counter[str] = Counter()
    skipped_dirs: Counter[str] = Counter()
    research_signal_dirs: Counter[str] = Counter()
    skipped_source_reasons: Counter[str] = Counter()
    project_chains: dict[str, Counter[str]] = defaultdict(Counter)
    project_markers: dict[str, Counter[str]] = defaultdict(Counter)
    project_noise: dict[str, Counter[str]] = defaultdict(Counter)
    examples: dict[str, list[str]] = defaultdict(list)
    noise_examples: dict[str, list[str]] = defaultdict(list)
    total_files = 0
    detected_source_files = 0
    source_files = 0
    package_roots_with_markers = _find_package_roots(root)
    package_root_paths = set(package_roots_with_markers.keys())

    for dirpath, dirnames, filenames in os.walk(root):
        skipped = [d for d in dirnames if should_skip_dir_name(d, include_research=include_research)]
        for d in skipped:
            skipped_dirs[d] += 1
            if d.lower() in RESEARCH_SIGNAL_DIRS:
                research_signal_dirs[d.lower()] += 1
        dirnames[:] = [d for d in dirnames if not should_skip_dir_name(d, include_research=include_research)]

        for fname in filenames:
            total_files += 1
            path = Path(dirpath) / fname
            bucket = _nearest_package_root(root, package_root_paths, path)

            if fname in PROJECT_MARKERS:
                marker_counts[fname] += 1
                project_markers[bucket][fname] += 1

            ext = path.suffix.lower() or "[no_ext]"
            ext_counts[ext] += 1
            chain = _chain_for_file(path)
            if not chain:
                continue

            detected_source_files += 1
            try:
                rel_path = path.relative_to(root)
            except ValueError:
                rel_path = path
            noise_reason = classify_source_noise(str(rel_path), include_research=include_research)
            if noise_reason:
                skipped_source_reasons[noise_reason] += 1
                project_noise[bucket][noise_reason] += 1
                if len(noise_examples[noise_reason]) < 5:
                    try:
                        noise_examples[noise_reason].append(str(path.relative_to(root)))
                    except ValueError:
                        noise_examples[noise_reason].append(str(path))
                continue

            source_files += 1
            chain_counts[chain] += 1
            project_chains[bucket][chain] += 1
            if len(examples[chain]) < 5:
                try:
                    examples[chain].append(str(path.relative_to(root)))
                except ValueError:
                    examples[chain].append(str(path))

    project_summaries = []
    framework_counts: Counter[str] = Counter()
    for bucket, chains in project_chains.items():
        if not chains:
            continue
        if bucket == "." and package_roots_with_markers:
            continue
        weighted = sum(SOURCE_PRIORITIES.get(chain, 10) * count for chain, count in chains.items())
        markers = project_markers[bucket]
        marker_bonus = sum(SOURCE_PRIORITIES.get(PROJECT_MARKERS.get(m, ""), 0) for m in markers)
        weighted += marker_bonus
        focus = [RISK_TAGS[c] for c, _ in chains.most_common(5) if c in RISK_TAGS]
        frameworks = _framework_hints(bucket, chains, markers)
        bounty_score = _bounty_priority(chains, frameworks, markers)
        for framework in frameworks:
            framework_counts[framework] += sum(chains.values())
        project_summaries.append({
            "path": bucket,
            "abs_path": str(root / bucket) if bucket != "." else str(root),
            "source_files": sum(chains.values()),
            "languages": dict(chains.most_common()),
            "markers": dict(markers.most_common()),
            "frameworks": frameworks,
            "skipped_noise": dict(project_noise[bucket].most_common(5)),
            "risk_focus": focus,
            "priority_score": weighted,
            "bounty_priority_score": bounty_score,
        })
    sort_key = "bounty_priority_score" if strategy == "bounty" else "priority_score"
    project_summaries.sort(key=lambda p: (p[sort_key], p["source_files"]), reverse=True)

    recommended_by_language: dict[str, list[dict]] = {}
    for chain in chain_counts:
        matches = [p for p in project_summaries if chain in p["languages"]]
        matches.sort(key=lambda p: (p["languages"].get(chain, 0), p["priority_score"]), reverse=True)
        recommended_by_language[chain] = [
            {
                "path": p["abs_path"],
                "source_files": p["languages"].get(chain, 0),
                "project_languages": p["languages"],
                "frameworks": p["frameworks"],
                "skipped_noise": p["skipped_noise"],
                "risk_focus": p["risk_focus"],
                "suggested_db": _db_path(root, p["path"]),
            }
            for p in matches[:3]
        ]

    risk_first_targets = []
    for chain in CONTRACT_SCHEMA_LANGS:
        for target in recommended_by_language.get(chain, [])[:2]:
            target_with_lang = {"language": chain, **target}
            risk_first_targets.append(target_with_lang)
    risk_first_targets.sort(key=lambda t: (SOURCE_PRIORITIES.get(t["language"], 0), t["source_files"]), reverse=True)
    recommended = _recommended_targets(root, project_summaries, risk_first_targets, top, strategy)
    workspace_clusters, recommended_clusters = _workspace_summaries(project_summaries, root, top)
    workspace_mode = len(workspace_clusters) >= 3 or len(project_summaries) >= 6

    return {
        "repo": str(root),
        "ranking_strategy": strategy,
        "include_research": include_research,
        "workspace_mode": workspace_mode,
        "total_files_scanned": total_files,
        "source_files_detected": detected_source_files,
        "source_files_supported": source_files,
        "source_files_skipped_as_noise": sum(skipped_source_reasons.values()),
        "noise_reduction_percent": round(
            (sum(skipped_source_reasons.values()) / detected_source_files) * 100, 2
        ) if detected_source_files else 0,
        "languages": dict(chain_counts.most_common()),
        "frameworks": dict(framework_counts.most_common()),
        "top_extensions": dict(ext_counts.most_common(top)),
        "project_markers": dict(marker_counts.most_common()),
        "package_roots_detected": len(package_roots_with_markers),
        "examples": dict(examples),
        "top_projects": project_summaries[:top],
        "workspace_clusters": workspace_clusters,
        "recommended_clusters": recommended_clusters,
        "recommended_build_targets": recommended,
        "recommended_by_language": recommended_by_language,
        "risk_first_targets": risk_first_targets[:top],
        "build_plan": _build_plan(
            recommended, risk_first_targets, min(top, DEFAULT_BUILD_LIMIT), include_research=include_research
        ),
        "skipped_dirs": dict(skipped_dirs.most_common(12)),
        "research_signal_dirs": dict(research_signal_dirs.most_common()),
        "research_mode_dirs": sorted(RESEARCH_DIR_NAMES),
        "skipped_source_reasons": dict(skipped_source_reasons.most_common(12)),
        "noise_examples": dict(noise_examples),
        "_tip": (
            "Start with build_plan targets. Each entry is an cs_build call with an explicit db path; "
            "avoid indexing the whole blockchain folder into one graph unless you need a cross-project overview."
        ),
    }
