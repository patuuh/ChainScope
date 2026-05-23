#!/usr/bin/env python3
"""ChainScope MCP Server — exposes web3 knowledge graph tools to AI agents.

Consolidated tool set (12 tools):
  Core:        cs_profile, cs_build, cs_help, cs_audit
  Scanners:    cs_hotspots, cs_defi, cs_unsafe
  Exploration: cs_paths, cs_trace, cs_cross, cs_state, cs_lookup
"""

import json
import os
import sys
import logging
import time
from pathlib import Path

from mcp.server.fastmcp import FastMCP

# Logging to stderr only (stdout is reserved for MCP JSON-RPC)
logging.basicConfig(level=logging.INFO, stream=sys.stderr)
logger = logging.getLogger("chainscope")

mcp = FastMCP("chainscope")

# Default DB path — can be overridden per-call
DEFAULT_DB = os.environ.get("CHAINSCOPE_DB", os.environ.get("CHAINSCOPE_DB", "graph.db"))
DEFAULT_MCP_BUILD_TIMEOUT_SECONDS = int(
    os.environ.get(
        "CHAINSCOPE_BUILD_TIMEOUT_SECONDS",
        os.environ.get("CHAINSCOPE_BUILD_TIMEOUT_SECONDS", "105"),
    )
)


def _resolve_db(db: str | None) -> str:
    return db or DEFAULT_DB


def _find_nodes(conn, label: str) -> list:
    """Find nodes by label or qualified ID fragment.

    Supports: 'deposit', 'Vault.deposit', 'KeyManager::generate_key', etc.
    Tries exact label match first, then ID contains, then label LIKE.
    """
    # Exact label match
    rows = conn.execute(
        "SELECT id, label FROM nodes WHERE label = ?", (label,)
    ).fetchall()
    if rows:
        return rows
    # Qualified: search in node IDs (e.g., 'KeyManager::generate_key' matches '...::KeyManager::generate_key...')
    rows = conn.execute(
        "SELECT id, label FROM nodes WHERE id LIKE ?", (f"%{label}%",)
    ).fetchall()
    if rows:
        return rows
    # Fuzzy label match
    rows = conn.execute(
        "SELECT id, label FROM nodes WHERE label LIKE ?", (f"%{label}%",)
    ).fetchall()
    return rows


def _qualified_label(node_id: str) -> str:
    """Extract a human-readable qualified label from a node ID.

    'file.sol::Contract.function(uint256)' -> 'Contract.function'
    'file.cpp::ns::Class::method(int)' -> 'Class::method'
    """
    # Strip file prefix
    if "::" in node_id:
        parts = node_id.split("::")
        # Remove file part (first element) and param types
        relevant = parts[1:]  # skip file
        # Strip param types from last part
        if relevant:
            last = relevant[-1]
            paren = last.find("(")
            if paren > 0:
                relevant[-1] = last[:paren]
        # For short chains, return last 2 parts
        if len(relevant) <= 2:
            return "::".join(relevant)
        # For longer chains (ns::class::method), return last 2
        return "::".join(relevant[-2:])
    return node_id


def _load_metadata(raw: str | None) -> dict:
    """Parse node metadata defensively."""
    try:
        return json.loads(raw or "{}")
    except (json.JSONDecodeError, TypeError):
        return {}


def _include_metadata(meta: dict, exclude_research: bool) -> bool:
    """Return whether a node should be included under the current query scope."""
    return not (exclude_research and meta.get("source_kind") == "research")


TRAVERSAL_RELATIONS = ("calls", "flows_to", "inherits")


# ---------------------------------------------------------------------------
# CORE TOOLS
# ---------------------------------------------------------------------------

@mcp.tool()
def cs_profile(
    repo_path: str,
    top: int = 20,
    strategy: str = "balanced",
    include_research: bool = False,
) -> str:
    """Profile a repository before building a graph.

    Fast inventory of supported languages, project markers, ecosystem/framework
    hints, likely build targets, build plan entries, skipped directories, and
    source files excluded as test/generated/noise. Use this on large folders
    such as a multi-project blockchain workspace before calling cs_build.

    Args:
        repo_path: Absolute path to the repository or workspace to inspect
        top: Number of top projects/extensions to return
        strategy: balanced (default) or bounty for exploit-surface-first ranking
        include_research: Include scripts/poc/fuzz/invariant/certora-style research artifacts
    """
    from core.project_profile import profile_repository

    return json.dumps(
        profile_repository(repo_path, top=top, strategy=strategy, include_research=include_research),
        indent=2,
    )


@mcp.tool()
def cs_build(
    repo_path: str,
    db: str = "",
    lang: str = "",
    include_research: bool = False,
    timeout_seconds: int = DEFAULT_MCP_BUILD_TIMEOUT_SECONDS,
) -> str:
    """Build a knowledge graph from a source repository.

    Parses source files using tree-sitter and stores the call graph, state flows,
    and data flow paths in a SQLite database.

    Supported languages: Solidity, Vyper, Move, Clarity, Cairo, Sway, TON,
    Anchor (Solana), Substrate, Soroban (Stellar), C/C++, Rust, Go, Java,
    TypeScript/JavaScript, Python, protobuf, Stellar XDR.
    Multi-language indexing: repos with mixed languages get ALL languages indexed.
    Security detection: reentrancy, sinks, validation, overflow, access control,
    proxy/upgrade, unsafe blocks, panic/DoS, race conditions, KVStore lifecycles,
    deserialization, reflection, injection, weak crypto, private key handling,
    TON bounce/message-flow issues.
    DeFi detection: timestamp dependence, unchecked ERC20 returns, oracle/price
    manipulation (getReserves/latestAnswer), signature replay, precision loss.

    Run this FIRST before using any other ChainScope tool.

    Args:
        repo_path: Absolute path to the source repository to index
        db: Output database path (default: graph.db in current directory)
        lang: Override chain detection — one of: solidity, vyper, move, clarity, cairo, sway, ton, proto, xdr, anchor, substrate, soroban, cpp, rust, go, java, typescript, python
        include_research: Include scripts/poc/fuzz/invariant/certora-style research artifacts
        timeout_seconds: MCP-side build budget. Default returns before client 120s timeout; set <=0 to disable.
    """
    from core.indexer import Indexer

    repo = Path(repo_path)
    if not repo.is_dir():
        return f"Error: {repo_path} is not a directory"

    db_path = db or DEFAULT_DB
    lang_override = lang or None

    indexer = Indexer(str(repo), lang_override=lang_override, include_research=include_research)
    deadline = None
    if timeout_seconds and timeout_seconds > 0:
        deadline = time.monotonic() + timeout_seconds
    stats = indexer.index(db_path, deadline=deadline)
    status = "partial_timeout" if stats.get("timed_out") else "success"

    return json.dumps({
        "status": status,
        "chain": indexer.detected_chain,
        "all_chains": sorted(indexer.all_chains),
        "include_research": include_research,
        "timeout_seconds": timeout_seconds,
        "timed_out": stats.get("timed_out", False),
        "database": db_path,
        "files_considered": stats["files_considered"],
        "files_indexed": stats["files_indexed"],
        "extractor_runs": stats["extractor_runs"],
        "extractor_failures": stats["extractor_failures"],
        "failed_files": stats["failed_files"],
        "failure_examples": stats["failure_examples"],
        "nodes": stats["nodes"],
        "edges": stats["edges"],
        "transitions": stats["transitions"],
        "confidence": stats["confidence"],
        "_next_steps": [
            "cs_audit — full security report (stats, hotspots, reentrancy, taint, events, deadcode, sinks)",
            "cs_hotspots — top functions ranked by composite risk score",
            "cs_defi — DeFi-specific vulnerability patterns",
            "cs_unsafe — Rust/Go/Java/Python/TypeScript/DSL security issues",
        ],
    }, indent=2)


@mcp.tool()
def cs_help() -> str:
    """Show the recommended ChainScope workflow and tool catalog.

    Call this first to understand the correct order of operations.
    """
    return json.dumps({
        "workflow": [
            "1. cs_profile(repo_path) — optional but recommended for large/mixed workspaces.",
            "2. cs_build(repo_path) — REQUIRED before graph queries. Builds the knowledge graph.",
            "3. cs_audit() — Full security report: stats, hotspots, reentrancy, taint, sinks, events, deadcode, access gaps.",
            "4. Drill into specific areas with specialized tools below.",
        ],
        "scanner_tools": {
            "cs_hotspots": "Composite risk scorer — all functions ranked with detailed reasons (score >= 8 = critical). Covers: access control, validation, overflow, proxy, unchecked calls.",
            "cs_defi": "DeFi patterns: timestamp, oracle, ERC20, signature, slippage, downcasts, flash loans, callbacks, Anchor, Move/Clarity/Vyper transfer sinks. Use category= to filter.",
            "cs_unsafe": "Rust/Go/Java/Python/TypeScript/DSL issues: unsafe blocks, panics, races, type assertions, SQL injection, command execution, deserialization, private key handling, dead params. Use category= to filter.",
        },
        "exploration_tools": {
            "cs_lookup": "Complete function profile: callers, callees, state reads/writes, guards, edges. Use depth=2 for two levels.",
            "cs_paths": "Find call paths between two functions (from_label → to_label)",
            "cs_trace": "Trace all readers/writers of a state variable",
            "cs_cross": "Cross-contract/module boundary calls (trust boundary crossings)",
            "cs_state": "State machine transitions and lifecycle analysis",
        },
        "_tip": "All tools accept db='path/to/graph.db'. Default is graph.db in current directory.",
    }, indent=2)


import os as _os

_C_EXTENSIONS = {".c", ".h", ".cpp", ".cc", ".cxx", ".hpp", ".hxx", ".c++"}

def _is_c_file(filepath: str) -> bool:
    """Check if a file path is a C/C++ file."""
    _, ext = _os.path.splitext(filepath)
    return ext in _C_EXTENSIONS


def _score_function(row, meta, writes, ext_calls, guard_count):
    """Score a function for security risk. Returns (score, reasons).

    Works for all languages: Solidity/Vyper, Move/Clarity/Cairo/Sway,
    Rust/Anchor, Go/Java, TypeScript/Python, and C/C++.
    """
    score = 0
    reasons = []
    vis = row["visibility"]
    is_entry = vis in ("external", "public")

    # --- Universal scoring (all languages) ---
    if is_entry and writes > 0:
        score += 3
        reasons.append(f"entry+writes({writes})")
    if ext_calls > 0:
        score += 3
        reasons.append(f"ext_calls({ext_calls})")

    # --- C/C++ specific scoring ---
    if _is_c_file(row["file"]):
        if meta.get("command_injection_risk"):
            score += 5
            reasons.append(f"cmd_injection({len(meta['command_injection_risk'])})")
        if meta.get("buffer_overflow_risk"):
            score += 4
            reasons.append(f"buffer_overflow({len(meta['buffer_overflow_risk'])})")
        if meta.get("format_string_risk"):
            score += 4
            reasons.append(f"format_string({len(meta['format_string_risk'])})")
        if meta.get("use_after_free_risk"):
            score += 4
            reasons.append(f"use_after_free({len(meta['use_after_free_risk'])})")
        if meta.get("double_free_risk"):
            score += 3
            reasons.append(f"double_free({len(meta['double_free_risk'])})")
        if meta.get("integer_overflow_risk"):
            score += 3
            reasons.append(f"int_overflow({len(meta['integer_overflow_risk'])})")
        if meta.get("toctou_risk"):
            score += 3
            reasons.append(f"toctou({len(meta['toctou_risk'])})")
        if meta.get("path_traversal_risk"):
            score += 3
            reasons.append(f"path_traversal({len(meta['path_traversal_risk'])})")
        if meta.get("null_deref_risk"):
            score += 2
            reasons.append(f"null_deref({len(meta['null_deref_risk'])})")
        if meta.get("uninitialized_use"):
            score += 2
            reasons.append(f"uninit_use({len(meta['uninitialized_use'])})")
        # Access control for C (no view/pure exclusion — C lacks these modifiers)
        if is_entry and writes > 0 and guard_count == 0:
            score += 2
            reasons.append("no_access_control")
        return (score, reasons)

    # --- Solidity/Vyper/Rust/Go/Java scoring (existing logic, ALL checks) ---
    if meta.get("no_input_validation"):
        score += 2
        reasons.append("no_validation")
    if meta.get("reentrancy_risk"):
        score += 5
        reasons.append("reentrancy")
    if meta.get("cross_reentrancy"):
        score += 4
        reasons.append("cross_reentrancy")
    if meta.get("unchecked_erc20"):
        score += 3
        reasons.append(f"unchecked_erc20({len(meta['unchecked_erc20'])})")
    if meta.get("oracle_risk"):
        score += 2
        reasons.append(f"oracle({len(meta['oracle_risk'])})")
    if meta.get("timestamp_dependence"):
        score += 1
        reasons.append("timestamp")
    if meta.get("signature_risk"):
        score += 3
        reasons.append(f"sig_risk({meta['signature_risk']})")
    if meta.get("precision_risk"):
        score += 2
        reasons.append("precision")
    if meta.get("unchecked_calls"):
        score += 3
        reasons.append(f"unchecked_calls({len(meta['unchecked_calls'])})")
    if meta.get("proxy_risk"):
        score += 2
        reasons.append(f"proxy({meta['proxy_risk']})")
    if meta.get("upgrade_surface"):
        score += 3
        reasons.append("upgrade_surface")
    if meta.get("privileged_operations"):
        score += 2
        reasons.append(f"privileged({len(meta['privileged_operations'])})")
    if meta.get("unguarded_privileged_operation"):
        score += 4
        reasons.append("unguarded_privileged")
    if meta.get("unchecked_arithmetic"):
        score += 2
        reasons.append("unchecked_arith")
    if meta.get("has_assembly"):
        score += 1
        reasons.append("assembly")
    if meta.get("dos_risk"):
        unbounded = [d for d in meta["dos_risk"] if d["type"] == "unbounded_loop"]
        ext_in_loop = [d for d in meta["dos_risk"] if d["type"] == "external_call_in_loop"]
        if unbounded:
            score += 3
            reasons.append(f"unbounded_loop({len(unbounded)})")
        if ext_in_loop:
            score += 2
            reasons.append(f"ext_call_in_loop({len(ext_in_loop)})")
    if meta.get("frontrun_risk"):
        score += 2
        reasons.append(f"frontrun({len(meta['frontrun_risk'])})")
    if meta.get("unsafe_type_assertions"):
        score += 2
        reasons.append(f"unsafe_assert({len(meta['unsafe_type_assertions'])})")
    if meta.get("sql_injection_risk"):
        score += 4
        reasons.append(f"sqli({len(meta['sql_injection_risk'])})")
    if meta.get("command_injection_risk"):
        score += 5
        reasons.append(f"cmd_injection({len(meta['command_injection_risk'])})")
    if meta.get("deserialization_sinks"):
        score += 4
        reasons.append(f"deser({len(meta['deserialization_sinks'])})")
    if meta.get("injection_sinks"):
        score += 4
        reasons.append(f"injection({len(meta['injection_sinks'])})")
    if meta.get("weak_crypto"):
        score += 2
        reasons.append(f"weak_crypto({len(meta['weak_crypto'])})")
    if meta.get("private_key_material"):
        score += 4
        reasons.append("private_key_material")
    if meta.get("transfer_sinks"):
        score += 3
        reasons.append(f"transfer_sink({len(meta['transfer_sinks'])})")
    if meta.get("cross_contract_calls"):
        score += 2
        reasons.append(f"cross_contract({len(meta['cross_contract_calls'])})")
    if meta.get("ignored_bounce"):
        score += 3
        reasons.append("ignored_bounce")
    if meta.get("auth_boundary"):
        score += 2
        reasons.append("auth_boundary")
    if meta.get("unsafe_downcast"):
        score += 2
        reasons.append(f"unsafe_downcast({len(meta['unsafe_downcast'])})")
    if meta.get("flash_loan_risk"):
        score += 4
        reasons.append(f"flash_loan({','.join(meta['flash_loan_risk'])})")
    if meta.get("slippage_risk"):
        score += 3
        reasons.append(f"slippage({','.join(meta['slippage_risk'])})")
    if meta.get("dead_params"):
        score += 1
        reasons.append(f"dead_params({','.join(meta['dead_params'])})")
    if meta.get("erc_callback_risk"):
        score += 4
        reasons.append(f"erc_callback({','.join(meta['erc_callback_risk'])})")
    if meta.get("anchor_risks"):
        risk_types = [r["type"] for r in meta["anchor_risks"]]
        if "missing_signer" in risk_types:
            score += 4
            reasons.append("missing_signer")
        if "weak_pda_seeds" in risk_types:
            score += 3
            reasons.append("weak_pda")
        if "unchecked_no_owner" in risk_types:
            score += 3
            reasons.append("unchecked_account")
    if meta.get("cpi_reentrancy_risk"):
        score += 4
        reasons.append("cpi_reentrancy")
    # Access control (no guards)
    if is_entry and writes > 0 and guard_count == 0 and not meta.get("view") and not meta.get("pure"):
        score += 2
        reasons.append("no_access_control")

    return (score, reasons)


@mcp.tool()
def cs_audit(db: str = "", top: int = 15, exclude_research: bool = False) -> str:
    """Generate a comprehensive security audit report in one call.

    Combines: graph stats, attack surface, detection tallies, hotspot ranking,
    reentrancy findings, taint paths, sink reachability, dead code, access control
    gaps, silent state changes, and DeFi/unsafe summaries into a single report.

    This is the recommended tool after cs_build for a full audit overview.
    Use cs_hotspots, cs_defi, cs_unsafe for deeper drill-down with filtering.

    Args:
        db: Database path (default: graph.db)
        top: Max findings per category (default: 15)
        exclude_research: Exclude nodes originating from research-mode files
    """
    from core.schema import GraphDB
    from core.graph import Graph

    db_path = _resolve_db(db)
    graph_db = GraphDB(db_path)
    graph = Graph(db_path)
    conn = graph_db.get_connection()
    try:
        report: dict = {}

        # --- 1. Stats (formerly cs_summary) ---
        node_count = conn.execute("SELECT COUNT(*) FROM nodes").fetchone()[0]
        edge_count = conn.execute("SELECT COUNT(*) FROM edges").fetchone()[0]
        func_count = conn.execute("SELECT COUNT(*) FROM nodes WHERE type='function'").fetchone()[0]
        file_count = conn.execute("SELECT COUNT(DISTINCT file) FROM nodes").fetchone()[0]
        entry_count = conn.execute(
            "SELECT COUNT(*) FROM nodes WHERE type='function' AND visibility IN ('external', 'public')"
        ).fetchone()[0]
        guarded_count = conn.execute(
            "SELECT COUNT(DISTINCT target) FROM edges WHERE relation='guards'"
        ).fetchone()[0]
        sink_count = conn.execute(
            "SELECT COUNT(*) FROM nodes WHERE metadata LIKE '%\"is_sink\"%'"
        ).fetchone()[0]
        state_var_count = conn.execute(
            "SELECT COUNT(*) FROM nodes WHERE type='state_var'"
        ).fetchone()[0]
        transition_count = conn.execute(
            "SELECT COUNT(*) FROM state_transitions"
        ).fetchone()[0]

        report["stats"] = {
            "nodes": node_count, "edges": edge_count,
            "functions": func_count, "state_vars": state_var_count,
            "files": file_count, "transitions": transition_count,
            "entry_points": entry_count,
            "guarded_entry_points": guarded_count,
            "unguarded_entry_points": entry_count - guarded_count,
            "sinks": sink_count,
        }
        report["query_scope"] = "production_only" if exclude_research else "all_sources"
        build_info = graph_db.get_metadata("build_info")
        if build_info:
            report["build_info"] = build_info

        # Node/edge type breakdown
        type_rows = conn.execute(
            "SELECT type, COUNT(*) as cnt FROM nodes GROUP BY type ORDER BY cnt DESC"
        ).fetchall()
        report["stats"]["node_types"] = {r["type"]: r["cnt"] for r in type_rows}

        rel_rows = conn.execute(
            "SELECT relation, COUNT(*) as cnt FROM edges GROUP BY relation ORDER BY cnt DESC"
        ).fetchall()
        report["stats"]["edge_relations"] = {r["relation"]: r["cnt"] for r in rel_rows}

        # --- 2. Detection tallies (single metadata pass) ---
        DETECTION_KEYS = [
            "reentrancy_risk", "cross_reentrancy", "unchecked_calls",
            "no_input_validation", "proxy_risk", "unchecked_arithmetic",
            "upgrade_surface", "privileged_operations", "unguarded_privileged_operation",
            "timestamp_dependence", "unchecked_erc20", "oracle_risk",
            "signature_risk", "dos_risk", "precision_risk", "frontrun_risk",
            "unsafe_downcast", "flash_loan_risk", "slippage_risk",
            "dead_params", "erc_callback_risk", "anchor_risks",
            "cpi_reentrancy_risk", "unsafe_type_assertions",
            "sql_injection_risk", "unsafe_blocks", "panic_paths",
            "uses_tx_origin", "has_assembly", "potential_race",
            "no_error_check", "unchecked_errors", "transfer_sinks",
            "cross_contract_calls", "private_key_material",
            "command_injection_risk", "deserialization_sinks",
            "injection_sinks", "weak_crypto", "move_entry",
            "ton_accept_message", "ton_validation", "ignored_bounce",
            "streaming_rpc", "auth_boundary",
        ]
        detection_counts: dict[str, int] = {}
        source_context_counts: dict[str, int] = {}
        all_funcs = conn.execute(
            "SELECT id, label, file, line_start, visibility, signature, metadata FROM nodes WHERE type='function'"
        ).fetchall()
        func_meta_cache: dict[str, dict] = {}
        func_by_id: dict[str, dict] = {}
        for row in all_funcs:
            meta = json.loads(row["metadata"] or "{}")
            if exclude_research and meta.get("source_kind") == "research":
                continue
            func_meta_cache[row["id"]] = meta
            func_by_id[row["id"]] = row
            source_context = meta.get("source_context", "production")
            source_context_counts[source_context] = source_context_counts.get(source_context, 0) + 1
            for key in DETECTION_KEYS:
                if meta.get(key):
                    detection_counts[key] = detection_counts.get(key, 0) + 1

        report["detections"] = dict(sorted(detection_counts.items(), key=lambda x: -x[1]))
        report["source_context_summary"] = dict(sorted(source_context_counts.items(), key=lambda x: (-x[1], x[0])))

        # --- 3. Precompute shared data structures ---
        write_map: dict[str, int] = {}
        write_targets: dict[str, list[str]] = {}
        for r in conn.execute(
            "SELECT source, target FROM edges WHERE relation='writes_state'"
        ).fetchall():
            write_map[r["source"]] = write_map.get(r["source"], 0) + 1
            write_targets.setdefault(r["source"], []).append(r["target"])

        guard_set = set()
        for r in conn.execute(
            "SELECT DISTINCT target FROM edges WHERE relation='guards'"
        ).fetchall():
            guard_set.add(r["target"])

        ext_call_map: dict[str, int] = {}
        for r in conn.execute(
            "SELECT source, COUNT(*) as cnt FROM edges "
            "WHERE relation='calls' AND attributes LIKE '%\"unresolved\"%' "
            "AND attributes NOT LIKE '%\"internal_candidate\"%' GROUP BY source"
        ).fetchall():
            ext_call_map[r["source"]] = r["cnt"]
        for r in conn.execute(
            "SELECT source, COUNT(*) as cnt FROM edges WHERE relation='calls' AND attributes LIKE '%\"cpi\"%' GROUP BY source"
        ).fetchall():
            ext_call_map[r["source"]] = ext_call_map.get(r["source"], 0) + r["cnt"]

        adj = graph._build_adjacency(conn)

        # --- 4. Attack surface (formerly in cs_summary) ---
        attack_surface = graph.get_attack_surface()
        if attack_surface:
            report["attack_surface"] = attack_surface[:top]

        # --- 5. Top hotspots (inline scoring) ---
        hotspots = []
        for row in all_funcs:
            if row["label"] in ("constructor", "fallback", "receive"):
                continue
            meta = func_meta_cache.get(row["id"], {})
            vis = row["visibility"]
            writes = write_map.get(row["id"], 0)
            ext_calls = ext_call_map.get(row["id"], 0)
            guard_count = 1 if row["id"] in guard_set else 0
            score, reasons = _score_function(row, meta, writes, ext_calls, guard_count)

            if score >= 5:
                hotspots.append({
                    "function": row["label"],
                    "file": row["file"],
                    "line": row["line_start"],
                    "source_context": meta.get("source_context", "production"),
                    "score": score,
                    "reasons": reasons,
                })

        hotspots.sort(key=lambda x: -x["score"])
        report["critical_hotspots"] = hotspots[:top]
        report["hotspot_summary"] = {
            "total_scored": len(hotspots),
            "critical_8plus": sum(1 for h in hotspots if h["score"] >= 8),
            "high_5to7": sum(1 for h in hotspots if 5 <= h["score"] < 8),
        }

        # --- 6. Reentrancy findings (detailed, formerly cs_reentrancy) ---
        reent = []
        for row in all_funcs:
            meta = func_meta_cache.get(row["id"], {})
            if meta.get("reentrancy_risk"):
                guards = conn.execute(
                    "SELECT n.label FROM edges e JOIN nodes n ON e.source = n.id "
                    "WHERE e.target = ? AND e.relation = 'guards'",
                    (row["id"],)
                ).fetchall()
                reent.append({
                    "function": row["label"],
                    "file": row["file"],
                    "line": row["line_start"],
                    "source_context": meta.get("source_context", "production"),
                    "type": "single_function",
                    "details": meta.get("reentrancy_details", ""),
                    "modifiers": [g["label"] for g in guards],
                })
            for cr in meta.get("cross_reentrancy", []):
                reent.append({
                    "function": row["label"],
                    "file": row["file"],
                    "line": row["line_start"],
                    "source_context": meta.get("source_context", "production"),
                    "type": "cross_function",
                    "via": cr["via"],
                    "stale_vars": cr["stale_vars"],
                })
        if reent:
            report["reentrancy"] = reent[:top]

        # --- 7. Taint paths (entry→sink) ---
        sink_ids = set()
        sink_info: dict[str, dict] = {}
        for s in conn.execute(
            "SELECT id, label, metadata FROM nodes WHERE metadata LIKE '%\"is_sink\"%'"
        ).fetchall():
            smeta = json.loads(s["metadata"])
            if smeta.get("is_sink"):
                sink_ids.add(s["id"])
                sink_info[s["id"]] = {
                    "label": s["label"],
                    "type": smeta.get("sink_type", "unknown"),
                }

        taint_results = []
        if sink_ids:
            for row in all_funcs:
                vis = row["visibility"]
                if vis not in ("external", "public"):
                    continue
                meta = func_meta_cache.get(row["id"], {})
                if meta.get("view") or meta.get("pure"):
                    continue
                # Check has parameters
                sig = row["signature"] or ""
                po = sig.find("(")
                pc = sig.find(")")
                if not (po >= 0 and pc > po + 1):
                    continue
                is_guarded = row["id"] in guard_set
                reachable = graph.get_reachable_nodes([row["id"]], adj=adj)
                reached = reachable & sink_ids
                if reached:
                    sink_details = []
                    for sid in list(reached)[:5]:
                        si = sink_info.get(sid, {})
                        sink_details.append({"sink": si.get("label", "?"), "type": si.get("type", "?")})
                    taint_results.append({
                        "entry": row["label"],
                        "file": row["file"],
                        "source_context": meta.get("source_context", "production"),
                        "visibility": vis,
                        "guarded": is_guarded,
                        "reachable_sinks": len(reached),
                        "sinks": sink_details,
                        "risk": "HIGH" if not is_guarded else "MEDIUM",
                    })
                if len(taint_results) >= top * 2:
                    break
        taint_results.sort(key=lambda x: (0 if x["risk"] == "HIGH" else 1, -x["reachable_sinks"]))
        if taint_results:
            report["taint_paths"] = taint_results[:top]
            report["taint_summary"] = {
                "total": len(taint_results),
                "high_risk": sum(1 for r in taint_results if r["risk"] == "HIGH"),
            }

        # --- 8. Sink reachability summary (formerly cs_sinks) ---
        if sink_ids:
            sink_type_counts: dict[str, int] = {}
            for sid, si in sink_info.items():
                st = si.get("type", "unknown")
                sink_type_counts[st] = sink_type_counts.get(st, 0) + 1
            # Build reverse adjacency for backward BFS
            rev_adj = graph._build_reverse_adjacency(conn)
            node_map = graph._build_node_map(conn)
            # Count how many unique functions can reach each sink type
            sink_reachable: dict[str, set] = {}
            for sid, si in sink_info.items():
                st = si.get("type", "unknown")
                if st not in sink_reachable:
                    sink_reachable[st] = set()
                # Quick backward BFS from this sink
                visited = {sid}
                queue = [sid]
                while queue:
                    curr = queue.pop()
                    for caller in rev_adj.get(curr, []):
                        if caller not in visited:
                            visited.add(caller)
                            queue.append(caller)
                sink_reachable[st] |= visited

            report["sink_summary"] = {
                "by_type": sink_type_counts,
                "reachable_functions": {st: len(ids) for st, ids in sink_reachable.items()},
            }

        # --- 9. Access control gaps (formerly cs_access) ---
        access_gaps = []
        for row in all_funcs:
            meta = func_meta_cache.get(row["id"], {})
            vis = row["visibility"]
            if vis not in ("external", "public"):
                continue
            if meta.get("view") or meta.get("pure"):
                continue
            if row["label"] in ("constructor", "fallback", "receive"):
                continue
            if meta.get("modifiers"):
                continue
            if meta.get("role_guards"):
                continue
            if row["id"] in guard_set:
                continue
            writes = write_map.get(row["id"], 0)
            if writes == 0:
                continue
            # Skip common user-facing permissionless functions
            user_facing = {"transfer", "approve", "transferFrom",
                           "increaseAllowance", "decreaseAllowance",
                           "deposit", "withdraw", "mint", "burn",
                           "wrap", "unwrap", "stake", "unstake",
                           "submit", "claim", "redeem", "swap",
                           "permit", "safeTransfer", "safeTransferFrom",
                           "setApprovalForAll"}
            if row["label"] in user_facing:
                continue
            # Skip test files
            test_patterns = ("test/", "tests/", "test_", "forge-test/", "mock/",
                             "mocks/", "fixture/", "script/", "scripts/")
            if any(pat in row["file"] for pat in test_patterns):
                continue
            wt = write_targets.get(row["id"], [])
            wvars = [t.split("::")[-1].split(".")[-1] for t in wt[:5]]
            access_gaps.append({
                "function": row["label"],
                "file": row["file"],
                "source_context": meta.get("source_context", "production"),
                "visibility": vis,
                "state_writes": wvars,
            })
        if access_gaps:
            report["access_control_gaps"] = access_gaps[:top]
            report["access_gaps_total"] = len(access_gaps)

        # --- 10. Silent state changes (formerly cs_events) ---
        emitters = set()
        for r in conn.execute(
            "SELECT DISTINCT source FROM edges WHERE relation='emits_event'"
        ).fetchall():
            emitters.add(r["source"])

        silent = []
        for fid, wcount in write_map.items():
            if fid in emitters:
                continue
            func = func_by_id.get(fid)
            if not func:
                continue
            meta = func_meta_cache.get(fid, {})
            if meta.get("view") or meta.get("pure"):
                continue
            if func["label"] == "constructor":
                continue
            if func["visibility"] in ("external", "public"):
                silent.append({
                    "function": func["label"],
                    "file": func["file"],
                    "source_context": meta.get("source_context", "production"),
                    "state_writes": wcount,
                })
        silent.sort(key=lambda x: -x["state_writes"])
        if silent:
            report["silent_state_changes"] = silent[:top]
            report["silent_total"] = len(silent)

        # --- 11. Dead code (formerly cs_deadcode) ---
        called_targets = set()
        for r in conn.execute(
            "SELECT DISTINCT target FROM edges WHERE relation = 'calls'"
        ).fetchall():
            called_targets.add(r["target"])

        library_ids = set()
        for r in conn.execute(
            "SELECT id FROM nodes WHERE type = 'library'"
        ).fetchall():
            library_ids.add(r["id"])

        dead_internal = []
        orphan_writers = []
        for func in all_funcs:
            fid = func["id"]
            vis = func["visibility"]
            meta = func_meta_cache.get(fid, {})
            if func["label"] in ("constructor", "fallback", "receive"):
                continue
            if fid in called_targets:
                continue

            if vis in ("internal", "private"):
                if "::" in fid:
                    file_part, rest = fid.split("::", 1)
                    dot_pos = rest.find(".")
                    parent_id = file_part + "::" + (rest[:dot_pos] if dot_pos >= 0 else rest)
                else:
                    parent_id = ""
                if parent_id in library_ids:
                    continue
                dead_internal.append({
                    "function": func["label"],
                    "file": func["file"],
                    "source_context": meta.get("source_context", "production"),
                    "visibility": vis,
                })
            elif vis in ("external", "public"):
                wt = write_targets.get(fid, [])
                if wt and not meta.get("view") and not meta.get("pure"):
                    wvars = [t.split("::")[-1].split(".")[-1] for t in wt[:5]]
                    orphan_writers.append({
                        "function": func["label"],
                        "file": func["file"],
                        "source_context": meta.get("source_context", "production"),
                        "visibility": vis,
                        "state_writes": wvars,
                    })

        report["dead_code"] = {
            "dead_internal": dead_internal[:top],
            "dead_internal_total": len(dead_internal),
            "direct_entry_points": orphan_writers[:top],
            "direct_entry_points_total": len(orphan_writers),
        }

        # --- 12. DeFi + Unsafe summary counts ---
        defi_keys = [
            "timestamp_dependence", "unchecked_erc20", "oracle_risk",
            "signature_risk", "precision_risk", "dos_risk", "frontrun_risk",
            "unsafe_downcast", "flash_loan_risk", "slippage_risk",
            "erc_callback_risk", "anchor_risks", "cpi_reentrancy_risk",
            "upgrade_surface", "unguarded_privileged_operation",
            "transfer_sinks", "cross_contract_calls", "ignored_bounce",
        ]
        defi_counts = {k: detection_counts.get(k, 0) for k in defi_keys if detection_counts.get(k, 0) > 0}
        if defi_counts:
            report["defi_summary"] = defi_counts

        unsafe_keys = [
            "unsafe_blocks", "panic_paths", "potential_race",
            "unsafe_type_assertions", "sql_injection_risk",
            "no_error_check", "unchecked_errors", "command_injection_risk",
            "deserialization_sinks", "injection_sinks", "weak_crypto",
            "private_key_material",
        ]
        unsafe_counts = {k: detection_counts.get(k, 0) for k in unsafe_keys if detection_counts.get(k, 0) > 0}
        if unsafe_counts:
            report["unsafe_summary"] = unsafe_counts

        return json.dumps(report, indent=2)
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# SCANNER TOOLS (detailed drill-down with filtering)
# ---------------------------------------------------------------------------

@mcp.tool()
def cs_hotspots(db: str = "", top: int = 30, exclude_research: bool = False) -> str:
    """Rank functions by composite risk score — highest-priority bug bounty targets.

    Scores each function based on overlapping risk indicators:

    Universal (all languages):
    - External/public visibility with state writes (+3)
    - External calls (unresolved cross-contract) (+3)

    Solidity/Vyper/Move/Clarity/Cairo/Sway/Rust/Go/Java/TypeScript/Python:
    - No access control modifier (+2), No input validation (+2)
    - Reentrancy risk (+5), Cross-function reentrancy (+4)
    - Unchecked ERC20 returns (+3), Oracle/price reads (+2)
    - Timestamp dependence (+1), Signature risk (+3)
    - Precision loss (+2), Unchecked low-level calls (+3)
    - Proxy risk (+2), Unchecked arithmetic (+2), Has assembly (+1)
    - Unsafe downcasts (+2), Flash loan callback risks (+4)
    - Missing slippage/deadline (+3), Dead parameters (+1)
    - Cross-contract/asset transfer sinks (+2/+3), private key material (+4)
    - Command execution (+5), deserialization/injection sinks (+4), weak crypto (+2)

    C/C++ specific:
    - Command injection (+5), Buffer overflow (+4)
    - Format string (+4), Use-after-free (+4)
    - Double free (+3), Integer overflow (+3)
    - TOCTOU (+3), Path traversal (+3)
    - Null dereference (+2), Uninitialized use (+2)
    - No access control (+2)

    Functions with score >= 5 are high-priority. Score >= 8 is critical.

    Args:
        db: Database path (default: graph.db)
        top: Number of top results to return (default: 30)
        exclude_research: Exclude nodes originating from research-mode files
    """
    from core.schema import GraphDB

    db_path = _resolve_db(db)
    graph_db = GraphDB(db_path)
    conn = graph_db.get_connection()
    try:
        # Get all functions
        rows = conn.execute("""
            SELECT id, label, file, visibility, signature, line_start, metadata
            FROM nodes WHERE type = 'function'
        """).fetchall()

        scored = []
        for r in rows:
            if r["label"] in ("constructor", "fallback", "receive"):
                continue
            meta = json.loads(r["metadata"] or "{}")
            if exclude_research and meta.get("source_kind") == "research":
                continue

            writes = conn.execute(
                "SELECT COUNT(*) as cnt FROM edges "
                "WHERE source = ? AND relation = 'writes_state'",
                (r["id"],)
            ).fetchone()["cnt"]

            ext_calls = conn.execute(
                "SELECT COUNT(*) as cnt FROM edges "
                "WHERE source = ? AND relation = 'calls' "
                "AND attributes LIKE '%\"unresolved\"%' "
                "AND attributes NOT LIKE '%\"internal_candidate\"%'",
                (r["id"],)
            ).fetchone()["cnt"]

            # Only query guards when needed (entry point with writes)
            guards = 0
            vis = r["visibility"]
            if vis in ("external", "public") and writes > 0:
                guards = conn.execute(
                    "SELECT COUNT(*) as cnt FROM edges "
                    "WHERE target = ? AND relation = 'guards'",
                    (r["id"],)
                ).fetchone()["cnt"]

            score, reasons = _score_function(r, meta, writes, ext_calls, guards)

            if score >= 3:
                scored.append({
                    "function": r["label"],
                    "file": r["file"],
                    "line": r["line_start"],
                    "visibility": r["visibility"],
                    "source_context": meta.get("source_context", "production"),
                    "score": score,
                    "reasons": reasons,
                })

        scored.sort(key=lambda x: x["score"], reverse=True)
        result = scored[:top]

        # Severity distribution
        critical = sum(1 for s in scored if s["score"] >= 8)
        high = sum(1 for s in scored if 5 <= s["score"] < 8)
        medium = sum(1 for s in scored if 3 <= s["score"] < 5)

        return json.dumps({
            "hotspots": result,
            "_summary": {
                "total_scored": len(scored),
                "critical_8plus": critical,
                "high_5to7": high,
                "medium_3to4": medium,
                "top_shown": len(result),
                "query_scope": "production_only" if exclude_research else "all_sources",
            }
        }, indent=2)
    finally:
        conn.close()


@mcp.tool()
def cs_defi(db: str = "", category: str = "", exclude_research: bool = False) -> str:
    """Find DeFi-specific vulnerability patterns in Solidity contracts.

    Detects high-value bug bounty targets:
    - timestamp: block.timestamp/number in comparisons or arithmetic (deadline bypass, auction manipulation)
    - erc20: unchecked ERC20 transfer/transferFrom return values (silent token loss)
    - oracle: spot price reads (getReserves, balanceOf, latestAnswer) without TWAP (flash loan manipulation)
    - signature: ecrecover without nonce or chainId/domain (signature replay)
    - precision: division before multiplication (rounding/truncation errors)
    - dos: unbounded loops over dynamic arrays, external calls inside loops (gas griefing)
    - frontrun: approve without zero-set (ERC20 approve race condition)
    - downcast: unsafe uint256->uint128/uint96/etc narrowing without SafeCast (silent overflow)
    - flashloan: flash loan callbacks with state writes or missing reentrancy guards
    - slippage: swap/liquidity functions missing slippage or deadline parameters (MEV/sandwich)
    - callback: ERC721/ERC1155 receive hooks with state writes (reentrancy entry points)
    - anchor: Anchor/Solana account validation issues (missing signer, weak PDA, unchecked accounts)
    - cpi_reentrancy: Anchor CPI calls with state writes in same function
    - transfer/crosscontract: Move, Clarity, Vyper, Cairo, Sway, TypeScript transfer and cross-contract sinks

    Args:
        db: Database path (default: graph.db)
        category: Filter: timestamp, erc20, oracle, signature, precision, dos, frontrun, downcast, flashloan, slippage, callback, anchor, cpi_reentrancy, transfer, crosscontract, all (default: all)
        exclude_research: Exclude nodes originating from research-mode files
    """
    from core.schema import GraphDB

    db_path = _resolve_db(db)
    graph_db = GraphDB(db_path)
    conn = graph_db.get_connection()
    try:
        cat = category.lower() if category else "all"
        results: dict = {}

        def _include(meta: dict) -> bool:
            return not (exclude_research and meta.get("source_kind") == "research")

        def _ctx(meta: dict) -> str:
            return meta.get("source_context", "production")

        # --- Timestamp dependence ---
        if cat in ("all", "timestamp"):
            rows = conn.execute(
                "SELECT label, file, line_start, metadata FROM nodes "
                "WHERE type = 'function' AND metadata LIKE '%\"timestamp_dependence\"%'"
            ).fetchall()
            ts_fns = []
            for r in rows:
                meta = json.loads(r["metadata"])
                if not _include(meta):
                    continue
                ts_fns.append({
                    "function": r["label"], "file": r["file"],
                    "line": r["line_start"], "risks": meta.get("timestamp_dependence", []),
                    "source_context": _ctx(meta),
                })
            if ts_fns:
                results["timestamp_dependence"] = ts_fns

        # --- Unchecked ERC20 returns ---
        if cat in ("all", "erc20"):
            rows = conn.execute(
                "SELECT label, file, line_start, metadata FROM nodes "
                "WHERE type = 'function' AND metadata LIKE '%\"unchecked_erc20\"%'"
            ).fetchall()
            erc_fns = []
            for r in rows:
                meta = json.loads(r["metadata"])
                if not _include(meta):
                    continue
                erc_fns.append({
                    "function": r["label"], "file": r["file"],
                    "line": r["line_start"], "unchecked_calls": meta.get("unchecked_erc20", []),
                    "source_context": _ctx(meta),
                })
            if erc_fns:
                results["unchecked_erc20"] = erc_fns

        # --- Oracle / price manipulation ---
        if cat in ("all", "oracle"):
            rows = conn.execute(
                "SELECT label, file, line_start, metadata FROM nodes "
                "WHERE type = 'function' AND metadata LIKE '%\"oracle_risk\"%'"
            ).fetchall()
            oracle_fns = []
            for r in rows:
                meta = json.loads(r["metadata"])
                if not _include(meta):
                    continue
                oracle_fns.append({
                    "function": r["label"], "file": r["file"],
                    "line": r["line_start"], "risks": meta.get("oracle_risk", []),
                    "source_context": _ctx(meta),
                })
            if oracle_fns:
                results["oracle_manipulation"] = oracle_fns

        # --- Signature replay ---
        if cat in ("all", "signature"):
            rows = conn.execute(
                "SELECT label, file, line_start, metadata FROM nodes "
                "WHERE type = 'function' AND metadata LIKE '%\"signature_risk\"%'"
            ).fetchall()
            sig_fns = []
            for r in rows:
                meta = json.loads(r["metadata"])
                if not _include(meta):
                    continue
                sig_fns.append({
                    "function": r["label"], "file": r["file"],
                    "line": r["line_start"], "risks": meta.get("signature_risk", []),
                    "source_context": _ctx(meta),
                })
            if sig_fns:
                results["signature_replay"] = sig_fns

        # --- Precision loss ---
        if cat in ("all", "precision"):
            rows = conn.execute(
                "SELECT label, file, line_start, metadata FROM nodes "
                "WHERE type = 'function' AND metadata LIKE '%\"precision_risk\"%'"
            ).fetchall()
            prec_fns = []
            for r in rows:
                meta = json.loads(r["metadata"])
                if not _include(meta):
                    continue
                prec_fns.append({
                    "function": r["label"], "file": r["file"],
                    "line": r["line_start"], "risks": meta.get("precision_risk", []),
                    "source_context": _ctx(meta),
                })
            if prec_fns:
                results["precision_loss"] = prec_fns

        # --- DoS risks ---
        if cat in ("all", "dos"):
            rows = conn.execute(
                "SELECT label, file, line_start, metadata FROM nodes "
                "WHERE type = 'function' AND metadata LIKE '%\"dos_risk\"%'"
            ).fetchall()
            dos_fns = []
            for r in rows:
                meta = json.loads(r["metadata"])
                if not _include(meta):
                    continue
                dos_fns.append({
                    "function": r["label"], "file": r["file"],
                    "line": r["line_start"], "risks": meta.get("dos_risk", []),
                    "source_context": _ctx(meta),
                })
            if dos_fns:
                results["dos_risks"] = dos_fns

        # --- Frontrunning surface ---
        if cat in ("all", "frontrun"):
            rows = conn.execute(
                "SELECT label, file, line_start, metadata FROM nodes "
                "WHERE type = 'function' AND metadata LIKE '%\"frontrun_risk\"%'"
            ).fetchall()
            fr_fns = []
            for r in rows:
                meta = json.loads(r["metadata"])
                if not _include(meta):
                    continue
                fr_fns.append({
                    "function": r["label"], "file": r["file"],
                    "line": r["line_start"], "risks": meta.get("frontrun_risk", []),
                    "source_context": _ctx(meta),
                })
            if fr_fns:
                results["frontrunning"] = fr_fns

        # --- Unsafe downcasts ---
        if cat in ("all", "downcast"):
            rows = conn.execute(
                "SELECT label, file, line_start, metadata FROM nodes "
                "WHERE type = 'function' AND metadata LIKE '%\"unsafe_downcast\"%'"
            ).fetchall()
            dc_fns = []
            for r in rows:
                meta = json.loads(r["metadata"])
                if not _include(meta):
                    continue
                dc_fns.append({
                    "function": r["label"], "file": r["file"],
                    "line": r["line_start"], "casts": meta.get("unsafe_downcast", []),
                    "source_context": _ctx(meta),
                })
            if dc_fns:
                results["unsafe_downcasts"] = dc_fns

        # --- Flash loan callbacks ---
        if cat in ("all", "flashloan"):
            rows = conn.execute(
                "SELECT label, file, line_start, metadata FROM nodes "
                "WHERE type = 'function' AND metadata LIKE '%\"flash_loan_risk\"%'"
            ).fetchall()
            fl_fns = []
            for r in rows:
                meta = json.loads(r["metadata"])
                if not _include(meta):
                    continue
                fl_fns.append({
                    "function": r["label"], "file": r["file"],
                    "line": r["line_start"], "risks": meta.get("flash_loan_risk", []),
                    "source_context": _ctx(meta),
                })
            if fl_fns:
                results["flash_loan_risks"] = fl_fns

        # --- Slippage / deadline missing ---
        if cat in ("all", "slippage"):
            rows = conn.execute(
                "SELECT label, file, line_start, metadata FROM nodes "
                "WHERE type = 'function' AND metadata LIKE '%\"slippage_risk\"%'"
            ).fetchall()
            sl_fns = []
            for r in rows:
                meta = json.loads(r["metadata"])
                if not _include(meta):
                    continue
                sl_fns.append({
                    "function": r["label"], "file": r["file"],
                    "line": r["line_start"], "risks": meta.get("slippage_risk", []),
                    "source_context": _ctx(meta),
                })
            if sl_fns:
                results["slippage_missing"] = sl_fns

        # --- ERC callback reentrancy ---
        if cat in ("all", "callback"):
            rows = conn.execute(
                "SELECT label, file, line_start, metadata FROM nodes "
                "WHERE type = 'function' AND metadata LIKE '%\"erc_callback_risk\"%'"
            ).fetchall()
            cb_fns = []
            for r in rows:
                meta = json.loads(r["metadata"])
                if not _include(meta):
                    continue
                cb_fns.append({
                    "function": r["label"], "file": r["file"],
                    "line": r["line_start"], "risks": meta.get("erc_callback_risk", []),
                    "source_context": _ctx(meta),
                })
            if cb_fns:
                results["erc_callback_reentrancy"] = cb_fns

        # --- Anchor-specific risks ---
        if cat in ("all", "anchor"):
            rows = conn.execute(
                "SELECT label, file, line_start, metadata FROM nodes "
                "WHERE type = 'function' AND metadata LIKE '%\"anchor_risks\"%'"
            ).fetchall()
            anch_fns = []
            for r in rows:
                meta = json.loads(r["metadata"])
                if not _include(meta):
                    continue
                anch_fns.append({
                    "function": r["label"], "file": r["file"],
                    "line": r["line_start"], "risks": meta.get("anchor_risks", []),
                    "source_context": _ctx(meta),
                })
            if anch_fns:
                results["anchor_risks"] = anch_fns

        # --- CPI reentrancy (Anchor) ---
        if cat in ("all", "cpi_reentrancy"):
            rows = conn.execute(
                "SELECT label, file, line_start, metadata FROM nodes "
                "WHERE type = 'function' AND metadata LIKE '%\"cpi_reentrancy_risk\"%'"
            ).fetchall()
            cpi_fns = []
            for r in rows:
                meta = json.loads(r["metadata"])
                if not _include(meta):
                    continue
                cpi_fns.append({
                    "function": r["label"], "file": r["file"],
                    "line": r["line_start"],
                    "source_context": _ctx(meta),
                })
            if cpi_fns:
                results["cpi_reentrancy"] = cpi_fns

        # --- Cross-language transfer/cross-contract sinks ---
        if cat in ("all", "transfer"):
            rows = conn.execute(
                "SELECT label, file, line_start, metadata FROM nodes "
                "WHERE type = 'function' AND metadata LIKE '%\"transfer_sinks\"%'"
            ).fetchall()
            transfer_fns = []
            for r in rows:
                meta = json.loads(r["metadata"])
                if not _include(meta):
                    continue
                transfer_fns.append({
                    "function": r["label"], "file": r["file"],
                    "line": r["line_start"], "sinks": meta.get("transfer_sinks", []),
                    "language": meta.get("language", ""),
                    "source_context": _ctx(meta),
                })
            if transfer_fns:
                results["transfer_sinks"] = transfer_fns

        if cat in ("all", "crosscontract"):
            rows = conn.execute(
                "SELECT label, file, line_start, metadata FROM nodes "
                "WHERE type = 'function' AND metadata LIKE '%\"cross_contract_calls\"%'"
            ).fetchall()
            cc_fns = []
            for r in rows:
                meta = json.loads(r["metadata"])
                if not _include(meta):
                    continue
                cc_fns.append({
                    "function": r["label"], "file": r["file"],
                    "line": r["line_start"], "calls": meta.get("cross_contract_calls", []),
                    "language": meta.get("language", ""),
                    "source_context": _ctx(meta),
                })
            if cc_fns:
                results["cross_contract_calls"] = cc_fns

        # Summary
        total = sum(len(v) for v in results.values())
        results["_summary"] = {
            "total_findings": total,
            "categories": list(results.keys()),
            "query_scope": "production_only" if exclude_research else "all_sources",
        }

        return json.dumps(results, indent=2)
    finally:
        conn.close()


@mcp.tool()
def cs_unsafe(db: str = "", category: str = "", exclude_research: bool = False) -> str:
    """Find Rust/Go/Java/Python/TypeScript/DSL security issues.

    Cross-language security scanner for non-Solidity codebases. Detects:
    - Rust: unsafe blocks, transmute/FFI, unwrap/panic DoS, wrapping arithmetic
    - Go: goroutine data races, unchecked errors, missing validation, unsafe type assertions, SQL injection
    - Java: deserialization, reflection, injection, weak crypto, swallowed exceptions, resource leaks
    - Python/TypeScript: command execution, deserialization, private key material, weak crypto
    - Move/Clarity/Vyper/Cairo/Sway: missing validation, transfer/cross-contract sinks

    Args:
        db: Database path (default: graph.db)
        category: Filter: unsafe, panic, race, ffi, validation, go, type_assert, sql, java, python, js, command, keys, deser, reflection, injection, crypto, downcast, dead_params, all (default: all)
        exclude_research: Exclude nodes originating from research-mode files
    """
    from core.schema import GraphDB

    db_path = _resolve_db(db)
    graph_db = GraphDB(db_path)
    conn = graph_db.get_connection()
    try:
        cat = category.lower() if category else "all"
        results: dict = {}

        def _include(meta: dict) -> bool:
            return not (exclude_research and meta.get("source_kind") == "research")

        def _ctx(meta: dict) -> str:
            return meta.get("source_context", "production")

        # --- Unsafe blocks (Rust) ---
        if cat in ("all", "unsafe"):
            rows = conn.execute(
                "SELECT label, file, signature, metadata FROM nodes "
                "WHERE type = 'function' AND metadata LIKE '%\"unsafe_blocks\"%'"
            ).fetchall()
            unsafe_fns = []
            for r in rows:
                meta = json.loads(r["metadata"])
                if not _include(meta):
                    continue
                unsafe_fns.append({
                    "function": r["label"], "file": r["file"],
                    "unsafe_blocks": meta.get("unsafe_blocks", 0),
                    "unsafe_operations": meta.get("unsafe_operations", []),
                    "raw_pointers": meta.get("raw_pointers", False),
                    "source_context": _ctx(meta),
                })
            if unsafe_fns:
                results["unsafe_blocks"] = unsafe_fns

        # --- Panic/unwrap sinks (Rust) ---
        if cat in ("all", "panic"):
            rows = conn.execute(
                "SELECT label, file, signature, metadata FROM nodes "
                "WHERE type = 'function' AND metadata LIKE '%\"panic_paths\"%'"
            ).fetchall()
            panic_fns = []
            for r in rows:
                meta = json.loads(r["metadata"])
                if not _include(meta):
                    continue
                panic_fns.append({
                    "function": r["label"], "file": r["file"],
                    "panic_calls": meta.get("panic_paths", []),
                    "source_context": _ctx(meta),
                })
            if panic_fns:
                results["panic_sinks"] = panic_fns

        # --- Race conditions (Go) ---
        if cat in ("all", "race"):
            rows = conn.execute(
                "SELECT label, file, signature, metadata FROM nodes "
                "WHERE type = 'function' AND metadata LIKE '%\"potential_race\"%'"
            ).fetchall()
            races = []
            for r in rows:
                meta = json.loads(r["metadata"])
                if not _include(meta):
                    continue
                race_info = meta.get("potential_race", {})
                races.append({
                    "function": r["label"], "file": r["file"],
                    "shared_fields": race_info.get("shared_fields", []),
                    "goroutine_line": race_info.get("goroutine_line", 0),
                    "source_context": _ctx(meta),
                })
            if races:
                results["race_conditions"] = races

        # --- FFI/transmute (Rust) ---
        if cat in ("all", "ffi"):
            sink_rows = conn.execute(
                "SELECT label, file, metadata FROM nodes "
                "WHERE metadata LIKE '%\"sink_type\": \"unsafe_ffi\"%'"
            ).fetchall()
            ffi_sinks = []
            for r in sink_rows:
                meta = json.loads(r["metadata"] or "{}")
                if not _include(meta):
                    continue
                ffi_sinks.append({"operation": r["label"], "file": r["file"], "source_context": _ctx(meta)})
            if ffi_sinks:
                results["ffi_risks"] = ffi_sinks

        # --- Missing validation (both Rust and Go) ---
        if cat in ("all", "validation"):
            rows = conn.execute(
                "SELECT label, file, signature, visibility, metadata FROM nodes "
                "WHERE type = 'function' AND metadata LIKE '%\"no_input_validation\"%'"
            ).fetchall()
            no_val = []
            for r in rows:
                meta = json.loads(r["metadata"])
                if not _include(meta):
                    continue
                if meta.get("no_input_validation"):
                    no_val.append({
                        "function": r["label"], "file": r["file"],
                        "visibility": r["visibility"],
                        "source_context": _ctx(meta),
                    })
            if no_val:
                results["missing_validation"] = no_val

        # --- Wrapping arithmetic (Rust) ---
        if cat in ("all", "unsafe"):
            rows = conn.execute(
                "SELECT label, file, metadata FROM nodes "
                "WHERE type = 'function' AND metadata LIKE '%\"wrapping_arithmetic\"%'"
            ).fetchall()
            wrap_fns = []
            for r in rows:
                meta = json.loads(r["metadata"])
                if not _include(meta):
                    continue
                wrap_fns.append({
                    "function": r["label"], "file": r["file"],
                    "operations": meta.get("wrapping_arithmetic", []),
                    "source_context": _ctx(meta),
                })
            if wrap_fns:
                results["wrapping_arithmetic"] = wrap_fns

        # --- Go: Unsafe type assertions ---
        if cat in ("all", "go", "type_assert"):
            rows = conn.execute(
                "SELECT label, file, metadata FROM nodes "
                "WHERE type = 'function' AND metadata LIKE '%\"unsafe_type_assertions\"%'"
            ).fetchall()
            ta_fns = []
            for r in rows:
                meta = json.loads(r["metadata"])
                if not _include(meta):
                    continue
                ta_fns.append({
                    "function": r["label"], "file": r["file"],
                    "assertions": meta.get("unsafe_type_assertions", []),
                    "source_context": _ctx(meta),
                })
            if ta_fns:
                results["unsafe_type_assertions"] = ta_fns

        # --- Go: SQL injection ---
        if cat in ("all", "go", "sql"):
            rows = conn.execute(
                "SELECT label, file, metadata FROM nodes "
                "WHERE type = 'function' AND metadata LIKE '%\"sql_injection_risk\"%'"
            ).fetchall()
            sql_fns = []
            for r in rows:
                meta = json.loads(r["metadata"])
                if not _include(meta):
                    continue
                sql_fns.append({
                    "function": r["label"], "file": r["file"],
                    "risks": meta.get("sql_injection_risk", []),
                    "source_context": _ctx(meta),
                })
            if sql_fns:
                results["sql_injection"] = sql_fns

        # --- Deserialization sinks ---
        if cat in ("all", "java", "python", "js", "deser"):
            rows = conn.execute(
                "SELECT label, file, metadata FROM nodes "
                "WHERE type = 'function' AND metadata LIKE '%\"deserialization_sinks\"%'"
            ).fetchall()
            deser_fns = []
            for r in rows:
                meta = json.loads(r["metadata"])
                if not _include(meta):
                    continue
                deser_fns.append({
                    "function": r["label"], "file": r["file"],
                    "sinks": meta.get("deserialization_sinks", []),
                    "source_context": _ctx(meta),
                })
            if deser_fns:
                results["deserialization"] = deser_fns

        # --- Java: Reflection usage ---
        if cat in ("all", "java", "reflection"):
            rows = conn.execute(
                "SELECT label, file, metadata FROM nodes "
                "WHERE type = 'function' AND metadata LIKE '%\"reflection_usage\"%'"
            ).fetchall()
            refl_fns = []
            for r in rows:
                meta = json.loads(r["metadata"])
                if not _include(meta):
                    continue
                refl_fns.append({
                    "function": r["label"], "file": r["file"],
                    "operations": meta.get("reflection_usage", []),
                    "source_context": _ctx(meta),
                })
            if refl_fns:
                results["reflection"] = refl_fns

        # --- Java: Injection sinks ---
        if cat in ("all", "java", "injection"):
            rows = conn.execute(
                "SELECT label, file, metadata FROM nodes "
                "WHERE type = 'function' AND metadata LIKE '%\"injection_sinks\"%'"
            ).fetchall()
            inj_fns = []
            for r in rows:
                meta = json.loads(r["metadata"])
                if not _include(meta):
                    continue
                inj_fns.append({
                    "function": r["label"], "file": r["file"],
                    "sinks": meta.get("injection_sinks", []),
                    "source_context": _ctx(meta),
                })
            if inj_fns:
                results["injection"] = inj_fns

        # --- Weak crypto ---
        if cat in ("all", "java", "python", "js", "crypto"):
            rows = conn.execute(
                "SELECT label, file, metadata FROM nodes "
                "WHERE type = 'function' AND metadata LIKE '%\"weak_crypto\"%'"
            ).fetchall()
            crypto_fns = []
            for r in rows:
                meta = json.loads(r["metadata"])
                if not _include(meta):
                    continue
                crypto_fns.append({
                    "function": r["label"], "file": r["file"],
                    "patterns": meta.get("weak_crypto", []),
                    "source_context": _ctx(meta),
                })
            if crypto_fns:
                results["weak_crypto"] = crypto_fns

        # --- Python/TypeScript: command execution ---
        if cat in ("all", "python", "command"):
            rows = conn.execute(
                "SELECT label, file, metadata FROM nodes "
                "WHERE type = 'function' AND metadata LIKE '%\"command_injection_risk\"%'"
            ).fetchall()
            cmd_fns = []
            for r in rows:
                meta = json.loads(r["metadata"])
                if not _include(meta):
                    continue
                cmd_fns.append({
                    "function": r["label"], "file": r["file"],
                    "risks": meta.get("command_injection_risk", []),
                    "language": meta.get("language", ""),
                    "source_context": _ctx(meta),
                })
            if cmd_fns:
                results["command_execution"] = cmd_fns

        # --- Python/TypeScript: private key material handling ---
        if cat in ("all", "python", "js", "keys"):
            rows = conn.execute(
                "SELECT label, file, metadata FROM nodes "
                "WHERE type = 'function' AND metadata LIKE '%\"private_key_material\"%'"
            ).fetchall()
            key_fns = []
            for r in rows:
                meta = json.loads(r["metadata"])
                if not _include(meta):
                    continue
                key_fns.append({
                    "function": r["label"], "file": r["file"],
                    "language": meta.get("language", ""),
                    "source_context": _ctx(meta),
                })
            if key_fns:
                results["private_key_material"] = key_fns

        # --- Java: Swallowed exceptions ---
        if cat in ("all", "java"):
            rows = conn.execute(
                "SELECT label, file, metadata FROM nodes "
                "WHERE type = 'function' AND metadata LIKE '%\"swallowed_exceptions\"%'"
            ).fetchall()
            swallow_fns = []
            for r in rows:
                meta = json.loads(r["metadata"])
                if not _include(meta):
                    continue
                if meta.get("swallowed_exceptions", 0) > 0:
                    swallow_fns.append({
                        "function": r["label"], "file": r["file"],
                        "empty_catches": meta["swallowed_exceptions"],
                        "source_context": _ctx(meta),
                    })
            if swallow_fns:
                results["swallowed_exceptions"] = swallow_fns

        # --- Java: Resource leaks ---
        if cat in ("all", "java"):
            rows = conn.execute(
                "SELECT label, file, metadata FROM nodes "
                "WHERE type = 'function' AND metadata LIKE '%\"resource_leaks\"%'"
            ).fetchall()
            leak_fns = []
            for r in rows:
                meta = json.loads(r["metadata"])
                if not _include(meta):
                    continue
                leak_fns.append({
                    "function": r["label"], "file": r["file"],
                    "types": meta.get("resource_leaks", []),
                    "source_context": _ctx(meta),
                })
            if leak_fns:
                results["resource_leaks"] = leak_fns

        # --- Unsafe downcasts (Solidity) ---
        if cat in ("all", "downcast"):
            rows = conn.execute(
                "SELECT label, file, line_start, metadata FROM nodes "
                "WHERE type = 'function' AND metadata LIKE '%\"unsafe_downcast\"%'"
            ).fetchall()
            dc_fns = []
            for r in rows:
                meta = json.loads(r["metadata"])
                if not _include(meta):
                    continue
                dc_fns.append({
                    "function": r["label"], "file": r["file"],
                    "line": r["line_start"], "casts": meta.get("unsafe_downcast", []),
                    "source_context": _ctx(meta),
                })
            if dc_fns:
                results["unsafe_downcasts"] = dc_fns

        # --- Dead parameters ---
        if cat in ("all", "dead_params"):
            rows = conn.execute(
                "SELECT label, file, line_start, visibility, metadata FROM nodes "
                "WHERE type = 'function' AND metadata LIKE '%\"dead_params\"%'"
            ).fetchall()
            dp_fns = []
            for r in rows:
                meta = json.loads(r["metadata"])
                if not _include(meta):
                    continue
                dp_fns.append({
                    "function": r["label"], "file": r["file"],
                    "line": r["line_start"], "visibility": r["visibility"],
                    "unused_params": meta.get("dead_params", []),
                    "source_context": _ctx(meta),
                })
            if dp_fns:
                results["dead_params"] = dp_fns

        # Summary
        total = sum(len(v) for v in results.values())
        results["_summary"] = {
            "total_findings": total,
            "categories": list(results.keys()),
            "query_scope": "production_only" if exclude_research else "all_sources",
        }

        return json.dumps(results, indent=2)
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# EXPLORATION TOOLS (drill-down, path finding, state tracing)
# ---------------------------------------------------------------------------

@mcp.tool()
def cs_paths(
    from_label: str,
    to_label: str,
    db: str = "",
    max_depth: int = 15,
    show_guards: bool = False,
    show_state: bool = False,
    exclude_research: bool = False,
) -> str:
    """Find call paths between two functions in the knowledge graph.

    Useful for tracing how an external entry point reaches a dangerous sink,
    or understanding the call chain between any two functions.

    Args:
        from_label: Source function name (e.g. "deposit")
        to_label: Target function name (e.g. "withdraw")
        db: Database path (default: graph.db)
        max_depth: Maximum path depth to search
        show_guards: Annotate each hop with its modifier/guard protections
        show_state: Annotate each hop with state variable reads/writes
        exclude_research: Exclude nodes originating from research-mode files
    """
    from collections import deque
    from core.schema import GraphDB

    db_path = _resolve_db(db)
    graph_db = GraphDB(db_path)
    conn = graph_db.get_connection()
    try:
        all_nodes = conn.execute(
            "SELECT id, label, metadata FROM nodes"
        ).fetchall()
        node_meta = {row["id"]: _load_metadata(row["metadata"]) for row in all_nodes}
        allowed_ids = {
            row["id"] for row in all_nodes
            if _include_metadata(node_meta[row["id"]], exclude_research)
        }

        from_nodes = [n for n in _find_nodes(conn, from_label) if n["id"] in allowed_ids]
        to_nodes = [n for n in _find_nodes(conn, to_label) if n["id"] in allowed_ids]

        if not from_nodes:
            if exclude_research:
                return json.dumps({"error": f"No production node found matching '{from_label}'"})
            return json.dumps({"error": f"No node found matching '{from_label}'"})
        if not to_nodes:
            if exclude_research:
                return json.dumps({"error": f"No production node found matching '{to_label}'"})
            return json.dumps({"error": f"No node found matching '{to_label}'"})

        adjacency_rows = conn.execute(
            """
            SELECT source, target
            FROM edges
            WHERE relation IN (?, ?, ?)
            """,
            TRAVERSAL_RELATIONS,
        ).fetchall()
        adjacency: dict[str, list[str]] = {}
        for row in adjacency_rows:
            if row["source"] not in allowed_ids or row["target"] not in allowed_ids:
                continue
            adjacency.setdefault(row["source"], []).append(row["target"])

        def _label_for_node(node_id: str) -> str:
            row = conn.execute(
                "SELECT label FROM nodes WHERE id = ?",
                (node_id,),
            ).fetchone()
            if not row:
                return node_id
            label = row["label"]
            count = conn.execute(
                "SELECT COUNT(*) as cnt FROM nodes WHERE label = ?",
                (label,),
            ).fetchone()["cnt"]
            if count > 1:
                return _qualified_label(node_id)
            return label

        def _find_paths(start_id: str, end_id: str, path_limit: int) -> list[list[str]]:
            results: list[list[str]] = []
            queue = deque([[start_id]])
            while queue and len(results) < path_limit:
                path = queue.popleft()
                current = path[-1]
                if current == end_id and len(path) > 1:
                    results.append(path)
                    continue
                if len(path) > max_depth:
                    continue
                for neighbor in adjacency.get(current, []):
                    if neighbor not in path:
                        queue.append(path + [neighbor])
            return results

        # Try all from/to combinations to find paths (handles ambiguous labels)
        all_path_ids: list[list[str]] = []
        seen_paths: set[tuple[str, ...]] = set()
        for fn in from_nodes:
            for tn in to_nodes:
                remaining = 10 - len(all_path_ids)
                if remaining <= 0:
                    break
                for path in _find_paths(fn["id"], tn["id"], remaining):
                    key = tuple(path)
                    if key in seen_paths:
                        continue
                    seen_paths.add(key)
                    all_path_ids.append(path)
                if len(all_path_ids) >= 10:
                    break
            if len(all_path_ids) >= 10:
                break

        all_paths = [[_label_for_node(node_id) for node_id in path] for path in all_path_ids]
        result = {
            "from": from_label,
            "to": to_label,
            "paths": all_paths,
            "query_scope": "production_only" if exclude_research else "all_sources",
        }

        if show_guards:
            result["guards"] = {}
            seen: set[str] = set()
            for path in all_path_ids:
                for node_id in path:
                    if node_id in seen:
                        continue
                    seen.add(node_id)
                    guards = conn.execute("""
                        SELECT n.id, n.label, n.metadata
                        FROM edges e JOIN nodes n ON e.source = n.id
                        WHERE e.target = ? AND e.relation = 'guards'
                    """, (node_id,)).fetchall()
                    labels = []
                    for guard in guards:
                        meta = _load_metadata(guard["metadata"])
                        if not _include_metadata(meta, exclude_research):
                            continue
                        labels.append(guard["label"])
                    if labels:
                        result["guards"][_label_for_node(node_id)] = labels

        if show_state:
            result["state_access"] = {}
            seen: set[str] = set()
            for path in all_path_ids:
                for node_id in path:
                    if node_id in seen:
                        continue
                    seen.add(node_id)
                    reads = conn.execute(
                        "SELECT target FROM edges WHERE source=? AND relation='reads_state'",
                        (node_id,)
                    ).fetchall()
                    writes = conn.execute(
                        "SELECT target FROM edges WHERE source=? AND relation='writes_state'",
                        (node_id,)
                    ).fetchall()
                    if reads or writes:
                        result["state_access"][_label_for_node(node_id)] = {
                            "reads": [r[0].split("::")[-1] for r in reads],
                            "writes": [w[0].split("::")[-1] for w in writes],
                        }

        return json.dumps(result, indent=2)
    finally:
        conn.close()


@mcp.tool()
def cs_trace(var: str, db: str = "", show_callers: bool = False, exclude_research: bool = False) -> str:
    """Trace all functions that read or write a state variable.

    Essential for understanding who can modify critical state like balances,
    totalSupply, owner, etc.

    Args:
        var: State variable name to trace (e.g. "balances", "totalSupply")
        db: Database path (default: graph.db)
        show_callers: Include one level of callers for each accessor
        exclude_research: Exclude nodes originating from research-mode files
    """
    from core.schema import GraphDB

    db_path = _resolve_db(db)
    graph_db = GraphDB(db_path)
    conn = graph_db.get_connection()
    try:
        rows = conn.execute(
            "SELECT id, label, file, signature, metadata FROM nodes WHERE label = ? AND type = 'state_var'",
            (var,)
        ).fetchall()
        if not rows:
            rows = conn.execute(
                "SELECT id, label, file, signature, metadata FROM nodes WHERE label LIKE ? AND type = 'state_var'",
                (f"%{var}%",)
            ).fetchall()
        if not rows:
            return json.dumps({"error": f"No state variable found matching '{var}'"})

        variables = []
        for row in rows:
            item = dict(row)
            item["metadata"] = _load_metadata(item.get("metadata"))
            if not _include_metadata(item["metadata"], exclude_research):
                continue
            item["source_context"] = item["metadata"].get("source_context", "production")
            variables.append(item)

        if not variables:
            return json.dumps({"error": f"No production state variable found matching '{var}'"})

        def _accessors(var_id: str, relation: str) -> list[dict]:
            accessors = conn.execute("""
                SELECT n.id, n.label, n.file, n.visibility, n.line_start, n.line_end, n.metadata
                FROM edges e JOIN nodes n ON e.source = n.id
                WHERE e.target = ? AND e.relation = ?
            """, (var_id, relation)).fetchall()
            results = []
            for row in accessors:
                item = dict(row)
                meta = _load_metadata(item.pop("metadata", None))
                if not _include_metadata(meta, exclude_research):
                    continue
                item["source_context"] = meta.get("source_context", "production")
                results.append(item)
            return results

        def _callers(node_id: str) -> list[dict]:
            rows = conn.execute("""
                SELECT n.id, n.label, n.file, n.visibility, n.metadata
                FROM edges e JOIN nodes n ON e.source = n.id
                WHERE e.target = ? AND e.relation = 'calls'
            """, (node_id,)).fetchall()
            callers = []
            for row in rows:
                item = dict(row)
                meta = _load_metadata(item.pop("metadata", None))
                if not _include_metadata(meta, exclude_research):
                    continue
                item["source_context"] = meta.get("source_context", "production")
                callers.append(item)
            return callers

        writers_by_id: dict[str, dict] = {}
        readers_by_id: dict[str, dict] = {}
        for variable in variables:
            for item in _accessors(variable["id"], "writes_state"):
                writers_by_id[item["id"]] = item
            for item in _accessors(variable["id"], "reads_state"):
                readers_by_id[item["id"]] = item

        writers = list(writers_by_id.values())
        readers = list(readers_by_id.values())

        if show_callers:
            for acc in writers + readers:
                acc["callers"] = _callers(acc["id"])

        return json.dumps({
            "variable": variables[0],
            "variables": variables,
            "variable_matches": len(variables),
            "query_scope": "production_only" if exclude_research else "all_sources",
            "writers": writers,
            "readers": readers,
        }, indent=2)
    finally:
        conn.close()


@mcp.tool()
def cs_cross(db: str = "", from_func: str = "", exclude_research: bool = False) -> str:
    """Find cross-contract and cross-module calls (unresolved interfaces, delegatecall, CPI).

    These are trust boundary crossings — critical for identifying attack vectors
    where external code can influence internal state.

    Args:
        db: Database path (default: graph.db)
        from_func: Trace from a specific function (empty = list all cross-contract calls)
        exclude_research: Exclude nodes originating from research-mode files
    """
    from core.schema import GraphDB
    from core.graph import Graph

    db_path = _resolve_db(db)
    graph_db = GraphDB(db_path)
    conn = graph_db.get_connection()
    try:
        if from_func:
            nodes = _find_nodes(conn, from_func)
            if not nodes:
                return json.dumps({"error": f"No function found matching '{from_func}'"})

            graph = Graph(db_path)
            start_id = None
            for node in nodes:
                row = conn.execute(
                    "SELECT metadata FROM nodes WHERE id = ?",
                    (node["id"],)
                ).fetchone()
                if row and _include_metadata(_load_metadata(row["metadata"]), exclude_research):
                    start_id = node["id"]
                    break
            if start_id is None:
                return json.dumps({"error": f"No production function found matching '{from_func}'"})
            reachable = graph.get_reachable_nodes([start_id])

            cross_boundary = []
            for node_id in reachable:
                source_row = conn.execute(
                    "SELECT label, file, metadata FROM nodes WHERE id = ?",
                    (node_id,)
                ).fetchone()
                source_meta = _load_metadata(source_row["metadata"]) if source_row else {}
                if source_row and not _include_metadata(source_meta, exclude_research):
                    continue
                edges = conn.execute(
                    "SELECT target, attributes FROM edges WHERE source = ? AND relation = 'calls'",
                    (node_id,)
                ).fetchall()
                for edge in edges:
                    attrs = json.loads(edge["attributes"])
                    if ((attrs.get("unresolved") and not attrs.get("internal_candidate"))
                            or attrs.get("sink") or attrs.get("cross_boundary")):
                        target = conn.execute(
                            "SELECT label, file, metadata FROM nodes WHERE id = ?", (edge["target"],)
                        ).fetchone()
                        target_meta = _load_metadata(target["metadata"]) if target else {}
                        if target and not _include_metadata(target_meta, exclude_research):
                            continue
                        cross_boundary.append({
                            "source": {
                                "label": source_row["label"],
                                "file": source_row["file"],
                                "source_context": source_meta.get("source_context", "production"),
                            } if source_row else {"label": node_id},
                            "target": {
                                "label": target["label"],
                                "file": target["file"],
                                "source_context": target_meta.get("source_context", "production"),
                            } if target else {"label": edge["target"]},
                            "attributes": attrs,
                        })

            return json.dumps(cross_boundary, indent=2)
        else:
            rows = conn.execute("""
                SELECT e.source, e.target, e.attributes,
                       s.label as source_label, s.file as source_file, s.metadata as source_metadata,
                       t.label as target_label, t.file as target_file, t.metadata as target_metadata
                FROM edges e
                LEFT JOIN nodes s ON e.source = s.id
                LEFT JOIN nodes t ON e.target = t.id
                WHERE e.relation = 'calls' AND (
                    (e.attributes LIKE '%"unresolved"%'
                     AND e.attributes NOT LIKE '%"internal_candidate"%')
                    OR e.attributes LIKE '%"sink"%'
                    OR e.attributes LIKE '%"cross_boundary"%'
                )
            """).fetchall()

            results = []
            for row in rows:
                entry = dict(row)
                source_meta = _load_metadata(entry.pop("source_metadata", None))
                target_meta = _load_metadata(entry.pop("target_metadata", None))
                if not _include_metadata(source_meta, exclude_research):
                    continue
                if entry.get("target_label") and not _include_metadata(target_meta, exclude_research):
                    continue
                entry["source_context"] = source_meta.get("source_context", "production")
                if entry.get("target_label"):
                    entry["target_source_context"] = target_meta.get("source_context", "production")
                results.append(entry)

            return json.dumps(results, indent=2, default=str)
    finally:
        conn.close()


@mcp.tool()
def cs_state(db: str = "", entity: str = "", exclude_research: bool = False) -> str:
    """Analyze state machine transitions and flag security issues.

    For Solidity: detects unguarded enum transitions, terminal states, missing transitions.
    For Cosmos SDK/Go: detects KVStore entity lifecycles (Set/Get/Delete), flags
    unvalidated writes, write-only entities (no deletion path), and unprotected CRUD.

    Args:
        db: Database path (default: graph.db)
        entity: Filter by entity name (e.g. "VaultState" or "Audience"). Empty = show all.
        exclude_research: Exclude transitions originating from research-mode files
    """
    from core.schema import GraphDB

    db_path = _resolve_db(db)
    graph_db = GraphDB(db_path)
    conn = graph_db.get_connection()
    try:
        if entity:
            rows = conn.execute(
                """
                SELECT st.*, n.file as function_file, n.label as function_label, n.metadata as function_metadata
                FROM state_transitions st
                LEFT JOIN nodes n ON st.function_id = n.id
                WHERE st.entity = ?
                """,
                (entity,)
            ).fetchall()
        else:
            rows = conn.execute("""
                SELECT st.*, n.file as function_file, n.label as function_label, n.metadata as function_metadata
                FROM state_transitions st
                LEFT JOIN nodes n ON st.function_id = n.id
            """).fetchall()

        transitions = []
        for row in rows:
            item = dict(row)
            meta = _load_metadata(item.pop("function_metadata", None))
            if not _include_metadata(meta, exclude_research):
                continue
            item["source_context"] = meta.get("source_context", "production")
            transitions.append(item)

        entities: dict[str, list[dict]] = {}
        for t in transitions:
            ent = t["entity"]
            if ent not in entities:
                entities[ent] = []
            entities[ent].append(t)

        warnings = []
        for ent, trans in entities.items():
            all_states = set()
            for t in trans:
                if t["from_state"] != "*":
                    all_states.add(t["from_state"])
                all_states.add(t["to_state"])

            # Detect Cosmos KV store lifecycle patterns
            has_set = any(t["to_state"] == "exists" and t["from_state"] == "*" for t in trans)
            has_delete = any(t["to_state"] == "deleted" for t in trans)
            has_read = any(json.loads(t.get("conditions", "[]")) == ["read"] for t in trans)

            if has_set or has_delete:
                # Cosmos KV store entity
                for t in trans:
                    conditions = json.loads(t.get("conditions", "[]"))
                    func_label = t.get("function_label") or t["function_id"].split("::")[-1]
                    if t["to_state"] == "exists" and "no_validation" in conditions:
                        warnings.append(
                            f"UNVALIDATED_WRITE: {func_label}() writes {ent} "
                            f"to store without input validation"
                        )
                    if t["to_state"] == "deleted" and "no_validation" in conditions:
                        warnings.append(
                            f"UNVALIDATED_DELETE: {func_label}() deletes {ent} "
                            f"from store without input validation"
                        )

                if has_set and not has_delete:
                    warnings.append(
                        f"NO_DELETE_PATH: {ent} can be created (Set) but never "
                        f"deleted — potential state bloat"
                    )
                if has_delete and not has_read:
                    warnings.append(
                        f"DELETE_WITHOUT_READ: {ent} can be deleted but no Get "
                        f"operation found — verify deletion logic"
                    )
            else:
                # Solidity-style enum state machine
                for t in trans:
                    if t["from_state"] == "*":
                        func_label = t.get("function_label") or t["function_id"].split("::")[-1]
                        warnings.append(
                            f"UNGUARDED: {func_label}() transitions {ent} to "
                            f"{t['to_state']} without checking current state"
                        )

                states_with_outgoing = {t["from_state"] for t in trans if t["from_state"] != "*"}
                states_targeted = {t["to_state"] for t in trans}
                terminal_states = all_states - states_with_outgoing
                for ts in terminal_states:
                    if any(t["to_state"] == ts for t in trans):
                        warnings.append(f"TERMINAL: {ent}::{ts} has no outgoing transitions")

                initial_candidates = states_with_outgoing - states_targeted
                for us in initial_candidates:
                    if us not in states_targeted:
                        warnings.append(
                            f"UNREACHABLE: {ent}::{us} has outgoing transitions "
                            f"but no incoming — may be unreachable after initialization"
                        )

                seen_pairs = set()
                for t1 in trans:
                    for t2 in trans:
                        if (t1["from_state"] == t2["to_state"]
                                and t1["to_state"] == t2["from_state"]
                                and t1["from_state"] != "*"
                                and t2["from_state"] != "*"):
                            pair = tuple(sorted([t1["from_state"], t1["to_state"]]))
                            if pair not in seen_pairs:
                                seen_pairs.add(pair)
                                c1 = json.loads(t1.get("conditions", "[]"))
                                c2 = json.loads(t2.get("conditions", "[]"))
                                if not c1 or not c2:
                                    warnings.append(
                                        f"TOGGLE: {ent} can toggle between "
                                        f"{pair[0]} <-> {pair[1]} — verify "
                                        f"this is intentional (potential griefing)"
                                    )

        return json.dumps({
            "entities": entities,
            "warnings": warnings,
            "query_scope": "production_only" if exclude_research else "all_sources",
        }, indent=2)
    finally:
        conn.close()


@mcp.tool()
def cs_lookup(name: str, db: str = "", depth: int = 1, exclude_research: bool = False) -> str:
    """Look up a function by name and return its complete profile.

    Returns every occurrence of the function in the graph with:
      - File, line range, signature, visibility, metadata
      - All direct callers (who calls this function)
      - All direct callees (what this function calls)
      - State variables it reads and writes
      - Guards/modifiers protecting it
      - Edges with attributes (e.g. call-site details)

    Use depth=2 to also include callers-of-callers and callees-of-callees.

    Args:
        name: Function name or fragment (e.g. "deposit", "Vault.withdraw",
              "KeyManager::generate_key")
        db: Database path (default: graph.db)
        depth: How many levels of callers/callees to include (1 or 2)
        exclude_research: Exclude nodes originating from research-mode files
    """
    from core.schema import GraphDB
    from core.graph import Graph

    db_path = _resolve_db(db)
    graph = Graph(db_path)
    graph_db = GraphDB(db_path)
    conn = graph_db.get_connection()
    try:
        nodes = _find_nodes(conn, name)
        if not nodes:
            return json.dumps({"error": f"No function found matching '{name}'"})

        results = []
        for node_row in nodes:
            node_id = node_row["id"]

            # Full node details
            full = conn.execute(
                "SELECT id, label, type, visibility, file, line_start, line_end, "
                "signature, metadata FROM nodes WHERE id = ?",
                (node_id,)
            ).fetchone()
            if not full:
                continue
            info = dict(full)
            info["metadata"] = _load_metadata(info.get("metadata"))
            if not _include_metadata(info["metadata"], exclude_research):
                continue

            # Callers (who calls this)
            callers = conn.execute("""
                SELECT n.id, n.label, n.file, n.visibility, n.line_start,
                       n.line_end, n.signature, n.metadata, e.attributes
                FROM edges e JOIN nodes n ON e.source = n.id
                WHERE e.target = ? AND e.relation = 'calls'
            """, (node_id,)).fetchall()
            filtered_callers = []
            for row in callers:
                caller = dict(row)
                meta = _load_metadata(caller.pop("metadata", None))
                if not _include_metadata(meta, exclude_research):
                    continue
                caller["source_context"] = meta.get("source_context", "production")
                filtered_callers.append(caller)
            info["callers"] = filtered_callers

            # Depth-2 callers
            if depth >= 2 and filtered_callers:
                for caller in info["callers"]:
                    c2 = conn.execute("""
                        SELECT n.id, n.label, n.file, n.visibility, n.metadata
                        FROM edges e JOIN nodes n ON e.source = n.id
                        WHERE e.target = ? AND e.relation = 'calls'
                    """, (caller["id"],)).fetchall()
                    caller["callers"] = []
                    for row in c2:
                        nested = dict(row)
                        meta = _load_metadata(nested.pop("metadata", None))
                        if not _include_metadata(meta, exclude_research):
                            continue
                        nested["source_context"] = meta.get("source_context", "production")
                        caller["callers"].append(nested)

            # Callees (what this calls)
            callees = conn.execute("""
                SELECT n.id, n.label, n.file, n.visibility, n.line_start,
                       n.line_end, n.signature, n.metadata, e.attributes
                FROM edges e JOIN nodes n ON e.target = n.id
                WHERE e.source = ? AND e.relation = 'calls'
            """, (node_id,)).fetchall()
            filtered_callees = []
            for row in callees:
                callee = dict(row)
                meta = _load_metadata(callee.pop("metadata", None))
                if not _include_metadata(meta, exclude_research):
                    continue
                callee["source_context"] = meta.get("source_context", "production")
                filtered_callees.append(callee)
            info["callees"] = filtered_callees

            # Depth-2 callees
            if depth >= 2 and filtered_callees:
                for callee in info["callees"]:
                    c2 = conn.execute("""
                        SELECT n.id, n.label, n.file, n.visibility, n.metadata
                        FROM edges e JOIN nodes n ON e.target = n.id
                        WHERE e.source = ? AND e.relation = 'calls'
                    """, (callee["id"],)).fetchall()
                    callee["callees"] = []
                    for row in c2:
                        nested = dict(row)
                        meta = _load_metadata(nested.pop("metadata", None))
                        if not _include_metadata(meta, exclude_research):
                            continue
                        nested["source_context"] = meta.get("source_context", "production")
                        callee["callees"].append(nested)

            # State reads
            reads = conn.execute("""
                SELECT n.id, n.label, n.file, n.metadata
                FROM edges e JOIN nodes n ON e.target = n.id
                WHERE e.source = ? AND e.relation = 'reads_state'
            """, (node_id,)).fetchall()
            info["state_reads"] = []
            for row in reads:
                state = dict(row)
                meta = _load_metadata(state.pop("metadata", None))
                if not _include_metadata(meta, exclude_research):
                    continue
                state["source_context"] = meta.get("source_context", "production")
                info["state_reads"].append(state)

            # State writes
            writes = conn.execute("""
                SELECT n.id, n.label, n.file, n.metadata
                FROM edges e JOIN nodes n ON e.target = n.id
                WHERE e.source = ? AND e.relation = 'writes_state'
            """, (node_id,)).fetchall()
            info["state_writes"] = []
            for row in writes:
                state = dict(row)
                meta = _load_metadata(state.pop("metadata", None))
                if not _include_metadata(meta, exclude_research):
                    continue
                state["source_context"] = meta.get("source_context", "production")
                info["state_writes"].append(state)

            # Guards/modifiers
            guards = []
            for guard in graph.get_guards_for(node_id):
                guard_meta = _load_metadata(conn.execute(
                    "SELECT metadata FROM nodes WHERE id = ?",
                    (guard["id"],)
                ).fetchone()["metadata"])
                if not _include_metadata(guard_meta, exclude_research):
                    continue
                guard["source_context"] = guard_meta.get("source_context", "production")
                guards.append(guard)
            info["guards"] = guards

            # All other edges (flows_to, inherits, emits_event, etc.)
            other_out = conn.execute("""
                SELECT e.relation, n.id, n.label, n.file, n.metadata, e.attributes
                FROM edges e JOIN nodes n ON e.target = n.id
                WHERE e.source = ? AND e.relation NOT IN
                      ('calls', 'reads_state', 'writes_state')
            """, (node_id,)).fetchall()
            if other_out:
                info["other_edges_out"] = []
                for row in other_out:
                    edge = dict(row)
                    meta = _load_metadata(edge.pop("metadata", None))
                    if not _include_metadata(meta, exclude_research):
                        continue
                    edge["source_context"] = meta.get("source_context", "production")
                    info["other_edges_out"].append(edge)

            other_in = conn.execute("""
                SELECT e.relation, n.id, n.label, n.file, n.metadata, e.attributes
                FROM edges e JOIN nodes n ON e.source = n.id
                WHERE e.target = ? AND e.relation NOT IN ('calls', 'guards')
            """, (node_id,)).fetchall()
            if other_in:
                info["other_edges_in"] = []
                for row in other_in:
                    edge = dict(row)
                    meta = _load_metadata(edge.pop("metadata", None))
                    if not _include_metadata(meta, exclude_research):
                        continue
                    edge["source_context"] = meta.get("source_context", "production")
                    info["other_edges_in"].append(edge)

            results.append(info)

        return json.dumps({
            "query": name,
            "matches": len(results),
            "query_scope": "production_only" if exclude_research else "all_sources",
            "functions": results,
        }, indent=2)
    finally:
        conn.close()


if __name__ == "__main__":
    mcp.run()
