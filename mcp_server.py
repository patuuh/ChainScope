#!/usr/bin/env python3
"""ChainScope MCP Server — exposes web3 knowledge graph tools to AI agents.

Consolidated tool set (15 tools):
  Core:        cs_profile, cs_build, cs_help, cs_summary, cs_audit
  Scanners:    cs_hotspots, cs_defi, cs_unsafe
  Exploration: cs_paths, cs_trace, cs_cross, cs_cross_summary, cs_sinks, cs_state, cs_lookup
"""

import json
import heapq
import os
import sys
import logging
import sqlite3
import time
import multiprocessing as mp
import queue as queue_mod
from pathlib import Path
from urllib.parse import quote

from mcp.server.fastmcp import FastMCP

# Logging to stderr only (stdout is reserved for MCP JSON-RPC)
logging.basicConfig(level=logging.INFO, stream=sys.stderr)
logger = logging.getLogger("chainscope")

mcp = FastMCP("chainscope")

# Default DB path — can be overridden per-call
DEFAULT_DB = os.environ.get("CHAINSCOPE_DB", os.environ.get("CHAINSCOPE_DB", "graph.db"))
DEFAULT_MCP_BUILD_TIMEOUT_SECONDS = int(os.environ.get("CHAINSCOPE_BUILD_TIMEOUT_SECONDS", "0"))
DEFAULT_MCP_QUERY_TIMEOUT_SECONDS = int(os.environ.get("CHAINSCOPE_QUERY_TIMEOUT_SECONDS", "30"))


def _resolve_db(db: str | None) -> str:
    return db or DEFAULT_DB


def _sqlite_uri(db_path: str, params: str) -> str:
    path = os.path.abspath(os.path.expanduser(db_path))
    return f"file:{quote(path, safe='/:')}?{params}"


def _open_query_connection(db_path: str, timeout_seconds: int | None = DEFAULT_MCP_QUERY_TIMEOUT_SECONDS):
    """Open an existing graph for read-only query tools without schema writes.

    SQLite can need lock sidecar access even for mode=ro reads. In sandboxed
    audit workspaces that may fail despite the DB file itself being readable, so
    fall back to immutable snapshots for read-only graph inspection.
    """
    attempts = (
        ("read_only", "mode=ro"),
        ("immutable", "mode=ro&immutable=1"),
    )
    last_error: Exception | None = None
    for mode, params in attempts:
        conn = None
        try:
            conn = sqlite3.connect(_sqlite_uri(db_path, params), uri=True, timeout=1.0)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys = ON")
            conn.execute("SELECT name FROM sqlite_master LIMIT 1").fetchone()
            if timeout_seconds and timeout_seconds > 0:
                deadline = time.monotonic() + timeout_seconds

                def _abort_on_deadline():
                    return 1 if time.monotonic() >= deadline else 0

                conn.set_progress_handler(_abort_on_deadline, 10_000)
            return conn
        except sqlite3.Error as exc:
            last_error = exc
            if conn is not None:
                conn.close()
            logger.debug("SQLite %s query open failed for %s: %s", mode, db_path, exc)
    if last_error is not None:
        raise last_error
    raise sqlite3.OperationalError(f"unable to open database file: {db_path}")


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


def _fetch_nodes_by_ids(conn, node_ids: list[str]) -> list[dict]:
    """Fetch full node rows in batches while preserving input order."""
    if not node_ids:
        return []
    rows_by_id: dict[str, dict] = {}
    columns = (
        "id, label, type, visibility, file, line_start, line_end, "
        "signature, metadata"
    )
    for start in range(0, len(node_ids), 500):
        batch = node_ids[start:start + 500]
        placeholders = ",".join("?" for _ in batch)
        rows = conn.execute(
            f"SELECT {columns} FROM nodes WHERE id IN ({placeholders})",
            batch,
        ).fetchall()
        for row in rows:
            rows_by_id[row["id"]] = dict(row)
    return [rows_by_id[node_id] for node_id in node_ids if node_id in rows_by_id]


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
    return not (exclude_research and _is_research_meta(meta))


TRAVERSAL_RELATIONS = ("calls", "flows_to", "inherits")


def _attr_enabled(value) -> bool:
    """Interpret common JSON attribute encodings without treating false-like strings as true."""
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        return value.strip().lower() not in ("", "0", "false", "no", "none", "null")
    return bool(value)


def _is_unresolved_external_call(attrs: dict) -> bool:
    return _attr_enabled(attrs.get("unresolved")) and not _attr_enabled(attrs.get("internal_candidate"))


def _is_trust_boundary_call(attrs: dict) -> bool:
    return (
        _is_unresolved_external_call(attrs)
        or _attr_enabled(attrs.get("sink"))
        or _attr_enabled(attrs.get("cross_boundary"))
    )


def _external_call_counts(conn, include_cpi: bool = False) -> dict[str, int]:
    """Count true external calls per source without trusting JSON key presence."""
    query = (
        "SELECT source, attributes FROM edges WHERE relation = 'calls' "
        "AND (attributes LIKE '%\"unresolved\"%'"
    )
    if include_cpi:
        query += " OR attributes LIKE '%\"cpi\"%'"
    query += ")"

    counts: dict[str, int] = {}
    for row in conn.execute(query):
        attrs = _load_metadata(row["attributes"])
        if _is_unresolved_external_call(attrs) or (include_cpi and _attr_enabled(attrs.get("cpi"))):
            counts[row["source"]] = counts.get(row["source"], 0) + 1
    return counts


def _iter_cross_call_rows(conn, exclude_research: bool):
    """Yield true trust-boundary call rows for broad cross-boundary scans."""
    rows = conn.execute("""
        SELECT e.source, e.target, e.attributes,
               s.label as source_label, s.file as source_file, s.metadata as source_metadata,
               t.label as target_label, t.file as target_file, t.metadata as target_metadata
        FROM edges e
        LEFT JOIN nodes s ON e.source = s.id
        LEFT JOIN nodes t ON e.target = t.id
        WHERE e.relation = 'calls' AND (
            e.attributes LIKE '%"unresolved"%'
            OR e.attributes LIKE '%"sink"%'
            OR e.attributes LIKE '%"cross_boundary"%'
        )
    """)

    for row in rows:
        entry = dict(row)
        attrs = _load_metadata(entry.get("attributes"))
        if not _is_trust_boundary_call(attrs):
            continue
        source_meta = _load_metadata(entry.pop("source_metadata", None))
        target_meta = _load_metadata(entry.pop("target_metadata", None))
        if not _include_metadata(source_meta, exclude_research):
            continue
        if entry.get("target_label") and not _include_metadata(target_meta, exclude_research):
            continue
        entry["source_context"] = source_meta.get("source_context", "production")
        if entry.get("target_label"):
            entry["target_source_context"] = target_meta.get("source_context", "production")
        yield entry


def _cross_call_rows(conn, exclude_research: bool) -> list[dict]:
    """Return all true trust-boundary call rows for exhaustive cross scans."""
    return list(_iter_cross_call_rows(conn, exclude_research))


def _cross_entry_attrs(entry: dict) -> dict:
    attrs = entry.get("attributes", {})
    if isinstance(attrs, dict):
        return attrs
    return _load_metadata(attrs)


def _compact_cross_entry(entry: dict) -> dict:
    attrs = _cross_entry_attrs(entry)
    if isinstance(entry.get("source"), dict):
        source = entry.get("source") or {}
        target = entry.get("target") or {}
        return {
            "source_label": source.get("label"),
            "source_file": source.get("file"),
            "source_context": source.get("source_context", "production"),
            "target_label": target.get("label"),
            "target_file": target.get("file"),
            "target_source_context": target.get("source_context", "production"),
            "attributes": attrs,
        }
    return {
        "source_label": entry.get("source_label"),
        "source_file": entry.get("source_file"),
        "source_context": entry.get("source_context", "production"),
        "target_label": entry.get("target_label") or entry.get("target"),
        "target_file": entry.get("target_file"),
        "target_source_context": entry.get("target_source_context"),
        "attributes": attrs,
    }


def _bump(counter: dict[str, int], key: str | None):
    if key:
        counter[key] = counter.get(key, 0) + 1


def _top_counter(counter: dict[str, int], limit: int) -> list[dict]:
    return [
        {"name": key, "calls": count}
        for key, count in sorted(counter.items(), key=lambda item: (-item[1], item[0]))[:limit]
    ]


def _category_truncation(results: dict, category_totals: dict[str, int]) -> dict[str, dict]:
    truncated: dict[str, dict] = {}
    for name, total in category_totals.items():
        shown = len(results.get(name, []))
        if total > shown:
            truncated[name] = {
                "shown": shown,
                "total": total,
                "hidden": total - shown,
            }
    return truncated


def _metadata_rows_by_key(
    rows: list,
    keys: list[str],
    exclude_research: bool,
    max_per_key: int = 0,
) -> tuple[dict[str, list[tuple]], dict[str, int]]:
    """Index capped metadata-key rows and full totals while parsing each row once."""
    needles = {key: f'"{key}"' for key in keys}
    indexed: dict[str, list[tuple]] = {key: [] for key in keys}
    totals: dict[str, int] = {key: 0 for key in keys}
    for row in rows:
        raw = row["metadata"] or ""
        matched = [key for key, needle in needles.items() if needle in raw]
        if not matched:
            continue
        meta = _load_metadata(raw)
        if not _include_metadata(meta, exclude_research):
            continue
        for key in matched:
            totals[key] += 1
            if max_per_key == 0 or len(indexed[key]) < max_per_key:
                indexed[key].append((row, meta))
    return indexed, totals


def _section_summary(total: int, shown: int) -> dict:
    return {
        "total": total,
        "shown": shown,
        "truncated": shown < total,
    }


def _cap_items(items: list, max_items: int) -> tuple[list, dict]:
    if max_items > 0 and len(items) > max_items:
        return items[:max_items], {
            "total": len(items),
            "shown": max_items,
            "truncated": True,
        }
    return items, {
        "total": len(items),
        "shown": len(items),
        "truncated": False,
    }


def _cap_mapping(mapping: dict, max_items: int) -> tuple[dict, dict]:
    if max_items > 0 and len(mapping) > max_items:
        items = list(mapping.items())
        return dict(items[:max_items]), {
            "total": len(mapping),
            "shown": max_items,
            "truncated": True,
        }
    return mapping, {
        "total": len(mapping),
        "shown": len(mapping),
        "truncated": False,
    }


def _cap_profile_output(profile: dict, max_output_items: int) -> dict:
    if max_output_items < 0:
        max_output_items = 0
    if not isinstance(profile, dict) or "error" in profile:
        return profile

    list_keys = (
        "top_projects",
        "workspace_clusters",
        "recommended_clusters",
        "recommended_build_targets",
        "risk_first_targets",
        "build_plan",
    )
    dict_keys = (
        "languages",
        "frameworks",
        "top_extensions",
        "project_markers",
        "recommended_by_language",
        "skipped_dirs",
        "research_signal_dirs",
        "skipped_source_reasons",
        "examples",
        "noise_examples",
    )
    sections: dict[str, dict] = {}
    truncated_sections = []

    for key in list_keys:
        value = profile.get(key)
        if isinstance(value, list):
            profile[key], summary = _cap_items(value, max_output_items)
            sections[key] = summary
            if summary["truncated"]:
                truncated_sections.append(key)

    for key in dict_keys:
        value = profile.get(key)
        if isinstance(value, dict):
            profile[key], summary = _cap_mapping(value, max_output_items)
            sections[key] = summary
            if summary["truncated"]:
                truncated_sections.append(key)

    profile["_summary"] = {
        **profile.get("_summary", {}),
        "max_output_items": max_output_items,
        "sections": sections,
        "truncated_sections": truncated_sections,
        "truncated": bool(truncated_sections),
    }
    if truncated_sections:
        profile["_summary"]["_hint"] = (
            "cs_profile output was capped for MCP. Increase max_output_items or set it to 0 for exhaustive profile sections."
        )
    return profile


def _summarize_cross_entries(entries, top: int, max_counter_items: int = 10) -> dict:
    top = max(top, 0)
    max_counter_items = max(max_counter_items, 0)
    total = 0
    attr_counts: dict[str, int] = {}
    context_counts: dict[str, int] = {}
    source_file_counts: dict[str, int] = {}
    target_counts: dict[str, int] = {}
    samples = []

    for entry in entries:
        total += 1
        compact = _compact_cross_entry(entry)
        attrs = compact["attributes"]
        if _is_unresolved_external_call(attrs):
            _bump(attr_counts, "unresolved")
        if _attr_enabled(attrs.get("sink")):
            _bump(attr_counts, "sink")
        if _attr_enabled(attrs.get("cross_boundary")):
            _bump(attr_counts, "cross_boundary")
        _bump(context_counts, compact.get("source_context") or "production")
        _bump(source_file_counts, compact.get("source_file") or "<unknown>")
        _bump(target_counts, compact.get("target_label") or "<unresolved>")
        if len(samples) < top:
            samples.append(compact)

    top_source_files, source_files_summary = _cap_items(
        _top_counter(source_file_counts, len(source_file_counts)),
        max_counter_items,
    )
    top_targets, targets_summary = _cap_items(
        _top_counter(target_counts, len(target_counts)),
        max_counter_items,
    )

    return {
        "total": total,
        "shown": len(samples),
        "truncated": total > len(samples),
        "by_attribute": dict(sorted(attr_counts.items(), key=lambda item: (-item[1], item[0]))),
        "by_source_context": dict(sorted(context_counts.items(), key=lambda item: (-item[1], item[0]))),
        "top_source_files": top_source_files,
        "top_targets": top_targets,
        "counter_summary": {
            "max_counter_items": max_counter_items,
            "top_source_files": source_files_summary,
            "top_targets": targets_summary,
            "truncated": source_files_summary["truncated"] or targets_summary["truncated"],
        },
        "calls": samples,
    }


def _collect_cross_entries(entries, max_results: int) -> tuple[list[dict], dict]:
    max_results = max(max_results, 0)
    total = 0
    calls = []

    for entry in entries:
        total += 1
        if max_results == 0 or len(calls) < max_results:
            calls.append(entry)

    return calls, {
        "total": total,
        "shown": len(calls),
        "truncated": len(calls) < total,
    }


def _append_capped(items: list, item, total: int, limit: int) -> int:
    total += 1
    if limit == 0 or len(items) < limit:
        items.append(item)
    return total


def _append_top(items: list, item, total: int, top: int) -> int:
    total += 1
    if len(items) < top:
        items.append(item)
    return total


def _collect_mapped_items(items, mapper, max_items: int) -> tuple[list, dict]:
    max_items = max(max_items, 0)
    total = 0
    shown = []
    for item in items:
        total += 1
        if max_items == 0 or len(shown) < max_items:
            shown.append(mapper(item))
    return shown, _section_summary(total, len(shown))


def _keep_ranked_result(heap: list, item: dict, score: int, sequence: int, limit: int):
    if limit <= 0:
        return
    ranked = (score, -sequence, item)
    if len(heap) < limit:
        heapq.heappush(heap, ranked)
    elif ranked > heap[0]:
        heapq.heapreplace(heap, ranked)


def _ranked_results(heap: list) -> list[dict]:
    return [
        item
        for _score, _neg_sequence, item in sorted(
            heap,
            key=lambda entry: (-entry[0], -entry[1]),
        )
    ]


def _keep_sorted_result(buffer: list, item: dict, sort_key, limit: int):
    if limit <= 0:
        return
    buffer.append((sort_key, item))
    if len(buffer) > limit:
        buffer.sort(key=lambda entry: entry[0])
        del buffer[limit:]


def _sorted_results(buffer: list) -> list[dict]:
    return [item for _sort_key, item in sorted(buffer, key=lambda entry: entry[0])]


def _load_build_info(conn) -> object | None:
    """Load persisted build metadata without constructing a write-capable GraphDB."""
    row = conn.execute(
        "SELECT value FROM graph_metadata WHERE key = 'build_info'"
    ).fetchone()
    if not row:
        return None
    try:
        return json.loads(row["value"])
    except Exception:
        return row["value"]


def _empty_graph_hint(db_path: str, build_info: object | None) -> str | None:
    """Explain the common empty-graph state to LLM callers."""
    if build_info:
        return None
    return (
        f"Graph '{db_path}' has no build metadata. If counts are zero, run "
        "cs_build(repo_path=..., db=...) first or verify that db points at the intended graph."
    )


def _query_open_error(tool: str, db_path: str, exc: sqlite3.Error) -> str:
    """Return a consistent JSON error for graph query open failures."""
    return json.dumps({
        "error": f"Unable to open graph database '{db_path}': {exc}",
        "tool": tool,
    }, indent=2)


def _query_sqlite_error(
    tool: str,
    exc: sqlite3.OperationalError,
    timeout_seconds: int,
    **fields,
) -> str:
    """Return a consistent JSON error for interrupted/failed graph queries."""
    payload = dict(fields)
    if "interrupted" in str(exc).lower():
        payload.update({
            "error": f"{tool} timed out after {timeout_seconds}s",
            "timed_out": True,
        })
    else:
        payload["error"] = f"SQLite error while running {tool}: {exc}"
    return json.dumps(payload, indent=2)


def _profile_repository_worker(
    out_queue,
    repo_path: str,
    top: int,
    strategy: str,
    include_research: bool,
) -> None:
    """Run workspace profiling out-of-process so it can be hard-killed on timeout."""
    try:
        from core.project_profile import profile_repository

        out_queue.put((
            "ok",
            profile_repository(
                repo_path,
                top=top,
                strategy=strategy,
                include_research=include_research,
            ),
        ))
    except BaseException as exc:
        out_queue.put(("error", f"{type(exc).__name__}: {exc}"))


# ---------------------------------------------------------------------------
# CORE TOOLS
# ---------------------------------------------------------------------------

@mcp.tool()
def cs_profile(
    repo_path: str,
    top: int = 20,
    strategy: str = "balanced",
    include_research: bool = False,
    timeout_seconds: int = DEFAULT_MCP_BUILD_TIMEOUT_SECONDS,
    max_output_items: int = 50,
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
        timeout_seconds: Optional MCP-side wall-clock budget (0 disables)
        max_output_items: Maximum items per large profile section (0 disables)
    """
    if max_output_items < 0:
        max_output_items = 0

    repo = Path(repo_path)
    if not repo.is_dir():
        return json.dumps({
            "error": f"Error: {repo_path} is not a directory",
            "repo_path": repo_path,
        }, indent=2)

    if timeout_seconds and timeout_seconds > 0:
        ctx_name = "fork" if "fork" in mp.get_all_start_methods() else mp.get_start_method()
        ctx = mp.get_context(ctx_name)
        out_queue = ctx.Queue(maxsize=1)
        proc = ctx.Process(
            target=_profile_repository_worker,
            args=(out_queue, repo_path, top, strategy, include_research),
            daemon=True,
        )
        proc.start()
        proc.join(timeout_seconds)
        if proc.is_alive():
            proc.terminate()
            proc.join(2)
            if proc.is_alive():
                proc.kill()
                proc.join(2)
            return json.dumps({
                "error": f"cs_profile timed out after {timeout_seconds}s",
                "repo_path": repo_path,
                "strategy": strategy,
                "include_research": include_research,
                "timed_out": True,
                "_hint": "Profile a narrower repo_path or increase timeout_seconds.",
            }, indent=2)
        try:
            status, payload = out_queue.get_nowait()
        except queue_mod.Empty:
            status, payload = ("error", f"profile worker exited with code {proc.exitcode} and returned no result")
        if status == "ok":
            return json.dumps(_cap_profile_output(payload, max_output_items), indent=2)
        return json.dumps({
            "error": f"cs_profile failed: {payload}",
            "repo_path": repo_path,
            "strategy": strategy,
            "include_research": include_research,
        }, indent=2)

    from core.project_profile import profile_repository

    return json.dumps(
        _cap_profile_output(
            profile_repository(repo_path, top=top, strategy=strategy, include_research=include_research),
            max_output_items,
        ),
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
        timeout_seconds: Optional MCP-side build budget. Set >0 to write a partial graph on timeout; 0 disables.
    """
    from core.indexer import Indexer

    repo = Path(repo_path)
    if not repo.is_dir():
        return json.dumps({
            "error": f"Error: {repo_path} is not a directory",
            "repo_path": repo_path,
            "tool": "cs_build",
        }, indent=2)

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
            "1. cs_profile(repo_path) — optional but recommended for large/mixed workspaces; output sections are capped by max_output_items.",
            "2. cs_build(repo_path) — REQUIRED before graph queries. Builds the knowledge graph; timeout_seconds is opt-in.",
            "3. cs_summary() — Cheap graph health/stats check before broad scanning.",
            "4. cs_audit() — Full security report: stats, hotspots, reentrancy, taint, sinks, events, deadcode, access gaps.",
            "5. Drill into specific areas with specialized tools below.",
        ],
        "core_tools": {
            "cs_summary": "Fast graph health and stats check. Use this before broad scans to catch empty or wrong db paths.",
            "cs_audit": "Top-N security overview with attack surface, hotspots, taint paths, sinks, dead code, and access gaps. Check _summary for truncated sections.",
            "cs_build": "Build the graph. MCP does not self-timeout by default; pass timeout_seconds for an intentional partial build.",
            "cs_profile": "Profile a repo/workspace before building. Large output sections are capped by max_output_items; use max_output_items=0 for exhaustive profile sections.",
        },
        "scanner_tools": {
            "cs_hotspots": "Composite risk scorer — all functions ranked with detailed reasons (score >= 8 = critical). Covers: access control, validation, overflow, proxy, unchecked calls.",
            "cs_defi": "DeFi patterns: timestamp, oracle, ERC20, signature, slippage, downcasts, flash loans, callbacks, Anchor, Move/Clarity/Vyper transfer sinks. Use category= to filter; category output is capped by max_per_category.",
            "cs_unsafe": "Rust/Go/Java/Python/TypeScript/DSL issues: unsafe blocks, panics, races, type assertions, SQL injection, command execution, deserialization, private key handling, dead params. Use category= to filter; category output is capped by max_per_category.",
        },
        "exploration_tools": {
            "cs_lookup": "Function profile: callers, callees, state reads/writes, guards, edges. Common names are capped by max_matches; candidates by max_candidates; relation lists by max_relation_items.",
            "cs_paths": "Find call paths between two functions. Ambiguous endpoints are capped by max_endpoint_matches, candidates by max_endpoint_candidates, and paths by max_paths.",
            "cs_trace": "Trace readers/writers of a state variable. Ambiguous names are capped by max_matches, candidates by max_candidates, and show_callers lists by max_callers_per_accessor.",
            "cs_cross": "Cross-contract/module boundary calls. Raw calls are capped by max_results; ambiguous from_func candidates by max_start_candidates.",
            "cs_cross_summary": "Bounded trust-boundary overview for large graphs; sample calls are capped by top and counters by max_counter_items.",
            "cs_sinks": "Dangerous sink inventory with bounded caller reachability. Sinks are capped by max_results and callers per sink by max_callers_per_sink.",
            "cs_state": "State machine transitions and lifecycle analysis. Broad output is capped by max_entities, max_transitions_per_entity, and max_warnings.",
        },
        "_tip": "All tools accept db='path/to/graph.db'. Default is graph.db in current directory.",
    }, indent=2)


@mcp.tool()
def cs_summary(
    db: str = "",
    attack_surface: bool = False,
    top: int = 20,
    exclude_research: bool = False,
    timeout_seconds: int = 0,
) -> str:
    """Summarize graph health and high-level structure.

    Cheap first query after cs_build. This is intentionally smaller than
    cs_audit so LLM agents can validate the DB path, build metadata, source
    scope, and graph size before spending context on detailed findings.

    Args:
        db: Database path (default: graph.db)
        attack_surface: Include top external/public functions by reachable state writes
        top: Maximum attack-surface rows to return
        exclude_research: Exclude nodes originating from research-mode files
        timeout_seconds: Optional SQLite query budget before returning an error (0 disables)
    """
    if top < 0:
        top = 0

    db_path = _resolve_db(db)
    try:
        conn = _open_query_connection(db_path, timeout_seconds=timeout_seconds)
    except sqlite3.Error as exc:
        return _query_open_error("cs_summary", db_path, exc)

    try:
        node_rows = conn.execute(
            "SELECT id, label, type, visibility, file, signature, metadata FROM nodes"
        ).fetchall()
        allowed_ids: set[str] = set()
        node_by_id: dict[str, dict] = {}
        type_counts: dict[str, int] = {}
        source_context_counts: dict[str, int] = {}
        files: set[str] = set()
        entry_points = 0

        for row in node_rows:
            meta = _load_metadata(row["metadata"])
            if not _include_metadata(meta, exclude_research):
                continue
            row_dict = dict(row)
            allowed_ids.add(row["id"])
            node_by_id[row["id"]] = row_dict
            files.add(row["file"])
            type_counts[row["type"]] = type_counts.get(row["type"], 0) + 1
            source_context = meta.get("source_context", "production")
            source_context_counts[source_context] = source_context_counts.get(source_context, 0) + 1
            if row["type"] == "function" and row["visibility"] in ("public", "external"):
                entry_points += 1

        edge_rows = conn.execute(
            "SELECT source, target, relation FROM edges"
        ).fetchall()
        rel_counts: dict[str, int] = {}
        filtered_edges = []
        for row in edge_rows:
            if row["source"] not in allowed_ids or row["target"] not in allowed_ids:
                continue
            filtered_edges.append(row)
            rel_counts[row["relation"]] = rel_counts.get(row["relation"], 0) + 1

        transitions = 0
        for row in conn.execute("""
            SELECT st.function_id, n.metadata
            FROM state_transitions st
            LEFT JOIN nodes n ON st.function_id = n.id
        """).fetchall():
            meta = _load_metadata(row["metadata"])
            if _include_metadata(meta, exclude_research):
                transitions += 1

        build_info = _load_build_info(conn)
        data = {
            "database": db_path,
            "query_scope": "production_only" if exclude_research else "all_sources",
            "nodes": len(allowed_ids),
            "edges": len(filtered_edges),
            "transitions": transitions,
            "files": len(files),
            "functions": type_counts.get("function", 0),
            "state_vars": type_counts.get("state_var", 0),
            "entry_points": entry_points,
            "node_types": dict(sorted(type_counts.items(), key=lambda item: (-item[1], item[0]))),
            "edge_relations": dict(sorted(rel_counts.items(), key=lambda item: (-item[1], item[0]))),
            "source_context_summary": dict(sorted(source_context_counts.items(), key=lambda item: (-item[1], item[0]))),
            "build_info": build_info,
        }

        hint = _empty_graph_hint(db_path, build_info)
        if hint and data["nodes"] == 0:
            data["_warning"] = hint
            data["_next_steps"] = [
                "Run cs_build(repo_path=..., db=...) to populate this graph.",
                "If you already built a graph, verify that the db argument points at the populated graph.db.",
            ]

        if attack_surface and allowed_ids:
            adjacency: dict[str, list[str]] = {}
            write_map: dict[str, int] = {}
            for row in filtered_edges:
                if row["relation"] in TRAVERSAL_RELATIONS:
                    adjacency.setdefault(row["source"], []).append(row["target"])
                if row["relation"] == "writes_state":
                    write_map[row["source"]] = write_map.get(row["source"], 0) + 1

            def _reachable(start_id: str) -> set[str]:
                reachable = {start_id}
                queue = [start_id]
                pos = 0
                while pos < len(queue):
                    current = queue[pos]
                    pos += 1
                    for neighbor in adjacency.get(current, []):
                        if neighbor not in reachable:
                            reachable.add(neighbor)
                            queue.append(neighbor)
                return reachable

            surface = []
            surface_total = 0
            for row in node_by_id.values():
                if row["type"] != "function" or row["visibility"] not in ("public", "external"):
                    continue
                meta = _load_metadata(row["metadata"])
                reachable = _reachable(row["id"])
                write_count = sum(write_map.get(rid, 0) for rid in reachable)
                surface_total += 1
                item = {
                    "id": row["id"],
                    "label": row["label"],
                    "file": row["file"],
                    "signature": row["signature"],
                    "reachable_count": len(reachable),
                    "state_writes": write_count,
                    "source_context": meta.get("source_context", "production"),
                }
                _keep_sorted_result(
                    surface,
                    item,
                    (-write_count, row["file"] or "", row["label"] or "", row["id"]),
                    top,
                )
            data["attack_surface"] = _sorted_results(surface)
            attack_surface_summary = _section_summary(surface_total, len(data["attack_surface"]))
            attack_surface_summary["top"] = top
            data["_summary"] = {
                "attack_surface": attack_surface_summary,
                "truncated": attack_surface_summary["truncated"],
            }
            if attack_surface_summary["truncated"]:
                data["_warning"] = (
                    "cs_summary attack_surface output was capped. Increase top for more entries."
                )

        return json.dumps(data, indent=2)
    except sqlite3.OperationalError as exc:
        return _query_sqlite_error(
            "cs_summary",
            exc,
            timeout_seconds,
            top=top,
            query_scope="production_only" if exclude_research else "all_sources",
        )
    finally:
        conn.close()


import os as _os

_C_EXTENSIONS = {".c", ".h", ".cpp", ".cc", ".cxx", ".hpp", ".hxx", ".c++"}

def _is_c_file(filepath: str) -> bool:
    """Check if a file path is a C/C++ file."""
    _, ext = _os.path.splitext(filepath)
    return ext in _C_EXTENSIONS


def _is_research_meta(meta: dict) -> bool:
    """Return true for non-production source contexts indexed from research files."""
    return meta.get("source_kind") == "research" or meta.get("source_context") not in (None, "", "production")


def _has_access_control(meta: dict, guard_count: int) -> bool:
    """Treat modifiers, graph guard edges, and inferred inline role checks as access control."""
    return bool(guard_count or meta.get("modifiers") or meta.get("role_guards") or meta.get("access_controls"))


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
        if is_entry and writes > 0 and not _has_access_control(meta, guard_count):
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
    if is_entry and writes > 0 and not _has_access_control(meta, guard_count) and not meta.get("view") and not meta.get("pure"):
        score += 2
        reasons.append("no_access_control")

    return (score, reasons)


@mcp.tool()
def cs_audit(
    db: str = "",
    top: int = 15,
    exclude_research: bool = False,
    timeout_seconds: int = 0,
) -> str:
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
        timeout_seconds: Optional SQLite query budget before returning an error (0 disables)
    """
    if top < 0:
        top = 0

    db_path = _resolve_db(db)
    try:
        conn = _open_query_connection(db_path, timeout_seconds=timeout_seconds)
    except sqlite3.Error as exc:
        return _query_open_error("cs_audit", db_path, exc)

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
        build_info = _load_build_info(conn)
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
            meta = _load_metadata(row["metadata"])
            if exclude_research and _is_research_meta(meta):
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
        guard_labels_by_target: dict[str, list[str]] = {}
        for r in conn.execute(
            """
            SELECT e.target, n.label
            FROM edges e LEFT JOIN nodes n ON e.source = n.id
            WHERE e.relation='guards'
            ORDER BY e.target, n.label
            """
        ).fetchall():
            guard_set.add(r["target"])
            if r["label"]:
                guard_labels_by_target.setdefault(r["target"], []).append(r["label"])

        ext_call_map = _external_call_counts(conn, include_cpi=True)

        adj: dict[str, list[str]] = {}
        call_rev_adj: dict[str, list[str]] = {}
        called_targets: set[str] = set()
        for r in conn.execute(
            "SELECT source, target, relation FROM edges WHERE relation IN (?, ?, ?)",
            TRAVERSAL_RELATIONS,
        ).fetchall():
            adj.setdefault(r["source"], []).append(r["target"])
            if r["relation"] == "calls":
                call_rev_adj.setdefault(r["target"], []).append(r["source"])
                called_targets.add(r["target"])

        reachable_cache: dict[str, set[str]] = {}

        def _reachable(start_id: str) -> set[str]:
            cached = reachable_cache.get(start_id)
            if cached is not None:
                return cached
            reachable = {start_id}
            queue = [start_id]
            pos = 0
            while pos < len(queue):
                current = queue[pos]
                pos += 1
                for neighbor in adj.get(current, []):
                    if neighbor not in reachable:
                        reachable.add(neighbor)
                        queue.append(neighbor)
            reachable_cache[start_id] = reachable
            return reachable

        # --- 4. Attack surface (formerly in cs_summary) ---
        attack_surface_heap: list[tuple[int, int, dict]] = []
        attack_surface_total = 0
        attack_surface_sequence = 0
        for row in all_funcs:
            if row["visibility"] not in ("public", "external"):
                continue
            if row["id"] not in func_meta_cache:
                continue
            reachable = _reachable(row["id"])
            write_count = sum(write_map.get(rid, 0) for rid in reachable)
            attack_surface_total += 1
            _keep_ranked_result(attack_surface_heap, {
                "id": row["id"],
                "label": row["label"],
                "file": row["file"],
                "signature": row["signature"],
                "reachable_count": len(reachable),
                "state_writes": write_count,
                "metadata": row["metadata"],
            }, write_count, attack_surface_sequence, top)
            attack_surface_sequence += 1
        if attack_surface_total:
            report["attack_surface"] = _ranked_results(attack_surface_heap)

        # --- 5. Top hotspots (inline scoring) ---
        hotspot_heap: list[tuple[int, int, dict]] = []
        hotspot_total = 0
        hotspot_critical = 0
        hotspot_high = 0
        hotspot_sequence = 0
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
                hotspot_total += 1
                if score >= 8:
                    hotspot_critical += 1
                else:
                    hotspot_high += 1
                _keep_ranked_result(hotspot_heap, {
                    "function": row["label"],
                    "file": row["file"],
                    "line": row["line_start"],
                    "source_context": meta.get("source_context", "production"),
                    "score": score,
                    "reasons": reasons,
                }, score, hotspot_sequence, top)
                hotspot_sequence += 1

        report["critical_hotspots"] = _ranked_results(hotspot_heap)
        report["hotspot_summary"] = {
            "total_scored": hotspot_total,
            "critical_8plus": hotspot_critical,
            "high_5to7": hotspot_high,
        }

        # --- 6. Reentrancy findings (detailed, formerly cs_reentrancy) ---
        reent = []
        reent_total = 0
        for row in all_funcs:
            meta = func_meta_cache.get(row["id"], {})
            if meta.get("reentrancy_risk"):
                reent_total = _append_top(reent, {
                    "function": row["label"],
                    "file": row["file"],
                    "line": row["line_start"],
                    "source_context": meta.get("source_context", "production"),
                    "type": "single_function",
                    "details": meta.get("reentrancy_details", ""),
                    "modifiers": guard_labels_by_target.get(row["id"], []),
                }, reent_total, top)
            for cr in meta.get("cross_reentrancy", []):
                reent_total = _append_top(reent, {
                    "function": row["label"],
                    "file": row["file"],
                    "line": row["line_start"],
                    "source_context": meta.get("source_context", "production"),
                    "type": "cross_function",
                    "via": cr["via"],
                    "stale_vars": cr["stale_vars"],
                }, reent_total, top)
        if reent_total:
            report["reentrancy"] = reent

        # --- 7. Taint paths (entry→sink) ---
        sink_ids = set()
        sink_info: dict[str, dict] = {}
        for s in conn.execute(
            "SELECT id, label, metadata FROM nodes WHERE metadata LIKE '%\"is_sink\"%'"
        ).fetchall():
            smeta = _load_metadata(s["metadata"])
            if smeta.get("is_sink"):
                sink_ids.add(s["id"])
                sink_info[s["id"]] = {
                    "label": s["label"],
                    "type": smeta.get("sink_type", "unknown"),
                }

        taint_results = []
        taint_total = 0
        taint_high_risk = 0
        taint_sequence = 0
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
                reachable = _reachable(row["id"])
                reached = reachable & sink_ids
                if reached:
                    risk = "HIGH" if not is_guarded else "MEDIUM"
                    taint_total += 1
                    if risk == "HIGH":
                        taint_high_risk += 1
                    if top > 0:
                        sink_details = []
                        for sid in sorted(reached)[:5]:
                            si = sink_info.get(sid, {})
                            sink_details.append({"sink": si.get("label", "?"), "type": si.get("type", "?")})
                        _keep_sorted_result(
                            taint_results,
                            {
                                "entry": row["label"],
                                "file": row["file"],
                                "source_context": meta.get("source_context", "production"),
                                "visibility": vis,
                                "guarded": is_guarded,
                                "reachable_sinks": len(reached),
                                "sinks": sink_details,
                                "risk": risk,
                            },
                            (0 if risk == "HIGH" else 1, -len(reached), taint_sequence),
                            top,
                        )
                    taint_sequence += 1
        if taint_total:
            report["taint_paths"] = _sorted_results(taint_results)
            report["taint_summary"] = {
                "total": taint_total,
                "high_risk": taint_high_risk,
            }

        # --- 8. Sink reachability summary (formerly cs_sinks) ---
        if sink_ids:
            sink_type_counts: dict[str, int] = {}
            for sid, si in sink_info.items():
                st = si.get("type", "unknown")
                sink_type_counts[st] = sink_type_counts.get(st, 0) + 1
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
                    for caller in call_rev_adj.get(curr, []):
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
        access_gaps_total = 0
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
            access_gaps_total = _append_top(access_gaps, {
                "function": row["label"],
                "file": row["file"],
                "source_context": meta.get("source_context", "production"),
                "visibility": vis,
                "state_writes": wvars,
            }, access_gaps_total, top)
        if access_gaps_total:
            report["access_control_gaps"] = access_gaps
            report["access_gaps_total"] = access_gaps_total

        # --- 10. Silent state changes (formerly cs_events) ---
        emitters = set()
        for r in conn.execute(
            "SELECT DISTINCT source FROM edges WHERE relation='emits_event'"
        ).fetchall():
            emitters.add(r["source"])

        silent = []
        silent_total = 0
        silent_sequence = 0
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
                silent_total += 1
                _keep_sorted_result(silent, {
                    "function": func["label"],
                    "file": func["file"],
                    "source_context": meta.get("source_context", "production"),
                    "state_writes": wcount,
                }, (-wcount, silent_sequence), top)
                silent_sequence += 1
        if silent_total:
            report["silent_state_changes"] = _sorted_results(silent)
            report["silent_total"] = silent_total

        # --- 11. Dead code (formerly cs_deadcode) ---
        library_ids = set()
        for r in conn.execute(
            "SELECT id FROM nodes WHERE type = 'library'"
        ).fetchall():
            library_ids.add(r["id"])

        dead_internal = []
        dead_internal_total = 0
        orphan_writers = []
        orphan_writers_total = 0
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
                dead_internal_total = _append_top(dead_internal, {
                    "function": func["label"],
                    "file": func["file"],
                    "source_context": meta.get("source_context", "production"),
                    "visibility": vis,
                }, dead_internal_total, top)
            elif vis in ("external", "public"):
                wt = write_targets.get(fid, [])
                if wt and not meta.get("view") and not meta.get("pure"):
                    wvars = [t.split("::")[-1].split(".")[-1] for t in wt[:5]]
                    orphan_writers_total = _append_top(orphan_writers, {
                        "function": func["label"],
                        "file": func["file"],
                        "source_context": meta.get("source_context", "production"),
                        "visibility": vis,
                        "state_writes": wvars,
                    }, orphan_writers_total, top)

        report["dead_code"] = {
            "dead_internal": dead_internal,
            "dead_internal_total": dead_internal_total,
            "direct_entry_points": orphan_writers,
            "direct_entry_points_total": orphan_writers_total,
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

        sections = {
            "attack_surface": _section_summary(attack_surface_total, len(report.get("attack_surface", []))),
            "critical_hotspots": _section_summary(hotspot_total, len(report.get("critical_hotspots", []))),
            "reentrancy": _section_summary(reent_total, len(report.get("reentrancy", []))),
            "taint_paths": _section_summary(taint_total, len(report.get("taint_paths", []))),
            "access_control_gaps": _section_summary(access_gaps_total, len(report.get("access_control_gaps", []))),
            "silent_state_changes": _section_summary(silent_total, len(report.get("silent_state_changes", []))),
            "dead_code.dead_internal": _section_summary(
                dead_internal_total,
                len(report["dead_code"]["dead_internal"]),
            ),
            "dead_code.direct_entry_points": _section_summary(
                orphan_writers_total,
                len(report["dead_code"]["direct_entry_points"]),
            ),
        }
        truncated_sections = [
            name for name, info in sections.items()
            if info["truncated"]
        ]
        report["_summary"] = {
            "top": top,
            "query_scope": report["query_scope"],
            "sections": sections,
            "truncated_sections": truncated_sections,
            "truncated": bool(truncated_sections),
            "_hint": (
                "cs_audit is a top-N overview. Use cs_hotspots, cs_defi, cs_unsafe, "
                "cs_paths, cs_trace, cs_cross_summary, or cs_state to drill into truncated sections."
            ) if truncated_sections else "",
        }

        return json.dumps(report, indent=2)
    except sqlite3.OperationalError as exc:
        return _query_sqlite_error(
            "cs_audit",
            exc,
            timeout_seconds,
            top=top,
            query_scope="production_only" if exclude_research else "all_sources",
        )
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# SCANNER TOOLS (detailed drill-down with filtering)
# ---------------------------------------------------------------------------

@mcp.tool()
def cs_hotspots(
    db: str = "",
    top: int = 30,
    exclude_research: bool = False,
    timeout_seconds: int = 0,
) -> str:
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
        timeout_seconds: Optional SQLite query budget before returning an error (0 disables)
    """
    if top < 0:
        top = 0

    db_path = _resolve_db(db)
    try:
        conn = _open_query_connection(db_path, timeout_seconds=timeout_seconds)
    except sqlite3.Error as exc:
        return _query_open_error("cs_hotspots", db_path, exc)

    try:
        # Get all functions
        rows = conn.execute("""
            SELECT id, label, file, visibility, signature, line_start, metadata
            FROM nodes WHERE type = 'function'
        """)

        write_map = {
            r["source"]: r["cnt"]
            for r in conn.execute("""
                SELECT source, COUNT(*) as cnt
                FROM edges
                WHERE relation = 'writes_state'
                GROUP BY source
            """).fetchall()
        }
        ext_call_map = _external_call_counts(conn)
        guard_map = {
            r["target"]: r["cnt"]
            for r in conn.execute("""
                SELECT target, COUNT(*) as cnt
                FROM edges
                WHERE relation = 'guards'
                GROUP BY target
            """).fetchall()
        }

        total_scored = 0
        critical = 0
        high = 0
        medium = 0
        top_heap: list[tuple[int, int, dict]] = []
        sequence = 0
        for r in rows:
            if r["label"] in ("constructor", "fallback", "receive"):
                continue
            meta = _load_metadata(r["metadata"])
            if exclude_research and _is_research_meta(meta):
                continue

            writes = write_map.get(r["id"], 0)
            ext_calls = ext_call_map.get(r["id"], 0)
            guards = 0
            vis = r["visibility"]
            if vis in ("external", "public") and writes > 0:
                guards = guard_map.get(r["id"], 0)

            score, reasons = _score_function(r, meta, writes, ext_calls, guards)

            if score >= 3:
                total_scored += 1
                if score >= 8:
                    critical += 1
                elif score >= 5:
                    high += 1
                else:
                    medium += 1

                _keep_ranked_result(top_heap, {
                    "function": r["label"],
                    "file": r["file"],
                    "line": r["line_start"],
                    "visibility": r["visibility"],
                    "source_context": meta.get("source_context", "production"),
                    "score": score,
                    "reasons": reasons,
                }, score, sequence, top)
                sequence += 1

        result = _ranked_results(top_heap)

        return json.dumps({
            "hotspots": result,
            "_summary": {
                "total_scored": total_scored,
                "critical_8plus": critical,
                "high_5to7": high,
                "medium_3to4": medium,
                "top_shown": len(result),
                "query_scope": "production_only" if exclude_research else "all_sources",
            }
        }, indent=2)
    except sqlite3.OperationalError as exc:
        return _query_sqlite_error(
            "cs_hotspots",
            exc,
            timeout_seconds,
            top=top,
            query_scope="production_only" if exclude_research else "all_sources",
        )
    finally:
        conn.close()


@mcp.tool()
def cs_defi(
    db: str = "",
    category: str = "",
    exclude_research: bool = False,
    timeout_seconds: int = 0,
    max_per_category: int = 50,
) -> str:
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
        timeout_seconds: Optional SQLite query budget before returning an error (0 disables)
        max_per_category: Maximum findings to return per category (0 disables)
    """
    if max_per_category < 0:
        max_per_category = 0

    db_path = _resolve_db(db)
    try:
        conn = _open_query_connection(db_path, timeout_seconds=timeout_seconds)
    except sqlite3.Error as exc:
        return _query_open_error("cs_defi", db_path, exc)

    try:
        cat = category.lower() if category else "all"
        results: dict = {}
        function_rows = conn.execute(
            "SELECT id, label, file, line_start, visibility, signature, metadata "
            "FROM nodes WHERE type = 'function' ORDER BY file, line_start, id"
        ).fetchall()
        metadata_rows, metadata_totals = _metadata_rows_by_key(function_rows, [
            "timestamp_dependence",
            "unchecked_erc20",
            "oracle_risk",
            "signature_risk",
            "precision_risk",
            "dos_risk",
            "frontrun_risk",
            "unsafe_downcast",
            "flash_loan_risk",
            "slippage_risk",
            "erc_callback_risk",
            "anchor_risks",
            "cpi_reentrancy_risk",
            "transfer_sinks",
            "cross_contract_calls",
        ], exclude_research, max_per_category)
        category_totals: dict[str, int] = {}

        def _function_rows_with(metadata_key: str) -> list[tuple]:
            return metadata_rows.get(metadata_key, [])

        def _set_category(result_key: str, metadata_key: str, values: list):
            total = metadata_totals.get(metadata_key, 0)
            if total:
                results[result_key] = values
                category_totals[result_key] = total

        def _ctx(meta: dict) -> str:
            return meta.get("source_context", "production")

        # --- Timestamp dependence ---
        if cat in ("all", "timestamp"):
            rows = _function_rows_with("timestamp_dependence")
            ts_fns = []
            for r, meta in rows:
                ts_fns.append({
                    "function": r["label"], "file": r["file"],
                    "line": r["line_start"], "risks": meta.get("timestamp_dependence", []),
                    "source_context": _ctx(meta),
                })
            _set_category("timestamp_dependence", "timestamp_dependence", ts_fns)

        # --- Unchecked ERC20 returns ---
        if cat in ("all", "erc20"):
            rows = _function_rows_with("unchecked_erc20")
            erc_fns = []
            for r, meta in rows:
                erc_fns.append({
                    "function": r["label"], "file": r["file"],
                    "line": r["line_start"], "unchecked_calls": meta.get("unchecked_erc20", []),
                    "source_context": _ctx(meta),
                })
            _set_category("unchecked_erc20", "unchecked_erc20", erc_fns)

        # --- Oracle / price manipulation ---
        if cat in ("all", "oracle"):
            rows = _function_rows_with("oracle_risk")
            oracle_fns = []
            for r, meta in rows:
                oracle_fns.append({
                    "function": r["label"], "file": r["file"],
                    "line": r["line_start"], "risks": meta.get("oracle_risk", []),
                    "source_context": _ctx(meta),
                })
            _set_category("oracle_manipulation", "oracle_risk", oracle_fns)

        # --- Signature replay ---
        if cat in ("all", "signature"):
            rows = _function_rows_with("signature_risk")
            sig_fns = []
            for r, meta in rows:
                sig_fns.append({
                    "function": r["label"], "file": r["file"],
                    "line": r["line_start"], "risks": meta.get("signature_risk", []),
                    "source_context": _ctx(meta),
                })
            _set_category("signature_replay", "signature_risk", sig_fns)

        # --- Precision loss ---
        if cat in ("all", "precision"):
            rows = _function_rows_with("precision_risk")
            prec_fns = []
            for r, meta in rows:
                prec_fns.append({
                    "function": r["label"], "file": r["file"],
                    "line": r["line_start"], "risks": meta.get("precision_risk", []),
                    "source_context": _ctx(meta),
                })
            _set_category("precision_loss", "precision_risk", prec_fns)

        # --- DoS risks ---
        if cat in ("all", "dos"):
            rows = _function_rows_with("dos_risk")
            dos_fns = []
            for r, meta in rows:
                dos_fns.append({
                    "function": r["label"], "file": r["file"],
                    "line": r["line_start"], "risks": meta.get("dos_risk", []),
                    "source_context": _ctx(meta),
                })
            _set_category("dos_risks", "dos_risk", dos_fns)

        # --- Frontrunning surface ---
        if cat in ("all", "frontrun"):
            rows = _function_rows_with("frontrun_risk")
            fr_fns = []
            for r, meta in rows:
                fr_fns.append({
                    "function": r["label"], "file": r["file"],
                    "line": r["line_start"], "risks": meta.get("frontrun_risk", []),
                    "source_context": _ctx(meta),
                })
            _set_category("frontrunning", "frontrun_risk", fr_fns)

        # --- Unsafe downcasts ---
        if cat in ("all", "downcast"):
            rows = _function_rows_with("unsafe_downcast")
            dc_fns = []
            for r, meta in rows:
                dc_fns.append({
                    "function": r["label"], "file": r["file"],
                    "line": r["line_start"], "casts": meta.get("unsafe_downcast", []),
                    "source_context": _ctx(meta),
                })
            _set_category("unsafe_downcasts", "unsafe_downcast", dc_fns)

        # --- Flash loan callbacks ---
        if cat in ("all", "flashloan"):
            rows = _function_rows_with("flash_loan_risk")
            fl_fns = []
            for r, meta in rows:
                fl_fns.append({
                    "function": r["label"], "file": r["file"],
                    "line": r["line_start"], "risks": meta.get("flash_loan_risk", []),
                    "source_context": _ctx(meta),
                })
            _set_category("flash_loan_risks", "flash_loan_risk", fl_fns)

        # --- Slippage / deadline missing ---
        if cat in ("all", "slippage"):
            rows = _function_rows_with("slippage_risk")
            sl_fns = []
            for r, meta in rows:
                sl_fns.append({
                    "function": r["label"], "file": r["file"],
                    "line": r["line_start"], "risks": meta.get("slippage_risk", []),
                    "source_context": _ctx(meta),
                })
            _set_category("slippage_missing", "slippage_risk", sl_fns)

        # --- ERC callback reentrancy ---
        if cat in ("all", "callback"):
            rows = _function_rows_with("erc_callback_risk")
            cb_fns = []
            for r, meta in rows:
                cb_fns.append({
                    "function": r["label"], "file": r["file"],
                    "line": r["line_start"], "risks": meta.get("erc_callback_risk", []),
                    "source_context": _ctx(meta),
                })
            _set_category("erc_callback_reentrancy", "erc_callback_risk", cb_fns)

        # --- Anchor-specific risks ---
        if cat in ("all", "anchor"):
            rows = _function_rows_with("anchor_risks")
            anch_fns = []
            for r, meta in rows:
                anch_fns.append({
                    "function": r["label"], "file": r["file"],
                    "line": r["line_start"], "risks": meta.get("anchor_risks", []),
                    "source_context": _ctx(meta),
                })
            _set_category("anchor_risks", "anchor_risks", anch_fns)

        # --- CPI reentrancy (Anchor) ---
        if cat in ("all", "cpi_reentrancy"):
            rows = _function_rows_with("cpi_reentrancy_risk")
            cpi_fns = []
            for r, meta in rows:
                cpi_fns.append({
                    "function": r["label"], "file": r["file"],
                    "line": r["line_start"],
                    "source_context": _ctx(meta),
                })
            _set_category("cpi_reentrancy", "cpi_reentrancy_risk", cpi_fns)

        # --- Cross-language transfer/cross-contract sinks ---
        if cat in ("all", "transfer"):
            rows = _function_rows_with("transfer_sinks")
            transfer_fns = []
            for r, meta in rows:
                transfer_fns.append({
                    "function": r["label"], "file": r["file"],
                    "line": r["line_start"], "sinks": meta.get("transfer_sinks", []),
                    "language": meta.get("language", ""),
                    "source_context": _ctx(meta),
                })
            _set_category("transfer_sinks", "transfer_sinks", transfer_fns)

        if cat in ("all", "crosscontract"):
            rows = _function_rows_with("cross_contract_calls")
            cc_fns = []
            for r, meta in rows:
                cc_fns.append({
                    "function": r["label"], "file": r["file"],
                    "line": r["line_start"], "calls": meta.get("cross_contract_calls", []),
                    "language": meta.get("language", ""),
                    "source_context": _ctx(meta),
                })
            _set_category("cross_contract_calls", "cross_contract_calls", cc_fns)

        # Summary
        total = sum(category_totals.values())
        truncated_categories = _category_truncation(results, category_totals)
        shown_total = sum(len(v) for v in results.values() if isinstance(v, list))
        results["_summary"] = {
            "total_findings": total,
            "shown_findings": shown_total,
            "categories": list(results.keys()),
            "category_totals": category_totals,
            "truncated_categories": truncated_categories,
            "truncated": bool(truncated_categories),
            "max_per_category": max_per_category,
            "query_scope": "production_only" if exclude_research else "all_sources",
        }

        return json.dumps(results, indent=2)
    except sqlite3.OperationalError as exc:
        return _query_sqlite_error(
            "cs_defi",
            exc,
            timeout_seconds,
            category=cat,
            query_scope="production_only" if exclude_research else "all_sources",
        )
    finally:
        conn.close()


@mcp.tool()
def cs_unsafe(
    db: str = "",
    category: str = "",
    exclude_research: bool = False,
    timeout_seconds: int = 0,
    max_per_category: int = 50,
) -> str:
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
        timeout_seconds: Optional SQLite query budget before returning an error (0 disables)
        max_per_category: Maximum findings to return per category (0 disables)
    """
    if max_per_category < 0:
        max_per_category = 0

    db_path = _resolve_db(db)
    try:
        conn = _open_query_connection(db_path, timeout_seconds=timeout_seconds)
    except sqlite3.Error as exc:
        return _query_open_error("cs_unsafe", db_path, exc)

    try:
        cat = category.lower() if category else "all"
        results: dict = {}
        function_rows = conn.execute(
            "SELECT id, label, file, line_start, visibility, signature, metadata "
            "FROM nodes WHERE type = 'function' ORDER BY file, line_start, id"
        ).fetchall()
        metadata_rows, metadata_totals = _metadata_rows_by_key(function_rows, [
            "unsafe_blocks",
            "panic_paths",
            "potential_race",
            "no_input_validation",
            "wrapping_arithmetic",
            "unsafe_type_assertions",
            "sql_injection_risk",
            "deserialization_sinks",
            "reflection_usage",
            "injection_sinks",
            "weak_crypto",
            "command_injection_risk",
            "private_key_material",
            "swallowed_exceptions",
            "resource_leaks",
            "unsafe_downcast",
            "dead_params",
        ], exclude_research, max_per_category)
        category_totals: dict[str, int] = {}

        def _function_rows_with(metadata_key: str) -> list[tuple]:
            return metadata_rows.get(metadata_key, [])

        def _set_category(result_key: str, metadata_key: str, values: list):
            total = metadata_totals.get(metadata_key, 0)
            if total:
                results[result_key] = values
                category_totals[result_key] = total

        def _include(meta: dict) -> bool:
            return not (exclude_research and _is_research_meta(meta))

        def _ctx(meta: dict) -> str:
            return meta.get("source_context", "production")

        # --- Unsafe blocks (Rust) ---
        if cat in ("all", "unsafe"):
            rows = _function_rows_with("unsafe_blocks")
            unsafe_fns = []
            for r, meta in rows:
                unsafe_fns.append({
                    "function": r["label"], "file": r["file"],
                    "unsafe_blocks": meta.get("unsafe_blocks", 0),
                    "unsafe_operations": meta.get("unsafe_operations", []),
                    "raw_pointers": meta.get("raw_pointers", False),
                    "source_context": _ctx(meta),
                })
            _set_category("unsafe_blocks", "unsafe_blocks", unsafe_fns)

        # --- Panic/unwrap sinks (Rust) ---
        if cat in ("all", "panic"):
            rows = _function_rows_with("panic_paths")
            panic_fns = []
            for r, meta in rows:
                panic_fns.append({
                    "function": r["label"], "file": r["file"],
                    "panic_calls": meta.get("panic_paths", []),
                    "source_context": _ctx(meta),
                })
            _set_category("panic_sinks", "panic_paths", panic_fns)

        # --- Race conditions (Go) ---
        if cat in ("all", "race"):
            rows = _function_rows_with("potential_race")
            races = []
            for r, meta in rows:
                race_info = meta.get("potential_race", {})
                races.append({
                    "function": r["label"], "file": r["file"],
                    "shared_fields": race_info.get("shared_fields", []),
                    "goroutine_line": race_info.get("goroutine_line", 0),
                    "source_context": _ctx(meta),
                })
            _set_category("race_conditions", "potential_race", races)

        # --- FFI/transmute (Rust) ---
        if cat in ("all", "ffi"):
            sink_rows = conn.execute(
                "SELECT label, file, metadata FROM nodes "
                "WHERE metadata LIKE '%\"sink_type\": \"unsafe_ffi\"%'"
            ).fetchall()
            ffi_sinks = []
            ffi_total = 0
            for r in sink_rows:
                meta = _load_metadata(r["metadata"])
                if not _include(meta):
                    continue
                ffi_total += 1
                if max_per_category == 0 or len(ffi_sinks) < max_per_category:
                    ffi_sinks.append({"operation": r["label"], "file": r["file"], "source_context": _ctx(meta)})
            if ffi_total:
                results["ffi_risks"] = ffi_sinks
                category_totals["ffi_risks"] = ffi_total

        # --- Missing validation (both Rust and Go) ---
        if cat in ("all", "validation"):
            rows = _function_rows_with("no_input_validation")
            no_val = []
            for r, meta in rows:
                if meta.get("no_input_validation"):
                    no_val.append({
                        "function": r["label"], "file": r["file"],
                        "visibility": r["visibility"],
                        "source_context": _ctx(meta),
                    })
            _set_category("missing_validation", "no_input_validation", no_val)

        # --- Wrapping arithmetic (Rust) ---
        if cat in ("all", "unsafe"):
            rows = _function_rows_with("wrapping_arithmetic")
            wrap_fns = []
            for r, meta in rows:
                wrap_fns.append({
                    "function": r["label"], "file": r["file"],
                    "operations": meta.get("wrapping_arithmetic", []),
                    "source_context": _ctx(meta),
                })
            _set_category("wrapping_arithmetic", "wrapping_arithmetic", wrap_fns)

        # --- Go: Unsafe type assertions ---
        if cat in ("all", "go", "type_assert"):
            rows = _function_rows_with("unsafe_type_assertions")
            ta_fns = []
            for r, meta in rows:
                ta_fns.append({
                    "function": r["label"], "file": r["file"],
                    "assertions": meta.get("unsafe_type_assertions", []),
                    "source_context": _ctx(meta),
                })
            _set_category("unsafe_type_assertions", "unsafe_type_assertions", ta_fns)

        # --- Go: SQL injection ---
        if cat in ("all", "go", "sql"):
            rows = _function_rows_with("sql_injection_risk")
            sql_fns = []
            for r, meta in rows:
                sql_fns.append({
                    "function": r["label"], "file": r["file"],
                    "risks": meta.get("sql_injection_risk", []),
                    "source_context": _ctx(meta),
                })
            _set_category("sql_injection", "sql_injection_risk", sql_fns)

        # --- Deserialization sinks ---
        if cat in ("all", "java", "python", "js", "deser"):
            rows = _function_rows_with("deserialization_sinks")
            deser_fns = []
            for r, meta in rows:
                deser_fns.append({
                    "function": r["label"], "file": r["file"],
                    "sinks": meta.get("deserialization_sinks", []),
                    "source_context": _ctx(meta),
                })
            _set_category("deserialization", "deserialization_sinks", deser_fns)

        # --- Java: Reflection usage ---
        if cat in ("all", "java", "reflection"):
            rows = _function_rows_with("reflection_usage")
            refl_fns = []
            for r, meta in rows:
                refl_fns.append({
                    "function": r["label"], "file": r["file"],
                    "operations": meta.get("reflection_usage", []),
                    "source_context": _ctx(meta),
                })
            _set_category("reflection", "reflection_usage", refl_fns)

        # --- Java: Injection sinks ---
        if cat in ("all", "java", "injection"):
            rows = _function_rows_with("injection_sinks")
            inj_fns = []
            for r, meta in rows:
                inj_fns.append({
                    "function": r["label"], "file": r["file"],
                    "sinks": meta.get("injection_sinks", []),
                    "source_context": _ctx(meta),
                })
            _set_category("injection", "injection_sinks", inj_fns)

        # --- Weak crypto ---
        if cat in ("all", "java", "python", "js", "crypto"):
            rows = _function_rows_with("weak_crypto")
            crypto_fns = []
            for r, meta in rows:
                crypto_fns.append({
                    "function": r["label"], "file": r["file"],
                    "patterns": meta.get("weak_crypto", []),
                    "source_context": _ctx(meta),
                })
            _set_category("weak_crypto", "weak_crypto", crypto_fns)

        # --- Python/TypeScript: command execution ---
        if cat in ("all", "python", "command"):
            rows = _function_rows_with("command_injection_risk")
            cmd_fns = []
            for r, meta in rows:
                cmd_fns.append({
                    "function": r["label"], "file": r["file"],
                    "risks": meta.get("command_injection_risk", []),
                    "language": meta.get("language", ""),
                    "source_context": _ctx(meta),
                })
            _set_category("command_execution", "command_injection_risk", cmd_fns)

        # --- Python/TypeScript: private key material handling ---
        if cat in ("all", "python", "js", "keys"):
            rows = _function_rows_with("private_key_material")
            key_fns = []
            for r, meta in rows:
                key_fns.append({
                    "function": r["label"], "file": r["file"],
                    "language": meta.get("language", ""),
                    "source_context": _ctx(meta),
                })
            _set_category("private_key_material", "private_key_material", key_fns)

        # --- Java: Swallowed exceptions ---
        if cat in ("all", "java"):
            rows = _function_rows_with("swallowed_exceptions")
            swallow_fns = []
            for r, meta in rows:
                if meta.get("swallowed_exceptions", 0) > 0:
                    swallow_fns.append({
                        "function": r["label"], "file": r["file"],
                        "empty_catches": meta["swallowed_exceptions"],
                        "source_context": _ctx(meta),
                    })
            _set_category("swallowed_exceptions", "swallowed_exceptions", swallow_fns)

        # --- Java: Resource leaks ---
        if cat in ("all", "java"):
            rows = _function_rows_with("resource_leaks")
            leak_fns = []
            for r, meta in rows:
                leak_fns.append({
                    "function": r["label"], "file": r["file"],
                    "types": meta.get("resource_leaks", []),
                    "source_context": _ctx(meta),
                })
            _set_category("resource_leaks", "resource_leaks", leak_fns)

        # --- Unsafe downcasts (Solidity) ---
        if cat in ("all", "downcast"):
            rows = _function_rows_with("unsafe_downcast")
            dc_fns = []
            for r, meta in rows:
                dc_fns.append({
                    "function": r["label"], "file": r["file"],
                    "line": r["line_start"], "casts": meta.get("unsafe_downcast", []),
                    "source_context": _ctx(meta),
                })
            _set_category("unsafe_downcasts", "unsafe_downcast", dc_fns)

        # --- Dead parameters ---
        if cat in ("all", "dead_params"):
            rows = _function_rows_with("dead_params")
            dp_fns = []
            for r, meta in rows:
                dp_fns.append({
                    "function": r["label"], "file": r["file"],
                    "line": r["line_start"], "visibility": r["visibility"],
                    "unused_params": meta.get("dead_params", []),
                    "source_context": _ctx(meta),
                })
            _set_category("dead_params", "dead_params", dp_fns)

        # Summary
        total = sum(category_totals.values())
        truncated_categories = _category_truncation(results, category_totals)
        shown_total = sum(len(v) for v in results.values() if isinstance(v, list))
        results["_summary"] = {
            "total_findings": total,
            "shown_findings": shown_total,
            "categories": list(results.keys()),
            "category_totals": category_totals,
            "truncated_categories": truncated_categories,
            "truncated": bool(truncated_categories),
            "max_per_category": max_per_category,
            "query_scope": "production_only" if exclude_research else "all_sources",
        }

        return json.dumps(results, indent=2)
    except sqlite3.OperationalError as exc:
        return _query_sqlite_error(
            "cs_unsafe",
            exc,
            timeout_seconds,
            category=cat,
            query_scope="production_only" if exclude_research else "all_sources",
        )
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# EXPLORATION TOOLS (drill-down, path finding, state tracing)
# ---------------------------------------------------------------------------

@mcp.tool()
def cs_sinks(
    db: str = "",
    sink_type: str = "",
    external_only: bool = False,
    exclude_research: bool = False,
    timeout_seconds: int = 0,
    max_results: int = 100,
    max_callers_per_sink: int = 20,
) -> str:
    """List dangerous sink nodes and bounded caller reachability.

    This is a drill-down companion to cs_audit's sink summary. Broad output is
    capped for LLM context by default; set max_results=0 and/or
    max_callers_per_sink=0 only when exhaustive output is intentional.

    Args:
        db: Database path (default: graph.db)
        sink_type: Optional sink type filter, e.g. fund_transfer or self_destruct
        external_only: Only include public/external callers in reachability output
        exclude_research: Exclude nodes originating from research-mode files
        timeout_seconds: Optional SQLite query budget before returning an error (0 disables)
        max_results: Maximum sinks to expand (0 disables)
        max_callers_per_sink: Maximum reachable callers per expanded sink (0 disables)
    """
    if max_results < 0:
        max_results = 0
    if max_callers_per_sink < 0:
        max_callers_per_sink = 0

    db_path = _resolve_db(db)
    try:
        conn = _open_query_connection(db_path, timeout_seconds=timeout_seconds)
    except sqlite3.Error as exc:
        return _query_open_error("cs_sinks", db_path, exc)

    try:
        sink_rows = conn.execute(
            "SELECT id, label, type, visibility, file, line_start, line_end, "
            "signature, metadata FROM nodes "
            "WHERE metadata LIKE '%\"is_sink\"%' "
            "ORDER BY file, line_start, id"
        ).fetchall()

        sinks = []
        total = 0
        by_type: dict[str, int] = {}
        for row in sink_rows:
            meta = _load_metadata(row["metadata"])
            if not meta.get("is_sink"):
                continue
            current_type = meta.get("sink_type", "unknown")
            if sink_type and current_type != sink_type:
                continue
            if not _include_metadata(meta, exclude_research):
                continue
            by_type[current_type] = by_type.get(current_type, 0) + 1
            total = _append_capped(sinks, {
                "id": row["id"],
                "label": row["label"],
                "node_type": row["type"],
                "visibility": row["visibility"],
                "file": row["file"],
                "line_start": row["line_start"],
                "line_end": row["line_end"],
                "signature": row["signature"],
                "sink_type": current_type,
                "source_context": meta.get("source_context", "production"),
                "metadata": meta,
            }, total, max_results)

        shown_sinks = sinks
        sink_summary = _section_summary(total, len(shown_sinks))

        if shown_sinks:
            node_map: dict[str, dict] = {}
            for row in conn.execute(
                "SELECT id, label, type, visibility, file, line_start, line_end, "
                "signature, metadata FROM nodes"
            ).fetchall():
                node_map[row["id"]] = {
                    "id": row["id"],
                    "label": row["label"],
                    "type": row["type"],
                    "visibility": row["visibility"],
                    "file": row["file"],
                    "line_start": row["line_start"],
                    "line_end": row["line_end"],
                    "signature": row["signature"],
                    "_metadata_raw": row["metadata"],
                }

            rev_adj: dict[str, list[str]] = {}
            for row in conn.execute(
                "SELECT source, target FROM edges WHERE relation = 'calls'"
            ).fetchall():
                rev_adj.setdefault(row["target"], []).append(row["source"])
            for callers in rev_adj.values():
                callers.sort()

            def _reachable_callers(sink_id: str) -> tuple[list[dict], dict]:
                visited = {sink_id}
                queue = [(sink_id, 0)]
                pos = 0
                callers = []
                callers_total = 0
                while pos < len(queue):
                    target_id, distance = queue[pos]
                    pos += 1
                    for caller_id in rev_adj.get(target_id, []):
                        if caller_id in visited:
                            continue
                        visited.add(caller_id)
                        queue.append((caller_id, distance + 1))
                        caller = node_map.get(caller_id)
                        if not caller or caller.get("type") != "function":
                            continue
                        caller_meta = None
                        if exclude_research:
                            caller_meta = _load_metadata(caller.get("_metadata_raw"))
                            if not _include_metadata(caller_meta, exclude_research):
                                continue
                        if external_only and caller.get("visibility") not in ("public", "external"):
                            continue
                        caller_entry = {
                            "id": caller["id"],
                            "label": caller["label"],
                            "file": caller["file"],
                            "line_start": caller["line_start"],
                            "line_end": caller["line_end"],
                            "visibility": caller["visibility"],
                            "signature": caller["signature"],
                            "distance": distance + 1,
                            "_metadata_raw": caller.get("_metadata_raw"),
                        }
                        if caller_meta is not None:
                            caller_entry["source_context"] = caller_meta.get("source_context", "production")
                        callers_total += 1
                        _keep_sorted_result(
                            callers,
                            caller_entry,
                            (
                                caller_entry["distance"],
                                caller_entry["file"] or "",
                                caller_entry["line_start"] or 0,
                                caller_entry["id"],
                            ),
                            max_callers_per_sink,
                        )

                shown = _sorted_results(callers)
                summary = _section_summary(callers_total, len(shown))
                for caller in shown:
                    if "source_context" not in caller:
                        meta = _load_metadata(caller.pop("_metadata_raw", None))
                        caller["source_context"] = meta.get("source_context", "production")
                    else:
                        caller.pop("_metadata_raw", None)
                return shown, summary

            for sink in shown_sinks:
                callers, caller_summary = _reachable_callers(sink["id"])
                sink["callers"] = callers
                sink["caller_summary"] = caller_summary

        result = {
            "tool": "cs_sinks",
            "query_scope": "production_only" if exclude_research else "all_sources",
            "sink_type": sink_type or "all",
            "external_only": external_only,
            "total": total,
            "shown": sink_summary["shown"],
            "truncated": sink_summary["truncated"],
            "max_results": max_results,
            "max_callers_per_sink": max_callers_per_sink,
            "by_type": dict(sorted(by_type.items(), key=lambda item: (-item[1], item[0]))),
            "sinks": shown_sinks,
        }
        if sink_summary["truncated"]:
            result["_warning"] = "cs_sinks output capped for MCP. Set max_results=0 for exhaustive sink expansion."
        if any(s.get("caller_summary", {}).get("truncated") for s in shown_sinks):
            result.setdefault("_warnings", []).append(
                "Some caller lists were capped. Set max_callers_per_sink=0 for exhaustive caller reachability."
            )
        return json.dumps(result, indent=2)
    except sqlite3.OperationalError as exc:
        return _query_sqlite_error(
            "cs_sinks",
            exc,
            timeout_seconds,
            sink_type=sink_type or "all",
            query_scope="production_only" if exclude_research else "all_sources",
        )
    finally:
        conn.close()


@mcp.tool()
def cs_paths(
    from_label: str,
    to_label: str,
    db: str = "",
    max_depth: int = 15,
    max_paths: int = 10,
    max_endpoint_matches: int = 20,
    max_endpoint_candidates: int = 50,
    show_guards: bool = False,
    show_state: bool = False,
    exclude_research: bool = False,
    timeout_seconds: int = 0,
) -> str:
    """Find call paths between two functions in the knowledge graph.

    Useful for tracing how an external entry point reaches a dangerous sink,
    or understanding the call chain between any two functions.

    Args:
        from_label: Source function name (e.g. "deposit")
        to_label: Target function name (e.g. "withdraw")
        db: Database path (default: graph.db)
        max_depth: Maximum path depth to search
        max_paths: Maximum paths to return (0 disables)
        max_endpoint_matches: Maximum matching start/end nodes to search (0 disables)
        max_endpoint_candidates: Maximum ambiguous endpoint candidates to return (0 disables)
        show_guards: Annotate each hop with its modifier/guard protections
        show_state: Annotate each hop with state variable reads/writes
        exclude_research: Exclude nodes originating from research-mode files
        timeout_seconds: Optional SQLite query budget before returning an error (0 disables)
    """
    from collections import deque

    if max_paths < 0:
        max_paths = 0
    if max_endpoint_matches < 0:
        max_endpoint_matches = 0
    if max_endpoint_candidates < 0:
        max_endpoint_candidates = 0

    db_path = _resolve_db(db)
    try:
        conn = _open_query_connection(db_path, timeout_seconds=timeout_seconds)
    except sqlite3.Error as exc:
        return _query_open_error("cs_paths", db_path, exc)

    try:
        all_nodes = conn.execute(
            "SELECT id, label, file, metadata FROM nodes"
        ).fetchall()
        node_labels = {row["id"]: row["label"] for row in all_nodes}
        node_files = {row["id"]: row["file"] for row in all_nodes}
        node_metadata_raw = {row["id"]: row["metadata"] for row in all_nodes}
        label_counts: dict[str, int] = {}
        for label in node_labels.values():
            label_counts[label] = label_counts.get(label, 0) + 1
        if exclude_research:
            node_meta = {row["id"]: _load_metadata(row["metadata"]) for row in all_nodes}
            allowed_ids = {
                row["id"] for row in all_nodes
                if _include_metadata(node_meta[row["id"]], exclude_research)
            }
        else:
            node_meta: dict[str, dict] = {}
            allowed_ids = set(node_labels)

        def _metadata_for_node(node_id: str) -> dict:
            meta = node_meta.get(node_id)
            if meta is None:
                meta = _load_metadata(node_metadata_raw.get(node_id))
                node_meta[node_id] = meta
            return meta

        from_nodes = sorted(
            [n for n in _find_nodes(conn, from_label) if n["id"] in allowed_ids],
            key=lambda n: n["id"],
        )
        to_nodes = sorted(
            [n for n in _find_nodes(conn, to_label) if n["id"] in allowed_ids],
            key=lambda n: n["id"],
        )

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
            label = node_labels.get(node_id)
            if label is None:
                return node_id
            if label_counts.get(label, 0) > 1:
                return _qualified_label(node_id)
            return label

        def _candidate_for_node(node: dict) -> dict:
            meta = _metadata_for_node(node["id"])
            return {
                "id": node["id"],
                "label": node["label"],
                "qualified_label": _label_for_node(node["id"]),
                "file": node_files.get(node["id"], ""),
                "source_context": meta.get("source_context", "production"),
            }

        from_matches_total = len(from_nodes)
        to_matches_total = len(to_nodes)
        endpoint_cap_enabled = max_endpoint_matches > 0
        selected_from_nodes = (
            from_nodes[:max_endpoint_matches] if endpoint_cap_enabled else from_nodes
        )
        selected_to_nodes = (
            to_nodes[:max_endpoint_matches] if endpoint_cap_enabled else to_nodes
        )
        endpoint_truncated = (
            len(selected_from_nodes) < from_matches_total
            or len(selected_to_nodes) < to_matches_total
        )

        def _find_paths(start_id: str, end_id: str, path_limit: int | None) -> list[list[str]]:
            results: list[list[str]] = []
            queue = deque([[start_id]])
            while queue and (path_limit is None or len(results) < path_limit):
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
        path_limit = None if max_paths == 0 else max_paths
        path_limit_reached = False
        for fn in selected_from_nodes:
            for tn in selected_to_nodes:
                remaining = None if path_limit is None else path_limit - len(all_path_ids)
                if remaining is not None and remaining <= 0:
                    path_limit_reached = True
                    break
                for path in _find_paths(fn["id"], tn["id"], remaining):
                    key = tuple(path)
                    if key in seen_paths:
                        continue
                    seen_paths.add(key)
                    all_path_ids.append(path)
                if path_limit is not None and len(all_path_ids) >= path_limit:
                    path_limit_reached = True
                    break
            if path_limit_reached:
                break

        all_paths = [[_label_for_node(node_id) for node_id in path] for path in all_path_ids]
        result = {
            "from": from_label,
            "to": to_label,
            "paths": all_paths,
            "query_scope": "production_only" if exclude_research else "all_sources",
            "_summary": {
                "paths_found": len(all_paths),
                "path_limit_reached": path_limit_reached,
                "max_paths": max_paths,
                "max_depth": max_depth,
                "max_endpoint_matches": max_endpoint_matches,
                "max_endpoint_candidates": max_endpoint_candidates,
                "from_matches_total": from_matches_total,
                "from_matches_used": len(selected_from_nodes),
                "to_matches_total": to_matches_total,
                "to_matches_used": len(selected_to_nodes),
                "endpoint_matches_truncated": endpoint_truncated,
                "truncated": path_limit_reached or endpoint_truncated,
            },
        }
        if endpoint_truncated:
            from_candidates, from_candidate_summary = _collect_mapped_items(
                from_nodes,
                _candidate_for_node,
                max_endpoint_candidates,
            )
            to_candidates, to_candidate_summary = _collect_mapped_items(
                to_nodes,
                _candidate_for_node,
                max_endpoint_candidates,
            )
            result["from_candidates"] = from_candidates
            result["to_candidates"] = to_candidates
            result["_summary"]["from_candidates"] = from_candidate_summary
            result["_summary"]["to_candidates"] = to_candidate_summary
            if from_candidate_summary["truncated"] or to_candidate_summary["truncated"]:
                result.setdefault("_warnings", []).append(
                    "cs_paths endpoint candidate lists were capped. Increase max_endpoint_candidates or set max_endpoint_candidates=0 for all candidates."
                )

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
    except sqlite3.OperationalError as exc:
        return _query_sqlite_error(
            "cs_paths",
            exc,
            timeout_seconds,
            from_label=from_label,
            to_label=to_label,
            query_scope="production_only" if exclude_research else "all_sources",
        )
    finally:
        conn.close()


@mcp.tool()
def cs_trace(
    var: str,
    db: str = "",
    show_callers: bool = False,
    exclude_research: bool = False,
    timeout_seconds: int = 0,
    max_matches: int = 20,
    max_candidates: int = 50,
    max_callers_per_accessor: int = 20,
) -> str:
    """Trace all functions that read or write a state variable.

    Essential for understanding who can modify critical state like balances,
    totalSupply, owner, etc.

    Args:
        var: State variable name to trace (e.g. "balances", "totalSupply")
        db: Database path (default: graph.db)
        show_callers: Include one level of callers for each accessor
        exclude_research: Exclude nodes originating from research-mode files
        timeout_seconds: Optional SQLite query budget before returning an error (0 disables)
        max_matches: Maximum matching state variables to trace fully (0 disables)
        max_candidates: Maximum ambiguous variable candidates to return (0 disables)
        max_callers_per_accessor: Maximum callers attached to each reader/writer when show_callers is true (0 disables)
    """
    if max_matches < 0:
        max_matches = 0
    if max_candidates < 0:
        max_candidates = 0
    if max_callers_per_accessor < 0:
        max_callers_per_accessor = 0

    db_path = _resolve_db(db)
    try:
        conn = _open_query_connection(db_path, timeout_seconds=timeout_seconds)
    except sqlite3.Error as exc:
        return _query_open_error("cs_trace", db_path, exc)

    try:
        rows = conn.execute(
            """
            SELECT id, label, file, signature, metadata
            FROM nodes
            WHERE label = ? AND type = 'state_var'
            ORDER BY file, id
            """,
            (var,)
        ).fetchall()
        if not rows:
            rows = conn.execute(
                """
                SELECT id, label, file, signature, metadata
                FROM nodes
                WHERE label LIKE ? AND type = 'state_var'
                ORDER BY file, id
                """,
                (f"%{var}%",)
            ).fetchall()
        if not rows:
            return json.dumps({"error": f"No state variable found matching '{var}'"})

        full_by_id: dict[str, dict] = {}

        def _state_var_for_row(row) -> dict:
            cached = full_by_id.get(row["id"])
            if cached is not None:
                return cached
            item = dict(row)
            item["metadata"] = _load_metadata(item.get("metadata"))
            item["source_context"] = item["metadata"].get("source_context", "production")
            full_by_id[item["id"]] = item
            return item

        if exclude_research:
            matched_rows = []
            for row in rows:
                item = _state_var_for_row(row)
                if _include_metadata(item["metadata"], exclude_research):
                    matched_rows.append(row)
        else:
            matched_rows = rows

        if not matched_rows:
            return json.dumps({"error": f"No production state variable found matching '{var}'"})

        total_matches = len(matched_rows)
        truncated = max_matches > 0 and total_matches > max_matches
        variable_rows = matched_rows[:max_matches or total_matches]
        variables = [_state_var_for_row(row) for row in variable_rows]

        def _candidate_for_row(row) -> dict:
            item = _state_var_for_row(row)
            return {
                "id": item["id"],
                "label": item["label"],
                "file": item["file"],
                "signature": item.get("signature", ""),
                "source_context": item["source_context"],
            }

        def _accessors(var_id: str, relation: str) -> list[dict]:
            accessors = conn.execute("""
                SELECT n.id, n.label, n.file, n.visibility, n.line_start, n.line_end, n.metadata
                FROM edges e JOIN nodes n ON e.source = n.id
                WHERE e.target = ? AND e.relation = ?
                ORDER BY n.file, n.line_start, n.id
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

        def _callers(node_id: str) -> tuple[list[dict], dict]:
            rows = conn.execute("""
                SELECT n.id, n.label, n.file, n.visibility, n.metadata
                FROM edges AS e INDEXED BY idx_edges_target JOIN nodes n ON e.source = n.id
                WHERE e.target = ? AND e.relation = 'calls'
                ORDER BY n.file, n.id
            """, (node_id,)).fetchall()
            callers = []
            callers_total = 0
            for row in rows:
                item = dict(row)
                caller_meta = None
                if exclude_research:
                    caller_meta = _load_metadata(item.pop("metadata", None))
                    if not _include_metadata(caller_meta, exclude_research):
                        continue
                    item["source_context"] = caller_meta.get("source_context", "production")
                else:
                    item["_metadata_raw"] = item.pop("metadata", None)
                callers_total += 1
                sort_key = (item["file"] or "", item["id"])
                if max_callers_per_accessor == 0:
                    callers.append((sort_key, item))
                else:
                    _keep_sorted_result(
                        callers,
                        item,
                        sort_key,
                        max_callers_per_accessor,
                    )
            shown = _sorted_results(callers)
            summary = _section_summary(callers_total, len(shown))
            for caller in shown:
                if "source_context" not in caller:
                    meta = _load_metadata(caller.pop("_metadata_raw", None))
                    caller["source_context"] = meta.get("source_context", "production")
                else:
                    caller.pop("_metadata_raw", None)
            return shown, summary

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
                callers, caller_summary = _callers(acc["id"])
                acc["callers"] = callers
                acc["callers_summary"] = caller_summary

        response = {
            "query": var,
            "variable": variables[0],
            "variables": variables,
            "variable_matches": len(variables),
            "variable_matches_total": total_matches,
            "truncated": truncated,
            "max_matches": max_matches,
            "max_candidates": max_candidates,
            "max_callers_per_accessor": max_callers_per_accessor,
            "query_scope": "production_only" if exclude_research else "all_sources",
            "writers": writers,
            "readers": readers,
        }
        caller_truncated = any(
            accessor.get("callers_summary", {}).get("truncated")
            for accessor in writers + readers
        )
        if caller_truncated:
            response["caller_truncated"] = True
            response.setdefault("_warnings", []).append(
                "Some cs_trace caller lists were capped. Set max_callers_per_accessor=0 for exhaustive caller output."
            )
        if truncated:
            response["_warning"] = (
                f"cs_trace found {total_matches} matching state variables and traced the first {len(variables)}. "
                "Use a more qualified variable name or set max_matches=0 for all matches."
            )
            shown_candidates, candidate_summary = _collect_mapped_items(
                matched_rows,
                _candidate_for_row,
                max_candidates,
            )
            response["candidates"] = shown_candidates
            response["candidate_summary"] = candidate_summary
            if candidate_summary["truncated"]:
                response.setdefault("_warnings", []).append(
                    "cs_trace candidate list was capped. Increase max_candidates or set max_candidates=0 for all candidates."
                )
        return json.dumps(response, indent=2)
    except sqlite3.OperationalError as exc:
        return _query_sqlite_error(
            "cs_trace",
            exc,
            timeout_seconds,
            var=var,
            query_scope="production_only" if exclude_research else "all_sources",
        )
    finally:
        conn.close()


@mcp.tool()
def cs_cross(
    db: str = "",
    from_func: str = "",
    max_results: int = 500,
    max_start_candidates: int = 20,
    exclude_research: bool = False,
    timeout_seconds: int = 0,
) -> str:
    """Find cross-contract and cross-module calls (unresolved interfaces, delegatecall, CPI).

    These are trust boundary crossings — critical for identifying attack vectors
    where external code can influence internal state.

    Args:
        db: Database path (default: graph.db)
        from_func: Trace from a specific function (empty = list all cross-contract calls)
        max_results: Maximum raw calls returned (0 disables)
        max_start_candidates: Maximum ambiguous from_func candidates to return (0 disables)
        exclude_research: Exclude nodes originating from research-mode files
        timeout_seconds: Optional SQLite query budget before returning an error (0 disables)
    """
    if max_results < 0:
        max_results = 0
    if max_start_candidates < 0:
        max_start_candidates = 0

    db_path = _resolve_db(db)
    try:
        conn = _open_query_connection(db_path, timeout_seconds=timeout_seconds)
    except sqlite3.Error as exc:
        return _query_open_error("cs_cross", db_path, exc)

    try:
        if from_func:
            nodes = _find_nodes(conn, from_func)
            if not nodes:
                return json.dumps({"error": f"No function found matching '{from_func}'"})

            all_nodes = conn.execute(
                "SELECT id, label, type, file, metadata FROM nodes"
            ).fetchall()
            node_by_id = {row["id"]: dict(row) for row in all_nodes}
            if exclude_research:
                node_meta = {row["id"]: _load_metadata(row["metadata"]) for row in all_nodes}
                allowed_ids = {
                    row["id"] for row in all_nodes
                    if _include_metadata(node_meta[row["id"]], exclude_research)
                }
            else:
                node_meta: dict[str, dict] = {}
                allowed_ids = set(node_by_id)

            def _metadata_for_node(node_id: str) -> dict:
                meta = node_meta.get(node_id)
                if meta is None:
                    row = node_by_id.get(node_id)
                    meta = _load_metadata(row.get("metadata") if row else None)
                    node_meta[node_id] = meta
                return meta

            matching_starts = [
                node_by_id[node["id"]]
                for node in nodes
                if (
                    node["id"] in allowed_ids
                    and node["id"] in node_by_id
                    and node_by_id[node["id"]].get("type") == "function"
                )
            ]
            if not matching_starts:
                return json.dumps({"error": f"No production function found matching '{from_func}'"})
            if len(matching_starts) > 1:
                candidates = []
                for node in matching_starts:
                    meta = _metadata_for_node(node["id"])
                    candidates.append({
                        "id": node["id"],
                        "label": node["label"],
                        "file": node["file"],
                        "source_context": meta.get("source_context", "production"),
                    })
                shown_candidates, candidate_summary = _cap_items(candidates, max_start_candidates)
                response = {
                    "error": (
                        f"Ambiguous from_func '{from_func}' matched {len(matching_starts)} functions. "
                        "Use a more qualified function name."
                    ),
                    "tool": "cs_cross",
                    "from_func": from_func,
                    "query_scope": "production_only" if exclude_research else "all_sources",
                    "max_start_candidates": max_start_candidates,
                    "start_candidates": shown_candidates,
                    "start_candidate_summary": candidate_summary,
                }
                if candidate_summary["truncated"]:
                    response["_warning"] = (
                        "cs_cross start candidate list was capped. Increase max_start_candidates "
                        "or set max_start_candidates=0 for all candidates."
                    )
                return json.dumps(response, indent=2)

            start_id = matching_starts[0]["id"]

            adjacency: dict[str, list[str]] = {}
            for row in conn.execute(
                "SELECT source, target FROM edges WHERE relation IN (?, ?, ?)",
                TRAVERSAL_RELATIONS,
            ).fetchall():
                if row["source"] not in allowed_ids or row["target"] not in allowed_ids:
                    continue
                adjacency.setdefault(row["source"], []).append(row["target"])

            reachable = {start_id}
            queue = [start_id]
            pos = 0
            while pos < len(queue):
                current = queue[pos]
                pos += 1
                for neighbor in adjacency.get(current, []):
                    if neighbor not in reachable:
                        reachable.add(neighbor)
                        queue.append(neighbor)

            call_edges_by_source: dict[str, list[dict]] = {}
            for row in conn.execute(
                "SELECT source, target, attributes FROM edges WHERE relation = 'calls'"
            ).fetchall():
                if row["source"] in reachable:
                    call_edges_by_source.setdefault(row["source"], []).append(dict(row))

            cross_boundary = []
            for node_id in reachable:
                source_row = node_by_id.get(node_id)
                edges = call_edges_by_source.get(node_id, [])
                for edge in edges:
                    attrs = _load_metadata(edge["attributes"])
                    if _is_trust_boundary_call(attrs):
                        target = node_by_id.get(edge["target"])
                        if target and edge["target"] not in allowed_ids:
                            continue
                        source_meta = _metadata_for_node(node_id)
                        target_meta = _metadata_for_node(edge["target"]) if target else {}
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

            calls = cross_boundary
            total = len(calls)
            shown_calls = calls[:max_results] if max_results > 0 else calls
            truncated = len(shown_calls) < total
        else:
            shown_calls, call_summary = _collect_cross_entries(
                _iter_cross_call_rows(conn, exclude_research),
                max_results,
            )
            total = call_summary["total"]
            truncated = call_summary["truncated"]

        response = {
            "tool": "cs_cross",
            "query_scope": "production_only" if exclude_research else "all_sources",
            "from_func": from_func or None,
            "total": total,
            "shown": len(shown_calls),
            "truncated": truncated,
            "max_results": max_results,
            "max_start_candidates": max_start_candidates,
            "calls": shown_calls,
        }
        if truncated:
            response["_warning"] = (
                f"cs_cross found {total} trust-boundary calls and returned {len(shown_calls)}. "
                "Use cs_cross_summary first on large graphs or set max_results=0 for exhaustive raw output."
            )
        return json.dumps(response, indent=2, default=str)
    except sqlite3.OperationalError as exc:
        return _query_sqlite_error(
            "cs_cross",
            exc,
            timeout_seconds,
            from_func=from_func,
            query_scope="production_only" if exclude_research else "all_sources",
        )
    finally:
        conn.close()


@mcp.tool()
def cs_cross_summary(
    db: str = "",
    from_func: str = "",
    top: int = 50,
    max_counter_items: int = 10,
    max_start_candidates: int = 20,
    exclude_research: bool = False,
    timeout_seconds: int = 0,
) -> str:
    """Summarize trust-boundary calls with bounded samples for large graphs.

    Use this before exhaustive cs_cross on large repos. It reports totals,
    top source files/targets, source context counts, and at most top sample
    calls so MCP clients avoid spending large context on raw edge lists.

    Args:
        db: Database path (default: graph.db)
        from_func: Optional function to trace before summarizing trust-boundary calls
        top: Maximum sample calls to include
        max_counter_items: Maximum top source files/targets to include (0 disables)
        max_start_candidates: Maximum ambiguous from_func candidates to return (0 disables)
        exclude_research: Exclude nodes originating from research-mode files
        timeout_seconds: Optional SQLite query budget before returning an error (0 disables)
    """
    if max_counter_items < 0:
        max_counter_items = 0
    if max_start_candidates < 0:
        max_start_candidates = 0

    db_path = _resolve_db(db)
    try:
        if from_func:
            cross_result = json.loads(cs_cross(
                db=db_path,
                from_func=from_func,
                max_results=0,
                max_start_candidates=max_start_candidates,
                exclude_research=exclude_research,
                timeout_seconds=timeout_seconds,
            ))
            if isinstance(cross_result, dict) and "error" in cross_result:
                cross_result["tool"] = "cs_cross_summary"
                return json.dumps(cross_result, indent=2)
            entries = cross_result.get("calls", []) if isinstance(cross_result, dict) else cross_result
            summary = _summarize_cross_entries(entries, top, max_counter_items)
        else:
            conn = _open_query_connection(db_path, timeout_seconds=timeout_seconds)
            try:
                summary = _summarize_cross_entries(
                    _iter_cross_call_rows(conn, exclude_research),
                    top,
                    max_counter_items,
                )
            finally:
                conn.close()

        summary.update({
            "tool": "cs_cross_summary",
            "query_scope": "production_only" if exclude_research else "all_sources",
            "from_func": from_func or None,
            "_next_steps": [
                "Use cs_cross(from_func=...) to inspect a specific reachable boundary in detail.",
                "Use cs_paths(from_label=..., to_label=...) to validate exploit-relevant paths.",
                "Use direct source review on the top source files before treating this as a finding.",
            ],
        })
        if summary.get("counter_summary", {}).get("truncated"):
            summary.setdefault("_warnings", []).append(
                "cs_cross_summary counters were capped. Increase max_counter_items or set max_counter_items=0 for exhaustive counters."
            )
        return json.dumps(summary, indent=2, default=str)
    except sqlite3.OperationalError as exc:
        return _query_sqlite_error(
            "cs_cross_summary",
            exc,
            timeout_seconds,
            from_func=from_func,
            query_scope="production_only" if exclude_research else "all_sources",
        )
    except sqlite3.Error as exc:
        return _query_open_error("cs_cross_summary", db_path, exc)


@mcp.tool()
def cs_state(
    db: str = "",
    entity: str = "",
    exclude_research: bool = False,
    timeout_seconds: int = 0,
    max_entities: int = 20,
    max_transitions_per_entity: int = 50,
    max_warnings: int = 50,
) -> str:
    """Analyze state machine transitions and flag security issues.

    For Solidity: detects unguarded enum transitions, terminal states, missing transitions.
    For Cosmos SDK/Go: detects KVStore entity lifecycles (Set/Get/Delete), flags
    unvalidated writes, write-only entities (no deletion path), and unprotected CRUD.

    Args:
        db: Database path (default: graph.db)
        entity: Filter by entity name (e.g. "VaultState" or "Audience"). Empty = show all.
        exclude_research: Exclude transitions originating from research-mode files
        timeout_seconds: Optional SQLite query budget before returning an error (0 disables)
        max_entities: Maximum entity groups to return when entity is empty (0 disables)
        max_transitions_per_entity: Maximum transitions returned per entity (0 disables)
        max_warnings: Maximum warnings returned (0 disables)
    """
    if max_entities < 0:
        max_entities = 0
    if max_transitions_per_entity < 0:
        max_transitions_per_entity = 0
    if max_warnings < 0:
        max_warnings = 0

    db_path = _resolve_db(db)
    try:
        conn = _open_query_connection(db_path, timeout_seconds=timeout_seconds)
    except sqlite3.Error as exc:
        return _query_open_error("cs_state", db_path, exc)

    try:
        if entity:
            rows = conn.execute(
                """
                SELECT st.*, n.file as function_file, n.label as function_label, n.metadata as function_metadata
                FROM state_transitions st
                LEFT JOIN nodes n ON st.function_id = n.id
                WHERE st.entity = ?
                ORDER BY st.entity, st.function_id, st.from_state, st.to_state
                """,
                (entity,)
            ).fetchall()
        else:
            rows = conn.execute("""
                SELECT st.*, n.file as function_file, n.label as function_label, n.metadata as function_metadata
                FROM state_transitions st
                LEFT JOIN nodes n ON st.function_id = n.id
                ORDER BY st.entity, st.function_id, st.from_state, st.to_state
            """).fetchall()

        transitions = []
        for row in rows:
            item = dict(row)
            raw_meta = item.pop("function_metadata", None)
            if exclude_research:
                meta = _load_metadata(raw_meta)
                if not _include_metadata(meta, exclude_research):
                    continue
                item["source_context"] = meta.get("source_context", "production")
            else:
                item["_function_metadata_raw"] = raw_meta
            transitions.append(item)

        entities: dict[str, list[dict]] = {}
        for t in transitions:
            ent = t["entity"]
            if ent not in entities:
                entities[ent] = []
            entities[ent].append(t)

        warnings = []
        warnings_total = 0

        def _add_warning(message: str):
            nonlocal warnings_total
            warnings_total = _append_capped(warnings, message, warnings_total, max_warnings)

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
                        _add_warning(
                            f"UNVALIDATED_WRITE: {func_label}() writes {ent} "
                            f"to store without input validation"
                        )
                    if t["to_state"] == "deleted" and "no_validation" in conditions:
                        _add_warning(
                            f"UNVALIDATED_DELETE: {func_label}() deletes {ent} "
                            f"from store without input validation"
                        )

                if has_set and not has_delete:
                    _add_warning(
                        f"NO_DELETE_PATH: {ent} can be created (Set) but never "
                        f"deleted — potential state bloat"
                    )
                if has_delete and not has_read:
                    _add_warning(
                        f"DELETE_WITHOUT_READ: {ent} can be deleted but no Get "
                        f"operation found — verify deletion logic"
                    )
            else:
                # Solidity-style enum state machine
                for t in trans:
                    if t["from_state"] == "*":
                        func_label = t.get("function_label") or t["function_id"].split("::")[-1]
                        _add_warning(
                            f"UNGUARDED: {func_label}() transitions {ent} to "
                            f"{t['to_state']} without checking current state"
                        )

                states_with_outgoing = {t["from_state"] for t in trans if t["from_state"] != "*"}
                states_targeted = {t["to_state"] for t in trans}
                terminal_states = all_states - states_with_outgoing
                for ts in terminal_states:
                    if any(t["to_state"] == ts for t in trans):
                        _add_warning(f"TERMINAL: {ent}::{ts} has no outgoing transitions")

                initial_candidates = states_with_outgoing - states_targeted
                for us in initial_candidates:
                    if us not in states_targeted:
                        _add_warning(
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
                                    _add_warning(
                                        f"TOGGLE: {ent} can toggle between "
                                        f"{pair[0]} <-> {pair[1]} — verify "
                                        f"this is intentional (potential griefing)"
                                    )

        entity_names = sorted(entities)
        entity_totals = {name: len(entities[name]) for name in entity_names}
        transitions_total = sum(entity_totals.values())

        shown_entity_names = entity_names
        if not entity and max_entities > 0:
            shown_entity_names = entity_names[:max_entities]

        shown_entities: dict[str, list[dict]] = {}
        truncated_entities: dict[str, dict] = {}
        for ent in shown_entity_names:
            trans = entities[ent]
            if max_transitions_per_entity > 0 and len(trans) > max_transitions_per_entity:
                shown_entities[ent] = trans[:max_transitions_per_entity]
                truncated_entities[ent] = {
                    "shown": max_transitions_per_entity,
                    "total": len(trans),
                    "hidden": len(trans) - max_transitions_per_entity,
                }
            else:
                shown_entities[ent] = trans

        for trans in shown_entities.values():
            for item in trans:
                if "source_context" not in item:
                    meta = _load_metadata(item.pop("_function_metadata_raw", None))
                    item["source_context"] = meta.get("source_context", "production")
                else:
                    item.pop("_function_metadata_raw", None)

        hidden_entities = len(entity_names) - len(shown_entity_names)
        shown_warnings = warnings

        truncated = bool(
            hidden_entities
            or truncated_entities
            or len(shown_warnings) < warnings_total
        )

        return json.dumps({
            "entities": shown_entities,
            "warnings": shown_warnings,
            "query_scope": "production_only" if exclude_research else "all_sources",
            "_summary": {
                "entity": entity or None,
                "entities_total": len(entity_names),
                "entities_shown": len(shown_entity_names),
                "hidden_entities": hidden_entities,
                "transitions_total": transitions_total,
                "transitions_shown": sum(len(v) for v in shown_entities.values()),
                "entity_totals": entity_totals,
                "truncated_entities": truncated_entities,
                "warnings_total": warnings_total,
                "warnings_shown": len(shown_warnings),
                "truncated": truncated,
                "max_entities": max_entities,
                "max_transitions_per_entity": max_transitions_per_entity,
                "max_warnings": max_warnings,
            },
        }, indent=2)
    except sqlite3.OperationalError as exc:
        return _query_sqlite_error(
            "cs_state",
            exc,
            timeout_seconds,
            entity=entity,
            query_scope="production_only" if exclude_research else "all_sources",
        )
    finally:
        conn.close()


@mcp.tool()
def cs_lookup(
    name: str,
    db: str = "",
    depth: int = 1,
    exclude_research: bool = False,
    timeout_seconds: int = DEFAULT_MCP_QUERY_TIMEOUT_SECONDS,
    max_matches: int = 20,
    max_relation_items: int = 100,
    max_candidates: int = 50,
) -> str:
    """Look up a function by name and return its complete profile.

    Returns every occurrence of the function in the graph with:
      - File, line range, signature, visibility, metadata
      - Direct callers (who calls this function)
      - Direct callees (what this function calls)
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
        timeout_seconds: SQLite query budget before returning an error
        max_matches: Maximum matching functions to fully profile (0 disables)
        max_relation_items: Maximum rows per relation list in each function profile (0 disables)
        max_candidates: Maximum ambiguous match candidates to return (0 disables)
    """
    if max_matches < 0:
        max_matches = 0
    if max_relation_items < 0:
        max_relation_items = 0
    if max_candidates < 0:
        max_candidates = 0

    db_path = _resolve_db(db)
    try:
        conn = _open_query_connection(db_path, timeout_seconds=timeout_seconds)
    except sqlite3.Error as exc:
        return _query_open_error("cs_lookup", db_path, exc)

    try:
        nodes = _find_nodes(conn, name)
        if not nodes:
            return json.dumps({"error": f"No function found matching '{name}'"})

        full_by_id: dict[str, dict] = {}
        matched_node_ids = [row["id"] for row in nodes]

        def _parse_full_node(full_dict: dict) -> dict | None:
            cached = full_by_id.get(full_dict["id"])
            if cached is not None:
                return cached
            meta = _load_metadata(full_dict.get("metadata"))
            if not _include_metadata(meta, exclude_research):
                return None
            full_dict["metadata"] = meta
            full_by_id[full_dict["id"]] = full_dict
            return full_dict

        if exclude_research:
            filtered_ids = []
            fetched_rows = _fetch_nodes_by_ids(conn, matched_node_ids)
            for full_dict in fetched_rows:
                parsed = _parse_full_node(full_dict)
                if parsed is not None:
                    filtered_ids.append(parsed["id"])
            matched_node_ids = filtered_ids
        else:
            total_unfiltered = len(matched_node_ids)
            profile_count = total_unfiltered if max_matches == 0 else min(max_matches, total_unfiltered)
            candidate_count = 0
            if max_matches > 0 and total_unfiltered > max_matches:
                candidate_count = total_unfiltered if max_candidates == 0 else min(max_candidates, total_unfiltered)
            needed_count = max(profile_count, candidate_count)
            for full_dict in _fetch_nodes_by_ids(conn, matched_node_ids[:needed_count]):
                _parse_full_node(full_dict)

        def _candidate_for_id(node_id: str) -> dict:
            full_dict = full_by_id.get(node_id)
            if full_dict is None:
                fetched = _fetch_nodes_by_ids(conn, [node_id])
                if fetched:
                    full_dict = _parse_full_node(fetched[0])
            if full_dict is None:
                return {"id": node_id}
            meta = full_dict["metadata"]
            return {
                "id": full_dict["id"],
                "label": full_dict["label"],
                "type": full_dict["type"],
                "visibility": full_dict["visibility"],
                "file": full_dict["file"],
                "line": full_dict["line_start"],
                "source_context": meta.get("source_context", "production"),
            }

        if not matched_node_ids:
            if exclude_research:
                return json.dumps({"error": f"No production function found matching '{name}'"})
            return json.dumps({"error": f"No function found matching '{name}'"})

        total_matches = len(matched_node_ids)
        truncated = max_matches > 0 and total_matches > max_matches
        candidate_ids = matched_node_ids[:max_matches or total_matches]

        results = []
        for node_id in candidate_ids:

            # Full node details
            full = full_by_id.get(node_id)
            if not full:
                continue
            info = dict(full)
            relation_summary: dict[str, dict] = {}

            def _set_relation(name: str, items: list, summary: dict | None = None):
                if summary is None:
                    shown, summary = _cap_items(items, max_relation_items)
                else:
                    shown = items
                info[name] = shown
                relation_summary[name] = summary

            def _relation_item(row) -> dict | None:
                item = dict(row)
                meta = _load_metadata(item.pop("metadata", None))
                if not _include_metadata(meta, exclude_research):
                    return None
                item["source_context"] = meta.get("source_context", "production")
                return item

            def _collect_relation(sql: str, params: tuple, count_sql: str) -> tuple[list, dict]:
                if max_relation_items > 0 and not exclude_research:
                    total = conn.execute(count_sql, params).fetchone()[0]
                    if total == 0:
                        return [], {
                            "total": 0,
                            "shown": 0,
                            "truncated": False,
                        }
                    rows = conn.execute(f"{sql} LIMIT ?", params + (max_relation_items,)).fetchall()
                    items = [_relation_item(row) for row in rows]
                    shown = [item for item in items if item is not None]
                    return shown, {
                        "total": total,
                        "shown": len(shown),
                        "truncated": total > len(shown),
                    }

                items = []
                total = 0
                for row in conn.execute(sql, params):
                    item = _relation_item(row)
                    if item is None:
                        continue
                    total += 1
                    if max_relation_items == 0 or len(items) < max_relation_items:
                        items.append(item)
                return items, {
                    "total": total,
                    "shown": len(items),
                    "truncated": total > len(items),
                }

            # Callers (who calls this)
            callers, callers_summary = _collect_relation("""
                SELECT n.id, n.label, n.file, n.visibility, n.line_start,
                       n.line_end, n.signature, n.metadata, e.attributes
                FROM edges AS e INDEXED BY idx_edges_target JOIN nodes n ON e.source = n.id
                WHERE e.target = ? AND e.relation = 'calls'
            """, (node_id,), (
                "SELECT COUNT(*) FROM edges AS e JOIN nodes n ON e.source = n.id "
                "WHERE e.target = ? AND e.relation = 'calls'"
            ))
            _set_relation("callers", callers, callers_summary)

            # Depth-2 callers
            if depth >= 2 and info["callers"]:
                for caller in info["callers"]:
                    caller["callers"], caller["callers_summary"] = _collect_relation("""
                        SELECT n.id, n.label, n.file, n.visibility, n.metadata
                        FROM edges AS e INDEXED BY idx_edges_target JOIN nodes n ON e.source = n.id
                        WHERE e.target = ? AND e.relation = 'calls'
                    """, (caller["id"],), (
                        "SELECT COUNT(*) FROM edges AS e JOIN nodes n ON e.source = n.id "
                        "WHERE e.target = ? AND e.relation = 'calls'"
                    ))

            # Callees (what this calls)
            callees, callees_summary = _collect_relation("""
                SELECT n.id, n.label, n.file, n.visibility, n.line_start,
                       n.line_end, n.signature, n.metadata, e.attributes
                FROM edges e JOIN nodes n ON e.target = n.id
                WHERE e.source = ? AND e.relation = 'calls'
            """, (node_id,), (
                "SELECT COUNT(*) FROM edges e JOIN nodes n ON e.target = n.id "
                "WHERE e.source = ? AND e.relation = 'calls'"
            ))
            _set_relation("callees", callees, callees_summary)

            # Depth-2 callees
            if depth >= 2 and info["callees"]:
                for callee in info["callees"]:
                    callee["callees"], callee["callees_summary"] = _collect_relation("""
                        SELECT n.id, n.label, n.file, n.visibility, n.metadata
                        FROM edges e JOIN nodes n ON e.target = n.id
                        WHERE e.source = ? AND e.relation = 'calls'
                    """, (callee["id"],), (
                        "SELECT COUNT(*) FROM edges e JOIN nodes n ON e.target = n.id "
                        "WHERE e.source = ? AND e.relation = 'calls'"
                    ))

            # State reads
            state_reads, state_reads_summary = _collect_relation("""
                SELECT n.id, n.label, n.file, n.metadata
                FROM edges e JOIN nodes n ON e.target = n.id
                WHERE e.source = ? AND e.relation = 'reads_state'
            """, (node_id,), (
                "SELECT COUNT(*) FROM edges e JOIN nodes n ON e.target = n.id "
                "WHERE e.source = ? AND e.relation = 'reads_state'"
            ))
            _set_relation("state_reads", state_reads, state_reads_summary)

            # State writes
            state_writes, state_writes_summary = _collect_relation("""
                SELECT n.id, n.label, n.file, n.metadata
                FROM edges e JOIN nodes n ON e.target = n.id
                WHERE e.source = ? AND e.relation = 'writes_state'
            """, (node_id,), (
                "SELECT COUNT(*) FROM edges e JOIN nodes n ON e.target = n.id "
                "WHERE e.source = ? AND e.relation = 'writes_state'"
            ))
            _set_relation("state_writes", state_writes, state_writes_summary)

            # Guards/modifiers
            guards, guards_summary = _collect_relation("""
                SELECT n.id, n.label, n.file, n.type, n.metadata
                FROM edges AS e INDEXED BY idx_edges_target JOIN nodes n ON e.source = n.id
                WHERE e.target = ? AND e.relation = 'guards'
            """, (node_id,), (
                "SELECT COUNT(*) FROM edges AS e JOIN nodes n ON e.source = n.id "
                "WHERE e.target = ? AND e.relation = 'guards'"
            ))
            _set_relation("guards", guards, guards_summary)

            # All other edges (flows_to, inherits, emits_event, etc.)
            other_edges_out, other_out_summary = _collect_relation("""
                SELECT e.relation, n.id, n.label, n.file, n.metadata, e.attributes
                FROM edges e JOIN nodes n ON e.target = n.id
                WHERE e.source = ? AND e.relation NOT IN
                      ('calls', 'reads_state', 'writes_state')
            """, (node_id,), (
                "SELECT COUNT(*) FROM edges e JOIN nodes n ON e.target = n.id "
                "WHERE e.source = ? AND e.relation NOT IN "
                "('calls', 'reads_state', 'writes_state')"
            ))
            if other_out_summary["total"]:
                _set_relation("other_edges_out", other_edges_out, other_out_summary)

            other_edges_in, other_in_summary = _collect_relation("""
                SELECT e.relation, n.id, n.label, n.file, n.metadata, e.attributes
                FROM edges AS e INDEXED BY idx_edges_target JOIN nodes n ON e.source = n.id
                WHERE e.target = ? AND e.relation NOT IN ('calls', 'guards')
            """, (node_id,), (
                "SELECT COUNT(*) FROM edges AS e JOIN nodes n ON e.source = n.id "
                "WHERE e.target = ? AND e.relation NOT IN ('calls', 'guards')"
            ))
            if other_in_summary["total"]:
                _set_relation("other_edges_in", other_edges_in, other_in_summary)

            info["_relation_summary"] = relation_summary

            results.append(info)

        response = {
            "query": name,
            "matches": len(results),
            "matches_total": total_matches,
            "truncated": truncated,
            "max_matches": max_matches,
            "max_relation_items": max_relation_items,
            "max_candidates": max_candidates,
            "query_scope": "production_only" if exclude_research else "all_sources",
            "functions": results,
        }
        relation_truncated = any(
            summary.get("truncated")
            for fn in results
            for summary in fn.get("_relation_summary", {}).values()
        )
        if relation_truncated:
            response["relation_truncated"] = True
            response.setdefault("_warnings", []).append(
                "Some cs_lookup relation lists were capped. Set max_relation_items=0 for exhaustive relation output."
            )
        if truncated:
            response["_warning"] = (
                f"cs_lookup found {total_matches} matches and returned the first {len(results)} full profiles. "
                "Use a more qualified name, inspect candidates, or set max_matches=0 for all profiles."
            )
            shown_candidates, candidate_summary = _collect_mapped_items(
                matched_node_ids,
                _candidate_for_id,
                max_candidates,
            )
            response["candidates"] = shown_candidates
            response["candidate_summary"] = candidate_summary
            if candidate_summary["truncated"]:
                response.setdefault("_warnings", []).append(
                    "cs_lookup candidate list was capped. Increase max_candidates or set max_candidates=0 for all candidates."
                )
        return json.dumps(response, indent=2)
    except sqlite3.OperationalError as exc:
        if "interrupted" in str(exc).lower():
            return json.dumps({
                "error": f"cs_lookup timed out after {timeout_seconds}s",
                "query": name,
                "query_scope": "production_only" if exclude_research else "all_sources",
            }, indent=2)
        return json.dumps({
            "error": f"SQLite error while running cs_lookup: {exc}",
            "query": name,
            "query_scope": "production_only" if exclude_research else "all_sources",
        }, indent=2)
    finally:
        conn.close()


if __name__ == "__main__":
    mcp.run()
