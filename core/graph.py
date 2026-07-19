"""Graph operations: BFS, path-finding, state tracing, sink propagation."""

import json
from collections import deque
from core.schema import GraphDB

# Edge types that BFS traversal follows (execution flow)
TRAVERSAL_EDGES = {"calls", "flows_to", "inherits"}


def _qualified_label_from_id(node_id: str) -> str:
    """Extract a qualified label from a node ID for disambiguation.

    'file.cpp::ns::Class::method(int)' -> 'Class::method'
    'file.sol::Contract.deposit' -> 'Contract.deposit'
    """
    if "::" in node_id:
        parts = node_id.split("::")
        relevant = parts[1:]  # skip file
        if relevant:
            last = relevant[-1]
            paren = last.find("(")
            if paren > 0:
                relevant[-1] = last[:paren]
        if len(relevant) <= 2:
            return "::".join(relevant)
        return "::".join(relevant[-2:])
    return node_id


class Graph:
    """Query interface over a ChainScope knowledge graph."""

    def __init__(self, db_path: str):
        self.db = GraphDB(db_path)

    def _build_adjacency(self, conn) -> dict[str, list[str]]:
        """Build forward adjacency list from traversal edges."""
        rows = conn.execute(
            """
            SELECT source, target, relation
            FROM edges INDEXED BY idx_edges_relation_source
            WHERE relation IN ('calls', 'flows_to', 'inherits')
            """
        ).fetchall()
        adj: dict[str, list[str]] = {}
        for row in rows:
            src = row["source"]
            if src not in adj:
                adj[src] = []
            adj[src].append(row["target"])
        return adj

    def _build_reverse_adjacency(self, conn) -> dict[str, list[str]]:
        """Build reverse adjacency list (target -> callers) for backward BFS."""
        rows = conn.execute(
            """
            SELECT source, target
            FROM edges INDEXED BY idx_edges_relation_target
            WHERE relation = 'calls'
            """
        ).fetchall()
        rev: dict[str, list[str]] = {}
        for row in rows:
            tgt = row["target"]
            if tgt not in rev:
                rev[tgt] = []
            rev[tgt].append(row["source"])
        return rev

    def _build_node_map(self, conn) -> dict[str, dict]:
        """Build id -> {label, file, type} lookup for all function nodes."""
        rows = conn.execute(
            "SELECT id, label, file, type FROM nodes WHERE type = 'function'"
        ).fetchall()
        return {row["id"]: dict(row) for row in rows}

    def get_reachable_nodes(self, start_ids: list[str], adj: dict = None) -> set:
        """Multi-source BFS. Only follows calls/flows_to/inherits edges.

        Pass a prebuilt adj dict to avoid rebuilding for repeated calls.
        """
        if not start_ids:
            return set()
        reachable = set(start_ids)
        queue = deque(start_ids)
        if adj is None:
            conn = self.db.get_connection()
            try:
                adj = self._build_adjacency(conn)
            finally:
                conn.close()
        while queue:
            current = queue.popleft()
            for neighbor in adj.get(current, []):
                if neighbor not in reachable:
                    reachable.add(neighbor)
                    queue.append(neighbor)
        return reachable

    def find_path(self, start_id: str, end_id: str, max_depth: int = 15) -> list[str]:
        """BFS shortest path. Returns list of labels, or [] if no path."""
        paths = self.find_all_paths(start_id, end_id, max_depth=max_depth, max_paths=1)
        return paths[0] if paths else []

    def find_all_paths(self, start_id: str, end_id: str,
                       max_depth: int = 15, max_paths: int = 20) -> list[list[str]]:
        """BFS all paths from start to end. Returns list of label-paths.

        Uses qualified labels (Class::method) when labels are ambiguous.
        """
        conn = self.db.get_connection()
        try:
            adj = self._build_adjacency(conn)
            results = []
            queue = deque([[start_id]])
            while queue and len(results) < max_paths:
                path = queue.popleft()
                current = path[-1]
                if current == end_id and len(path) > 1:
                    labels = []
                    for node_id in path:
                        row = conn.execute(
                            "SELECT label FROM nodes WHERE id=?", (node_id,)
                        ).fetchone()
                        if row:
                            label = row["label"]
                            # Check if label is ambiguous (multiple nodes share it)
                            count = conn.execute(
                                "SELECT COUNT(*) as cnt FROM nodes WHERE label=?", (label,)
                            ).fetchone()["cnt"]
                            if count > 1:
                                # Use qualified label from ID
                                label = _qualified_label_from_id(node_id)
                            labels.append(label)
                        else:
                            labels.append(node_id)
                    results.append(labels)
                    continue
                if len(path) > max_depth:
                    continue
                for neighbor in adj.get(current, []):
                    if neighbor not in path:  # Avoid cycles
                        queue.append(path + [neighbor])
            return results
        finally:
            conn.close()

    def get_state_accessors(self, state_var_id: str, relation: str) -> list[dict]:
        """Find all functions that read/write a state variable."""
        conn = self.db.get_connection()
        try:
            rows = conn.execute("""
                SELECT n.id, n.label, n.file, n.visibility, n.line_start, n.line_end
                FROM edges e INDEXED BY idx_edges_target_relation
                JOIN nodes n ON e.source = n.id
                WHERE e.target = ? AND e.relation = ?
            """, (state_var_id, relation)).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    def get_callers(self, node_id: str) -> list[dict]:
        """Find all direct callers of a function."""
        conn = self.db.get_connection()
        try:
            rows = conn.execute("""
                SELECT n.id, n.label, n.file, n.visibility
                FROM edges e INDEXED BY idx_edges_target_relation
                JOIN nodes n ON e.source = n.id
                WHERE e.target = ? AND e.relation = 'calls'
            """, (node_id,)).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    def get_guards_for(self, node_id: str) -> list[dict]:
        """Find all modifiers/guards protecting a function."""
        conn = self.db.get_connection()
        try:
            rows = conn.execute("""
                SELECT n.id, n.label, n.file, n.type
                FROM edges e INDEXED BY idx_edges_target_relation
                JOIN nodes n ON e.source = n.id
                WHERE e.target = ? AND e.relation = 'guards'
            """, (node_id,)).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    def get_sinks_by_type(self, sink_type: str = None) -> list[dict]:
        """Find all nodes tagged as sinks in metadata."""
        conn = self.db.get_connection()
        try:
            rows = conn.execute(
                """SELECT id, label, file, type, metadata FROM nodes
                   WHERE metadata LIKE '%"is_sink"%'"""
            ).fetchall()
            results = []
            for row in rows:
                meta = json.loads(row["metadata"]) if row["metadata"] else {}
                if not meta.get("is_sink"):
                    continue
                if sink_type and meta.get("sink_type") != sink_type:
                    continue
                results.append(dict(row))
            return results
        finally:
            conn.close()

    def propagate_sinks(self, sink_labels: list[str],
                         rev_adj: dict[str, list[str]] = None,
                         node_map: dict[str, dict] = None) -> list[dict]:
        """Backward BFS from sinks to find all wrapper functions.

        Pass prebuilt rev_adj and node_map to avoid rebuilding for repeated calls.
        """
        conn = self.db.get_connection()
        try:
            if not sink_labels:
                return []

            # Build in-memory lookups once if not provided
            if rev_adj is None:
                rev_adj = self._build_reverse_adjacency(conn)
            if node_map is None:
                node_map = self._build_node_map(conn)

            # Look up each sink label individually to avoid dynamic SQL
            sink_map: dict[str, str] = {}
            for label in sink_labels:
                rows = conn.execute(
                    "SELECT id, label FROM nodes WHERE label = ?", (label,)
                ).fetchall()
                for row in rows:
                    sink_map[row["id"]] = row["label"]

            queue = deque(sink_map.keys())
            visited = set(sink_map.keys())
            results = []

            while queue:
                target_id = queue.popleft()
                underlying_sink = sink_map[target_id]
                for caller_id in rev_adj.get(target_id, []):
                    if caller_id not in visited:
                        visited.add(caller_id)
                        node = node_map.get(caller_id)
                        if node and node["type"] == "function":
                            results.append({
                                "wrapper_label": node["label"],
                                "file": node["file"],
                                "underlying_sink": underlying_sink,
                            })
                            sink_map[caller_id] = underlying_sink
                            queue.append(caller_id)
            return results
        finally:
            conn.close()

    def get_attack_surface(self) -> list[dict]:
        """List all external/public functions sorted by state write reach.

        Optimized: builds adjacency + write-count maps once, then does BFS per entry point.
        """
        conn = self.db.get_connection()
        try:
            # Build adjacency list ONCE
            adj = self._build_adjacency(conn)

            # Precompute per-node write counts
            write_map: dict[str, int] = {}
            rows = conn.execute(
                "SELECT source, COUNT(DISTINCT target) as cnt "
                "FROM edges INDEXED BY idx_edges_relation_source "
                "WHERE relation='writes_state' GROUP BY source"
            ).fetchall()
            for r in rows:
                write_map[r["source"]] = r["cnt"]

            externals = conn.execute("""
                SELECT id, label, file, signature, metadata
                FROM nodes
                WHERE type = 'function' AND visibility IN ('public', 'external')
            """).fetchall()

            results = []
            for ext in externals:
                reachable = self.get_reachable_nodes([ext["id"]], adj=adj)
                write_count = sum(write_map.get(rid, 0) for rid in reachable)
                results.append({
                    "id": ext["id"],
                    "label": ext["label"],
                    "file": ext["file"],
                    "signature": ext["signature"],
                    "reachable_count": len(reachable),
                    "state_writes": write_count,
                    "metadata": ext["metadata"],
                })
            results.sort(key=lambda x: x["state_writes"], reverse=True)
            return results
        finally:
            conn.close()
