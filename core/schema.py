"""SQLite schema and connection management for ChainScope knowledge graphs."""

import json
import sqlite3
from pathlib import Path

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS nodes (
    id TEXT PRIMARY KEY,
    label TEXT NOT NULL,
    type TEXT NOT NULL,
    visibility TEXT DEFAULT '',
    file TEXT NOT NULL,
    line_start INTEGER DEFAULT 0,
    line_end INTEGER DEFAULT 0,
    signature TEXT DEFAULT '',
    metadata TEXT DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS edges (
    source TEXT NOT NULL,
    target TEXT NOT NULL,
    relation TEXT NOT NULL,
    attributes TEXT DEFAULT '{}',
    PRIMARY KEY (source, target, relation)
);

CREATE TABLE IF NOT EXISTS state_transitions (
    entity TEXT NOT NULL,
    from_state TEXT NOT NULL,
    to_state TEXT NOT NULL,
    function_id TEXT NOT NULL,
    conditions TEXT DEFAULT '[]',
    PRIMARY KEY (entity, from_state, to_state, function_id)
);

CREATE TABLE IF NOT EXISTS graph_metadata (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_nodes_file ON nodes(file);
CREATE INDEX IF NOT EXISTS idx_nodes_type ON nodes(type);
CREATE INDEX IF NOT EXISTS idx_nodes_label ON nodes(label);
CREATE INDEX IF NOT EXISTS idx_nodes_type_label ON nodes(type, label);
CREATE INDEX IF NOT EXISTS idx_nodes_type_label_file ON nodes(type, label, file, id);
CREATE INDEX IF NOT EXISTS idx_nodes_type_visibility ON nodes(type, visibility);
CREATE INDEX IF NOT EXISTS idx_nodes_type_file_line ON nodes(type, file, line_start, id);
CREATE INDEX IF NOT EXISTS idx_edges_source ON edges(source);
CREATE INDEX IF NOT EXISTS idx_edges_target ON edges(target);
CREATE INDEX IF NOT EXISTS idx_edges_relation ON edges(relation);
CREATE INDEX IF NOT EXISTS idx_edges_source_relation ON edges(source, relation);
CREATE INDEX IF NOT EXISTS idx_edges_target_relation ON edges(target, relation);
CREATE INDEX IF NOT EXISTS idx_edges_relation_source ON edges(relation, source);
CREATE INDEX IF NOT EXISTS idx_edges_relation_target ON edges(relation, target);
CREATE INDEX IF NOT EXISTS idx_transitions_entity ON state_transitions(entity);
CREATE INDEX IF NOT EXISTS idx_transitions_function ON state_transitions(function_id);
"""


class GraphDB:
    """SQLite-backed knowledge graph storage."""

    def __init__(self, db_path: str):
        self.db_path = db_path
        parent = Path(db_path).expanduser().parent
        if str(parent) not in ("", "."):
            parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    def _init_db(self):
        conn = self.get_connection()
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(SCHEMA_SQL)
            conn.commit()
        finally:
            conn.close()

    def clear(self):
        """Drop all data from tables so a fresh index can be built."""
        conn = self.get_connection()
        try:
            conn.execute("DELETE FROM state_transitions")
            conn.execute("DELETE FROM edges")
            conn.execute("DELETE FROM nodes")
            conn.execute("DELETE FROM graph_metadata")
            conn.commit()
        finally:
            conn.close()

    def insert_node(self, id: str, label: str, type: str, visibility: str = "",
                    file: str = "", line_start: int = 0, line_end: int = 0,
                    signature: str = "", metadata: str = "{}"):
        conn = self.get_connection()
        try:
            conn.execute("""
                INSERT OR IGNORE INTO nodes (id, label, type, visibility, file, line_start, line_end, signature, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (id, label, type, visibility, file, line_start, line_end, signature, metadata))
            conn.commit()
        finally:
            conn.close()

    def insert_nodes_batch(self, nodes: list[dict]):
        conn = self.get_connection()
        try:
            conn.executemany("""
                INSERT OR IGNORE INTO nodes (id, label, type, visibility, file, line_start, line_end, signature, metadata)
                VALUES (:id, :label, :type, :visibility, :file,
                        :line_start, :line_end, :signature, :metadata)
            """, [
                {
                    "id": n["id"], "label": n["label"], "type": n["type"],
                    "visibility": n.get("visibility", ""),
                    "file": n.get("file", ""),
                    "line_start": n.get("line_start", 0),
                    "line_end": n.get("line_end", 0),
                    "signature": n.get("signature", ""),
                    "metadata": n.get("metadata", "{}"),
                }
                for n in nodes
            ])
            conn.commit()
        finally:
            conn.close()

    def insert_edge(self, source: str, target: str, relation: str, attributes: str = "{}"):
        conn = self.get_connection()
        try:
            existing = conn.execute(
                "SELECT attributes FROM edges WHERE source=? AND target=? AND relation=?",
                (source, target, relation)
            ).fetchone()
            if existing:
                old_attrs = json.loads(existing["attributes"])
                new_attrs = json.loads(attributes)
                old_attrs.update(new_attrs)
                conn.execute(
                    "UPDATE edges SET attributes=? WHERE source=? AND target=? AND relation=?",
                    (json.dumps(old_attrs), source, target, relation)
                )
            else:
                conn.execute("""
                    INSERT INTO edges (source, target, relation, attributes)
                    VALUES (?, ?, ?, ?)
                """, (source, target, relation, attributes))
            conn.commit()
        finally:
            conn.close()

    def insert_edges_batch(self, edges: list[dict]):
        """Batch insert edges. Uses INSERT OR REPLACE — last writer wins."""
        conn = self.get_connection()
        try:
            conn.executemany("""
                INSERT OR REPLACE INTO edges (source, target, relation, attributes)
                VALUES (:source, :target, :relation, :attributes)
            """, [
                {
                    "source": e["source"], "target": e["target"],
                    "relation": e["relation"],
                    "attributes": e.get("attributes", "{}"),
                }
                for e in edges
            ])
            conn.commit()
        finally:
            conn.close()

    def insert_transition(self, entity: str, from_state: str, to_state: str,
                          function_id: str, conditions: str = "[]"):
        conn = self.get_connection()
        try:
            conn.execute("""
                INSERT OR IGNORE INTO state_transitions (entity, from_state, to_state, function_id, conditions)
                VALUES (?, ?, ?, ?, ?)
            """, (entity, from_state, to_state, function_id, conditions))
            conn.commit()
        finally:
            conn.close()

    def insert_transitions_batch(self, transitions: list[dict]):
        conn = self.get_connection()
        try:
            conn.executemany("""
                INSERT OR IGNORE INTO state_transitions (entity, from_state, to_state, function_id, conditions)
                VALUES (:entity, :from_state, :to_state, :function_id, :conditions)
            """, [
                {
                    "entity": t["entity"], "from_state": t["from_state"],
                    "to_state": t["to_state"], "function_id": t["function_id"],
                    "conditions": t.get("conditions", "[]"),
                }
                for t in transitions
            ])
            conn.commit()
        finally:
            conn.close()

    def set_metadata(self, key: str, value):
        conn = self.get_connection()
        try:
            encoded = value if isinstance(value, str) else json.dumps(value)
            conn.execute("""
                INSERT INTO graph_metadata (key, value)
                VALUES (?, ?)
                ON CONFLICT(key) DO UPDATE SET value=excluded.value
            """, (key, encoded))
            conn.commit()
        finally:
            conn.close()

    def get_metadata(self, key: str, default=None):
        conn = self.get_connection()
        try:
            row = conn.execute(
                "SELECT value FROM graph_metadata WHERE key=?",
                (key,),
            ).fetchone()
            if not row:
                return default
            raw = row["value"]
            try:
                return json.loads(raw)
            except Exception:
                return raw
        finally:
            conn.close()
