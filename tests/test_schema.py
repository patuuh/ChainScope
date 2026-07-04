import sqlite3
import json
import pytest
from core.schema import GraphDB


class TestSchemaCreation:
    def test_creates_tables(self, tmp_db):
        db = GraphDB(tmp_db)
        conn = db.get_connection()
        tables = [r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()]
        conn.close()
        assert "nodes" in tables
        assert "edges" in tables
        assert "state_transitions" in tables
        assert "graph_metadata" in tables

    def test_creates_parent_directory(self, tmp_path):
        db_path = tmp_path / ".chainscope" / "nested.db"
        GraphDB(str(db_path))
        assert db_path.exists()

    def test_wal_mode(self, tmp_db):
        db = GraphDB(tmp_db)
        conn = db.get_connection()
        mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
        conn.close()
        assert mode == "wal"

    def test_creates_target_relation_index(self, tmp_db):
        db = GraphDB(tmp_db)
        conn = db.get_connection()
        indexes = {
            r[0] for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='index'"
            ).fetchall()
        }
        conn.close()
        assert "idx_edges_target_relation" in indexes


class TestNodeCRUD:
    def test_insert_node(self, tmp_db):
        db = GraphDB(tmp_db)
        db.insert_node(
            id="vault.sol::deposit",
            label="deposit",
            type="function",
            visibility="external",
            file="vault.sol",
            line_start=30,
            line_end=40,
            signature="function deposit(uint256 amount) external",
            metadata=json.dumps({"payable": False})
        )
        conn = db.get_connection()
        row = conn.execute("SELECT * FROM nodes WHERE id=?", ("vault.sol::deposit",)).fetchone()
        conn.close()
        assert row is not None
        assert row["label"] == "deposit"
        assert row["visibility"] == "external"
        assert row["line_start"] == 30

    def test_insert_duplicate_ignored(self, tmp_db):
        db = GraphDB(tmp_db)
        db.insert_node(id="a::b", label="b", type="function", visibility="public", file="a")
        db.insert_node(id="a::b", label="b", type="function", visibility="public", file="a")
        conn = db.get_connection()
        count = conn.execute("SELECT COUNT(*) FROM nodes WHERE id='a::b'").fetchone()[0]
        conn.close()
        assert count == 1

    def test_batch_insert_nodes(self, tmp_db):
        db = GraphDB(tmp_db)
        nodes = [
            {"id": f"f::func{i}", "label": f"func{i}", "type": "function",
             "visibility": "public", "file": "f"}
            for i in range(100)
        ]
        db.insert_nodes_batch(nodes)
        conn = db.get_connection()
        count = conn.execute("SELECT COUNT(*) FROM nodes").fetchone()[0]
        conn.close()
        assert count == 100


class TestEdgeCRUD:
    def test_insert_edge(self, tmp_db):
        db = GraphDB(tmp_db)
        db.insert_edge("a::f1", "a::f2", "calls", json.dumps({"conditional": True}))
        conn = db.get_connection()
        row = conn.execute("SELECT * FROM edges WHERE source='a::f1'").fetchone()
        conn.close()
        assert row["relation"] == "calls"
        attrs = json.loads(row["attributes"])
        assert attrs["conditional"] is True

    def test_upsert_edge_merges_attributes(self, tmp_db):
        db = GraphDB(tmp_db)
        db.insert_edge("a::f1", "a::f2", "calls", json.dumps({"conditional": True}))
        db.insert_edge("a::f1", "a::f2", "calls", json.dumps({"in_branch": "if x > 0"}))
        conn = db.get_connection()
        row = conn.execute("SELECT * FROM edges WHERE source='a::f1'").fetchone()
        conn.close()
        attrs = json.loads(row["attributes"])
        assert attrs["conditional"] is True
        assert attrs["in_branch"] == "if x > 0"

    def test_batch_insert_edges(self, tmp_db):
        db = GraphDB(tmp_db)
        edges = [
            {"source": f"f::f{i}", "target": f"f::f{i+1}", "relation": "calls", "attributes": "{}"}
            for i in range(50)
        ]
        db.insert_edges_batch(edges)
        conn = db.get_connection()
        count = conn.execute("SELECT COUNT(*) FROM edges").fetchone()[0]
        conn.close()
        assert count == 50


class TestStateTransitions:
    def test_insert_transition(self, tmp_db):
        db = GraphDB(tmp_db)
        db.insert_transition("Vault", "Inactive", "Active", "vault.sol::activate",
                            json.dumps(["require(state == Inactive)"]))
        conn = db.get_connection()
        row = conn.execute("SELECT * FROM state_transitions").fetchone()
        conn.close()
        assert row["entity"] == "Vault"
        assert row["from_state"] == "Inactive"
        assert row["function_id"] == "vault.sol::activate"


class TestGraphMetadata:
    def test_set_and_get_metadata(self, tmp_db):
        db = GraphDB(tmp_db)
        value = {"confidence": {"score": 91.2}, "include_research": True}
        db.set_metadata("build_info", value)
        loaded = db.get_metadata("build_info")
        assert loaded == value

    def test_clear_removes_metadata(self, tmp_db):
        db = GraphDB(tmp_db)
        db.set_metadata("build_info", {"repo_path": "/tmp/repo"})
        db.clear()
        assert db.get_metadata("build_info") is None
