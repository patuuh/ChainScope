import json
import inspect
import pytest
from pathlib import Path
from core.indexer import Indexer
from core.indexer import classify_source_context
from core.schema import GraphDB


class TestChainDetection:
    def test_detects_solidity(self, sol_repo):
        indexer = Indexer(sol_repo)
        assert indexer.detected_chain == "solidity"

    def test_detects_anchor(self, anchor_repo):
        indexer = Indexer(anchor_repo)
        assert indexer.detected_chain == "anchor"

    def test_detects_substrate(self, substrate_repo):
        indexer = Indexer(substrate_repo)
        assert indexer.detected_chain == "substrate"


class TestIndexing:
    def test_mcp_build_and_profile_do_not_self_timeout_by_default(self):
        import mcp_server

        assert mcp_server.DEFAULT_MCP_BUILD_TIMEOUT_SECONDS == 0
        assert inspect.signature(mcp_server.cs_build).parameters["timeout_seconds"].default == 0
        assert inspect.signature(mcp_server.cs_profile).parameters["timeout_seconds"].default == 0

    def test_mcp_uses_capped_node_match_helpers(self):
        import mcp_server

        assert not hasattr(mcp_server, "_find_nodes")
        assert hasattr(mcp_server, "_find_node_ids_capped")
        assert hasattr(mcp_server, "_find_function_rows_capped")

    def test_schema_creates_mcp_query_indexes(self, tmp_db):
        db = GraphDB(tmp_db)
        conn = db.get_connection()
        try:
            indexes = {
                row["name"]
                for row in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'index'"
                )
            }
        finally:
            conn.close()

        assert {
            "idx_nodes_type_label",
            "idx_nodes_type_label_file",
            "idx_nodes_type_visibility",
            "idx_nodes_type_file_line",
            "idx_transitions_function",
        } <= indexes

    def test_build_missing_repo_returns_json_error(self):
        import mcp_server

        result = json.loads(mcp_server.cs_build(repo_path="/not/a/dir"))

        assert result["tool"] == "cs_build"
        assert result["repo_path"] == "/not/a/dir"
        assert "not a directory" in result["error"]

    def test_profile_caps_large_sections_for_mcp_context(self, tmp_path):
        import mcp_server

        repo = tmp_path / "workspace"
        repo.mkdir()
        for i in range(5):
            project = repo / f"pkg{i}"
            project.mkdir()
            (project / "foundry.toml").write_text("[profile.default]\n")
            (project / f"Vault{i}.sol").write_text(
                "pragma solidity ^0.8.0; contract Vault { function ping() external {} }"
            )

        capped = json.loads(mcp_server.cs_profile(str(repo), top=5, max_output_items=2))
        uncapped = json.loads(mcp_server.cs_profile(str(repo), top=5, max_output_items=0))

        assert len(capped["top_projects"]) == 2
        assert len(capped["build_plan"]) == 2
        assert capped["_summary"]["sections"]["top_projects"] == {"total": 5, "shown": 2, "truncated": True}
        assert capped["_summary"]["sections"]["project_markers"] == {"total": 1, "shown": 1, "truncated": False}
        assert "top_projects" in capped["_summary"]["truncated_sections"]
        assert capped["_summary"]["max_output_items"] == 2

        assert len(uncapped["top_projects"]) == 5
        assert len(uncapped["build_plan"]) == 5
        assert uncapped["_summary"]["truncated"] is False

    def test_source_context_classifies_deploy_dirs_as_script(self):
        assert classify_source_context("contracts/deploy/Foo.s.sol") == "script"
        assert classify_source_context("contracts/deployments/mainnet/Foo.sol") == "script"
        assert classify_source_context("broadcast/Deploy.s.sol/1/run-latest.json") == "script"

    def test_index_skips_deploy_dirs_unless_research_enabled(self, tmp_path, tmp_db):
        repo = tmp_path / "repo"
        repo.mkdir()
        deploy = repo / "deploy"
        deploy.mkdir()
        (repo / "Vault.sol").write_text(
            "pragma solidity ^0.8.0; contract Vault { uint256 public total; function set(uint256 x) external { total = x; } }"
        )
        (deploy / "Verifier.sol").write_text(
            "pragma solidity ^0.8.0; contract Verifier { uint256 public total; function execute(uint256 x) external { total = x; } }"
        )

        Indexer(str(repo), include_research=False).index(tmp_db)
        db = GraphDB(tmp_db)
        conn = db.get_connection()
        labels = {row["label"] for row in conn.execute("SELECT label FROM nodes WHERE type='function'").fetchall()}
        conn.close()
        assert "set" in labels
        assert "execute" not in labels

        Indexer(str(repo), include_research=True).index(tmp_db)
        db = GraphDB(tmp_db)
        conn = db.get_connection()
        rows = conn.execute("SELECT label, metadata FROM nodes WHERE type='function'").fetchall()
        conn.close()
        contexts = {row["label"]: json.loads(row["metadata"] or "{}").get("source_context", "production") for row in rows}
        assert contexts["set"] == "production"
        assert contexts["execute"] == "script"

    def test_index_solidity_repo(self, sol_repo, tmp_db):
        indexer = Indexer(sol_repo)
        stats = indexer.index(tmp_db)
        assert stats["files_indexed"] == 2
        assert stats["nodes"] > 0
        assert stats["edges"] > 0
        db = GraphDB(tmp_db)
        conn = db.get_connection()
        node_count = conn.execute("SELECT COUNT(*) FROM nodes").fetchone()[0]
        conn.close()
        assert node_count > 0

    def test_index_populates_all_tables(self, sol_repo, tmp_db):
        indexer = Indexer(sol_repo)
        indexer.index(tmp_db)
        db = GraphDB(tmp_db)
        conn = db.get_connection()
        nodes = conn.execute("SELECT COUNT(*) FROM nodes").fetchone()[0]
        edges = conn.execute("SELECT COUNT(*) FROM edges").fetchone()[0]
        transitions = conn.execute("SELECT COUNT(*) FROM state_transitions").fetchone()[0]
        conn.close()
        assert nodes > 0
        assert edges > 0
        assert transitions > 0  # simple_vault.sol has state machine

    def test_index_persists_build_info_metadata(self, sol_repo, tmp_db):
        indexer = Indexer(sol_repo, include_research=True)
        stats = indexer.index(tmp_db)
        db = GraphDB(tmp_db)
        build_info = db.get_metadata("build_info")
        assert build_info is not None
        assert build_info["repo_path"] == sol_repo
        assert build_info["include_research"] is True
        assert build_info["files_indexed"] == stats["files_indexed"]
        assert build_info["confidence"]["score"] == stats["confidence"]["score"]

    def test_audit_surfaces_persisted_build_info(self, sol_repo, tmp_db):
        import mcp_server

        indexer = Indexer(sol_repo, include_research=True)
        indexer.index(tmp_db)
        report = json.loads(mcp_server.cs_audit(db=tmp_db, top=5))
        assert "build_info" in report
        assert report["build_info"]["include_research"] is True

    def test_summary_is_cheap_graph_health_check(self, sol_repo, tmp_db):
        import mcp_server

        indexer = Indexer(sol_repo, include_research=True)
        stats = indexer.index(tmp_db)

        summary = json.loads(mcp_server.cs_summary(db=tmp_db, attack_surface=True, top=3))

        assert summary["nodes"] == stats["nodes"]
        assert summary["functions"] > 0
        assert summary["edges"] > 0
        assert summary["build_info"]["files_indexed"] == stats["files_indexed"]
        assert summary["source_context_summary"]
        assert len(summary["attack_surface"]) <= 3

    def test_summary_default_uses_aggregate_health_counts(self, sol_repo, tmp_db, monkeypatch):
        import mcp_server

        indexer = Indexer(sol_repo, include_research=True)
        indexer.index(tmp_db)

        db = GraphDB(tmp_db)
        conn = db.get_connection()
        try:
            node_ids = {row["id"] for row in conn.execute("SELECT id FROM nodes")}
            expected_nodes = len(node_ids)
            expected_edges = sum(
                1
                for row in conn.execute("SELECT source, target FROM edges")
                if row["source"] in node_ids and row["target"] in node_ids
            )
            expected_transitions = conn.execute(
                "SELECT COUNT(*) FROM state_transitions"
            ).fetchone()[0]
        finally:
            conn.close()

        real_open = mcp_server._open_query_connection
        statements = []

        class CountingConnection:
            def __init__(self, conn):
                self._conn = conn

            def execute(self, sql, *args, **kwargs):
                normalized = " ".join(sql.split())
                statements.append(normalized)
                if normalized == "SELECT id, label, type, visibility, file, signature, metadata FROM nodes":
                    raise AssertionError("default cs_summary should not stream full node rows")
                if normalized == "SELECT source, target, relation FROM edges":
                    raise AssertionError("default cs_summary should not stream full edge rows")
                return self._conn.execute(sql, *args, **kwargs)

            def close(self):
                self._conn.close()

        monkeypatch.setattr(
            mcp_server,
            "_open_query_connection",
            lambda *args, **kwargs: CountingConnection(real_open(*args, **kwargs)),
        )

        summary = json.loads(mcp_server.cs_summary(db=tmp_db))

        assert summary["nodes"] == expected_nodes
        assert summary["edges"] == expected_edges
        assert summary["transitions"] == expected_transitions
        assert summary["functions"] > 0
        assert summary["source_context_summary"]
        assert "attack_surface" not in summary
        assert any("SELECT COUNT(*) FROM nodes" in sql for sql in statements)
        assert any("GROUP BY type" in sql for sql in statements)
        assert any("GROUP BY e.relation" in sql for sql in statements)

    def test_summary_default_counts_known_source_contexts_without_parsing(self, tmp_db, monkeypatch):
        import mcp_server

        db = GraphDB(tmp_db)
        custom_metadata = json.dumps({"source_context": "custom", "large": ["x"] * 20})
        db.insert_node(
            id="Vault.sol::Vault.entry()",
            label="entry",
            type="function",
            visibility="external",
            file="Vault.sol",
            metadata=json.dumps({"source_context": "production"}),
        )
        db.insert_node(
            id="scripts/Deploy.sol::Deploy.run()",
            label="run",
            type="function",
            visibility="external",
            file="scripts/Deploy.sol",
            metadata=json.dumps({"source_context": "script"}),
        )
        db.insert_node(
            id="custom/Probe.sol::Probe.run()",
            label="runCustom",
            type="function",
            visibility="external",
            file="custom/Probe.sol",
            metadata=custom_metadata,
        )
        for i in range(40):
            db.insert_node(
                id=f"Vault.sol::Vault.helper{i}()",
                label=f"helper{i}",
                type="function",
                file="Vault.sol",
                metadata=json.dumps({"large": ["x"] * 20}),
            )

        real_load = mcp_server._load_metadata
        real_open = mcp_server._open_query_connection
        parsed = []
        statements = []

        class CountingConnection:
            def __init__(self, conn):
                self._conn = conn

            def execute(self, sql, *args, **kwargs):
                statements.append(" ".join(sql.split()))
                return self._conn.execute(sql, *args, **kwargs)

            def close(self):
                self._conn.close()

        def counting_load(raw):
            parsed.append(raw)
            return real_load(raw)

        monkeypatch.setattr(
            mcp_server,
            "_open_query_connection",
            lambda *args, **kwargs: CountingConnection(real_open(*args, **kwargs)),
        )
        monkeypatch.setattr(mcp_server, "_load_metadata", counting_load)

        summary = json.loads(mcp_server.cs_summary(db=tmp_db))

        assert summary["nodes"] == 43
        assert summary["source_context_summary"] == {
            "production": 41,
            "script": 1,
            "custom": 1,
        }
        assert parsed == [custom_metadata]
        assert sum("SUM(CASE WHEN" in sql and "source_context" in sql for sql in statements) == 1
        assert not any("SELECT COUNT(*) FROM nodes WHERE 1=1" in sql for sql in statements)
        assert any("AND NOT" in sql and "SELECT metadata FROM nodes" in sql for sql in statements)

    def test_known_source_context_helpers_avoid_json_parse(self, monkeypatch):
        import mcp_server

        def fail_load(_raw):
            raise AssertionError("known source_context values should not require JSON parsing")

        monkeypatch.setattr(mcp_server, "_load_metadata", fail_load)

        production = json.dumps({"source_context": "production", "large": ["x"] * 20})
        script = json.dumps({"source_context": "script", "large": ["x"] * 20})

        assert mcp_server._metadata_source_context(production) == "production"
        assert mcp_server._metadata_source_context(script) == "script"
        assert mcp_server._is_research_metadata_raw(production) is False
        assert mcp_server._is_research_metadata_raw(script) is True

    def test_summary_exclude_research_uses_raw_metadata_filters(self, tmp_db, monkeypatch):
        import mcp_server

        db = GraphDB(tmp_db)
        prod_meta = json.dumps({"source_context": "production", "large": ["x"] * 20})
        script_meta = json.dumps({"source_context": "script", "large": ["x"] * 20})
        db.insert_node(
            id="Vault.sol::Vault.entry()",
            label="entry",
            type="function",
            visibility="external",
            file="Vault.sol",
            metadata=prod_meta,
        )
        db.insert_node(
            id="Vault.sol::Vault.total",
            label="total",
            type="state_var",
            file="Vault.sol",
            metadata=json.dumps({"large": ["x"] * 20}),
        )
        db.insert_node(
            id="scripts/Deploy.sol::Deploy.run()",
            label="run",
            type="function",
            visibility="external",
            file="scripts/Deploy.sol",
            metadata=script_meta,
        )
        db.insert_node(
            id="scripts/Deploy.sol::Deploy.total",
            label="total",
            type="state_var",
            file="scripts/Deploy.sol",
            metadata=script_meta,
        )
        db.insert_edge("Vault.sol::Vault.entry()", "Vault.sol::Vault.total", "writes_state")
        db.insert_edge("scripts/Deploy.sol::Deploy.run()", "scripts/Deploy.sol::Deploy.total", "writes_state")
        db.insert_transition("Lifecycle", "Open", "Closed", "Vault.sol::Vault.entry()")
        db.insert_transition("Lifecycle", "Open", "Closed", "scripts/Deploy.sol::Deploy.run()")

        real_load = mcp_server._load_metadata
        parsed = []

        def counting_load(raw):
            parsed.append(raw)
            return real_load(raw)

        monkeypatch.setattr(mcp_server, "_load_metadata", counting_load)

        summary = json.loads(mcp_server.cs_summary(db=tmp_db, exclude_research=True))

        assert summary["nodes"] == 2
        assert summary["edges"] == 1
        assert summary["transitions"] == 1
        assert summary["source_context_summary"] == {"production": 2}
        assert parsed == []

    def test_summary_reports_attack_surface_truncation(self, tmp_db):
        import mcp_server

        db = GraphDB(tmp_db)
        for i in range(4):
            func_id = f"Vault.sol::Vault.entry{i}()"
            state_id = f"Vault.sol::Vault.total{i}"
            db.insert_node(
                id=func_id,
                label=f"entry{i}",
                type="function",
                visibility="external",
                file="Vault.sol",
            )
            db.insert_node(
                id=state_id,
                label=f"total{i}",
                type="state_var",
                file="Vault.sol",
            )
            db.insert_edge(func_id, state_id, "writes_state")

        capped = json.loads(mcp_server.cs_summary(db=tmp_db, attack_surface=True, top=2))
        hidden_all = json.loads(mcp_server.cs_summary(db=tmp_db, attack_surface=True, top=0))

        assert capped["_summary"]["attack_surface"] == {
            "total": 4,
            "shown": 2,
            "truncated": True,
            "top": 2,
        }
        assert capped["_summary"]["truncated"] is True
        assert "Increase top" in capped["_warning"]

        assert hidden_all["_summary"]["attack_surface"] == {
            "total": 4,
            "shown": 0,
            "truncated": True,
            "top": 0,
        }

    def test_summary_retains_only_top_attack_surface_rows(self, tmp_db, monkeypatch):
        import mcp_server

        db = GraphDB(tmp_db)
        for i in range(30):
            func_id = f"Vault.sol::Vault.entry{i:02d}()"
            state_id = f"Vault.sol::Vault.total{i:02d}"
            db.insert_node(
                id=func_id,
                label=f"entry{i:02d}",
                type="function",
                visibility="external",
                file="Vault.sol",
            )
            db.insert_node(
                id=state_id,
                label=f"total{i:02d}",
                type="state_var",
                file="Vault.sol",
            )
            db.insert_edge(func_id, state_id, "writes_state")

        real_keep_sorted = mcp_server._keep_sorted_result
        buffer_sizes = []

        def tracking_keep_sorted(buffer, item, sort_key, limit):
            real_keep_sorted(buffer, item, sort_key, limit)
            buffer_sizes.append(len(buffer))

        monkeypatch.setattr(mcp_server, "_keep_sorted_result", tracking_keep_sorted)

        summary = json.loads(mcp_server.cs_summary(db=tmp_db, attack_surface=True, top=3))

        assert summary["_summary"]["attack_surface"] == {
            "total": 30,
            "shown": 3,
            "truncated": True,
            "top": 3,
        }
        assert [item["label"] for item in summary["attack_surface"]] == [
            "entry00",
            "entry01",
            "entry02",
        ]
        assert max(buffer_sizes) == 3

    def test_summary_attack_surface_uses_aggregate_health_counts(self, tmp_db, monkeypatch):
        import mcp_server

        db = GraphDB(tmp_db)
        for i in range(4):
            func_id = f"Vault.sol::Vault.entry{i}()"
            state_id = f"Vault.sol::Vault.total{i}"
            db.insert_node(
                id=func_id,
                label=f"entry{i}",
                type="function",
                visibility="external",
                file="Vault.sol",
            )
            db.insert_node(
                id=state_id,
                label=f"total{i}",
                type="state_var",
                file="Vault.sol",
            )
            db.insert_edge(func_id, state_id, "writes_state")
            db.insert_edge(func_id, f"Vault.sol::Vault.helper{i}()", "calls")
            db.insert_edge(f"Vault.sol::Vault.onlyOwner{i}", func_id, "guards")

        real_open = mcp_server._open_query_connection
        real_load = mcp_server._load_metadata
        statements = []
        parsed = []

        class CountingConnection:
            def __init__(self, conn):
                self._conn = conn

            def execute(self, sql, *args, **kwargs):
                normalized = " ".join(sql.split())
                statements.append(normalized)
                if normalized == "SELECT id, label, type, visibility, file, signature, metadata FROM nodes":
                    raise AssertionError("attack_surface cs_summary should not stream full node rows")
                if normalized == "SELECT source, target, relation FROM edges":
                    raise AssertionError("attack_surface cs_summary should not stream full edge rows")
                return self._conn.execute(sql, *args, **kwargs)

            def close(self):
                self._conn.close()

        monkeypatch.setattr(
            mcp_server,
            "_open_query_connection",
            lambda *args, **kwargs: CountingConnection(real_open(*args, **kwargs)),
        )

        def counting_load(raw):
            parsed.append(raw)
            return real_load(raw)

        monkeypatch.setattr(mcp_server, "_load_metadata", counting_load)

        summary = json.loads(mcp_server.cs_summary(db=tmp_db, attack_surface=True, top=2))

        assert summary["_summary"]["attack_surface"] == {
            "total": 4,
            "shown": 2,
            "truncated": True,
            "top": 2,
        }
        assert any("GROUP BY type" in sql for sql in statements)
        assert any("GROUP BY e.relation" in sql for sql in statements)
        assert any("WHERE type = 'function' AND visibility IN" in sql for sql in statements)
        assert any("e.relation IN" in sql and "JOIN nodes" in sql for sql in statements)
        assert any(
            "e.relation = 'writes_state'" in sql
            and "JOIN nodes" in sql
            and "GROUP BY e.source" in sql
            for sql in statements
        )
        assert parsed == []

    def test_summary_streams_rows_for_attack_surface(self, monkeypatch):
        import mcp_server

        node_rows = [
            {
                "id": "Vault.sol::Vault.entry()",
                "label": "entry",
                "type": "function",
                "visibility": "external",
                "file": "Vault.sol",
                "signature": "entry()",
                "metadata": json.dumps({"source_context": "production"}),
            },
            {
                "id": "Vault.sol::Vault.total",
                "label": "total",
                "type": "state_var",
                "visibility": "",
                "file": "Vault.sol",
                "signature": "",
                "metadata": json.dumps({"source_context": "production"}),
            },
        ]
        edge_rows = [
            {
                "source": "Vault.sol::Vault.entry()",
                "target": "Vault.sol::Vault.total",
                "relation": "writes_state",
            }
        ]
        class StreamingRows:
            def __init__(self, rows):
                self.rows = rows

            def __iter__(self):
                return iter(self.rows)

            def fetchall(self):
                raise AssertionError("cs_summary rows should stream")

        class SingleRow:
            def __init__(self, row=None):
                self.row = row

            def fetchone(self):
                return self.row

        class FakeConn:
            def execute(self, sql, params=()):
                normalized = " ".join(sql.split())
                if "FROM nodes" in normalized and "FROM graph_metadata" not in normalized:
                    return StreamingRows(node_rows)
                if "FROM edges" in normalized:
                    return StreamingRows(edge_rows)
                if "FROM state_transitions" in normalized:
                    return StreamingRows([{"function_id": "Vault.sol::Vault.entry()", "metadata": json.dumps({"source_context": "production"})}])
                if "FROM graph_metadata" in normalized:
                    return SingleRow()
                raise AssertionError(normalized)

            def close(self):
                pass

        monkeypatch.setattr(
            mcp_server,
            "_open_query_connection",
            lambda db_path, timeout_seconds: FakeConn(),
        )

        summary = json.loads(mcp_server.cs_summary(
            db="stream.db",
            attack_surface=True,
            top=1,
            exclude_research=True,
        ))

        assert summary["nodes"] == 2
        assert summary["edges"] == 1
        assert summary["transitions"] == 1
        assert summary["entry_points"] == 1
        assert summary["attack_surface"][0]["label"] == "entry"
        assert summary["_summary"]["attack_surface"] == {"total": 1, "shown": 1, "truncated": False, "top": 1}

    def test_summary_warns_on_empty_unbuilt_graph(self, tmp_path):
        import mcp_server

        db_path = tmp_path / "empty.db"
        db = GraphDB(str(db_path))

        summary = json.loads(mcp_server.cs_summary(db=db.db_path))

        assert summary["nodes"] == 0
        assert summary["edges"] == 0
        assert summary["build_info"] is None
        assert "cs_build" in summary["_warning"]
        assert summary["_next_steps"]

    def test_summary_missing_db_does_not_create_empty_graph(self, tmp_path):
        import mcp_server

        db_path = tmp_path / "missing.db"

        summary = json.loads(mcp_server.cs_summary(db=str(db_path)))

        assert "error" in summary
        assert summary["tool"] == "cs_summary"
        assert not db_path.exists()

    def test_audit_reports_truncated_section_totals_for_llm_context(self, tmp_db):
        import mcp_server

        db = GraphDB(tmp_db)
        for i in range(3):
            func_id = f"Vault{i}.sol::Vault{i}.set(uint256)"
            state_id = f"Vault{i}.sol::Vault{i}.total"
            db.insert_node(
                id=func_id,
                label=f"set{i}",
                type="function",
                visibility="external",
                file=f"Vault{i}.sol",
                line_start=i + 1,
            )
            db.insert_node(
                id=state_id,
                label="total",
                type="state_var",
                file=f"Vault{i}.sol",
            )
            db.insert_edge(func_id, state_id, "writes_state")

        audit = json.loads(mcp_server.cs_audit(db=tmp_db, top=1))
        sections = audit["_summary"]["sections"]

        assert audit["_summary"]["top"] == 1
        assert audit["_summary"]["truncated"] is True
        assert sections["attack_surface"] == {"total": 3, "shown": 1, "truncated": True}
        assert sections["critical_hotspots"] == {"total": 3, "shown": 1, "truncated": True}
        assert sections["access_control_gaps"] == {"total": 3, "shown": 1, "truncated": True}
        assert sections["silent_state_changes"] == {"total": 3, "shown": 1, "truncated": True}
        assert "attack_surface" in audit["_summary"]["truncated_sections"]
        assert "cs_hotspots" in audit["_summary"]["_hint"]

    def test_audit_retains_only_top_ranked_sections(self, tmp_db, monkeypatch):
        import mcp_server

        db = GraphDB(tmp_db)
        for i in range(20):
            func_id = f"Vault{i}.sol::Vault{i}.set(uint256)"
            state_id = f"Vault{i}.sol::Vault{i}.total"
            db.insert_node(
                id=func_id,
                label=f"set{i}",
                type="function",
                visibility="external",
                file=f"Vault{i}.sol",
                line_start=i + 1,
            )
            db.insert_node(
                id=state_id,
                label="total",
                type="state_var",
                file=f"Vault{i}.sol",
            )
            db.insert_edge(func_id, state_id, "writes_state")

        real_heappush = mcp_server.heapq.heappush
        real_heapreplace = mcp_server.heapq.heapreplace
        heap_sizes = []

        def tracking_heappush(heap, item):
            real_heappush(heap, item)
            heap_sizes.append(len(heap))

        def tracking_heapreplace(heap, item):
            result = real_heapreplace(heap, item)
            heap_sizes.append(len(heap))
            return result

        monkeypatch.setattr(mcp_server.heapq, "heappush", tracking_heappush)
        monkeypatch.setattr(mcp_server.heapq, "heapreplace", tracking_heapreplace)

        audit = json.loads(mcp_server.cs_audit(db=tmp_db, top=2))
        sections = audit["_summary"]["sections"]

        assert sections["attack_surface"] == {"total": 20, "shown": 2, "truncated": True}
        assert sections["critical_hotspots"] == {"total": 20, "shown": 2, "truncated": True}
        assert [item["label"] for item in audit["attack_surface"]] == ["set0", "set1"]
        assert [item["function"] for item in audit["critical_hotspots"]] == ["set0", "set1"]
        assert max(heap_sizes) == 2

    def test_audit_omits_attack_surface_metadata_by_default(self, tmp_db):
        import mcp_server

        db = GraphDB(tmp_db)
        func_id = "Vault.sol::Vault.set(uint256)"
        state_id = "Vault.sol::Vault.total"
        db.insert_node(
            id=func_id,
            label="set",
            type="function",
            visibility="external",
            file="Vault.sol",
            signature="function set(uint256 x) external",
            metadata=json.dumps({
                "source_context": "production",
                "large": ["x"] * 50,
            }),
        )
        db.insert_node(
            id=state_id,
            label="total",
            type="state_var",
            file="Vault.sol",
        )
        db.insert_edge(func_id, state_id, "writes_state")

        compact = json.loads(mcp_server.cs_audit(db=tmp_db, top=1))
        detailed = json.loads(mcp_server.cs_audit(db=tmp_db, top=1, include_metadata=True))

        assert compact["_summary"]["include_metadata"] is False
        assert compact["attack_surface"][0]["label"] == "set"
        assert "metadata" not in compact["attack_surface"][0]
        assert detailed["_summary"]["include_metadata"] is True
        assert json.loads(detailed["attack_surface"][0]["metadata"])["large"] == ["x"] * 50

    def test_audit_skips_neutral_function_metadata_parses(self, tmp_db, monkeypatch):
        import mcp_server

        db = GraphDB(tmp_db)
        entry_id = "Vault.sol::Vault.entry(uint256)"
        state_id = "Vault.sol::Vault.total"
        neutral_metadata = json.dumps({"large": ["x"] * 20})
        risk_metadata = json.dumps({"reentrancy_risk": True, "large": ["x"] * 20})
        db.insert_node(
            id=entry_id,
            label="entry",
            type="function",
            visibility="external",
            file="Vault.sol",
            signature="function entry(uint256 amount) external",
            metadata=neutral_metadata,
        )
        db.insert_node(
            id=state_id,
            label="total",
            type="state_var",
            file="Vault.sol",
        )
        db.insert_edge(entry_id, state_id, "writes_state")
        db.insert_node(
            id="Vault.sol::Vault.reenter()",
            label="reenter",
            type="function",
            visibility="internal",
            file="Vault.sol",
            metadata=risk_metadata,
        )
        for i in range(30):
            db.insert_node(
                id=f"Helper{i}.sol::Helper{i}.noop()",
                label=f"noop{i}",
                type="function",
                visibility="internal",
                file=f"Helper{i}.sol",
                metadata=neutral_metadata,
            )

        real_load = mcp_server._load_metadata
        parsed = []

        def counting_load(raw):
            parsed.append(raw)
            return real_load(raw)

        monkeypatch.setattr(mcp_server, "_load_metadata", counting_load)

        audit = json.loads(mcp_server.cs_audit(db=tmp_db, top=10))

        assert audit["source_context_summary"] == {"production": 32}
        assert audit["detections"] == {"reentrancy_risk": 1}
        assert audit["hotspot_summary"]["total_scored"] == 2
        assert audit["access_gaps_total"] == 1
        assert audit["silent_total"] == 1
        assert audit["dead_code"]["dead_internal_total"] == 31
        assert parsed == [risk_metadata]

    def test_audit_retains_only_top_append_sections(self, tmp_db, monkeypatch):
        import mcp_server

        db = GraphDB(tmp_db)
        for i in range(12):
            func_id = f"Vault{i}.sol::Vault{i}.set(uint256)"
            state_id = f"Vault{i}.sol::Vault{i}.total"
            db.insert_node(
                id=func_id,
                label=f"set{i}",
                type="function",
                visibility="external",
                file=f"Vault{i}.sol",
                line_start=i + 1,
                metadata=json.dumps({"reentrancy_risk": True}),
            )
            db.insert_node(
                id=state_id,
                label="total",
                type="state_var",
                file=f"Vault{i}.sol",
            )
            db.insert_edge(func_id, state_id, "writes_state")
            db.insert_node(
                id=f"Vault{i}.sol::Vault{i}.helper()",
                label=f"helper{i}",
                type="function",
                visibility="internal",
                file=f"Vault{i}.sol",
                line_start=100 + i,
            )

        real_append_top = mcp_server._append_top
        retained_sizes = []

        def tracking_append_top(items, item, total, top):
            updated = real_append_top(items, item, total, top)
            retained_sizes.append(len(items))
            return updated

        monkeypatch.setattr(mcp_server, "_append_top", tracking_append_top)

        audit = json.loads(mcp_server.cs_audit(db=tmp_db, top=2))
        sections = audit["_summary"]["sections"]

        assert sections["reentrancy"] == {"total": 12, "shown": 2, "truncated": True}
        assert sections["access_control_gaps"] == {"total": 12, "shown": 2, "truncated": True}
        assert sections["dead_code.dead_internal"] == {"total": 12, "shown": 2, "truncated": True}
        assert sections["dead_code.direct_entry_points"] == {"total": 12, "shown": 2, "truncated": True}
        assert audit["access_gaps_total"] == 12
        assert audit["dead_code"]["dead_internal_total"] == 12
        assert audit["dead_code"]["direct_entry_points_total"] == 12
        assert max(retained_sizes) == 2

    def test_audit_retains_only_top_sorted_sections(self, tmp_db, monkeypatch):
        import mcp_server

        db = GraphDB(tmp_db)
        sink_id = "Vault.sol::Vault.transfer(address,uint256)"
        db.insert_node(
            id=sink_id,
            label="transfer",
            type="function",
            visibility="internal",
            file="Vault.sol",
            metadata=json.dumps({"is_sink": True, "sink_type": "fund_transfer"}),
        )
        db.insert_node(
            id="Vault.sol::Vault.total",
            label="total",
            type="state_var",
            file="Vault.sol",
        )
        for i in range(12):
            func_id = f"Vault{i}.sol::Vault{i}.entry(uint256)"
            db.insert_node(
                id=func_id,
                label=f"entry{i:02d}",
                type="function",
                visibility="external",
                file=f"Vault{i}.sol",
                line_start=i + 1,
                signature="function entry(uint256 amount) external",
            )
            db.insert_edge(func_id, sink_id, "calls")
            db.insert_edge(func_id, "Vault.sol::Vault.total", "writes_state")

        real_keep_sorted = mcp_server._keep_sorted_result
        taint_sizes = []
        silent_sizes = []

        def tracking_keep_sorted(buffer, item, sort_key, limit):
            real_keep_sorted(buffer, item, sort_key, limit)
            if isinstance(item, dict) and "entry" in item:
                taint_sizes.append(len(buffer))
            if isinstance(item, dict) and item.get("function", "").startswith("entry"):
                silent_sizes.append(len(buffer))

        monkeypatch.setattr(mcp_server, "_keep_sorted_result", tracking_keep_sorted)

        audit = json.loads(mcp_server.cs_audit(db=tmp_db, top=2))
        sections = audit["_summary"]["sections"]

        assert sections["taint_paths"] == {"total": 12, "shown": 2, "truncated": True}
        assert sections["silent_state_changes"] == {"total": 12, "shown": 2, "truncated": True}
        assert audit["taint_summary"] == {"total": 12, "high_risk": 12}
        assert audit["silent_total"] == 12
        assert [item["entry"] for item in audit["taint_paths"]] == ["entry00", "entry01"]
        assert [item["function"] for item in audit["silent_state_changes"]] == ["entry00", "entry01"]
        assert max(taint_sizes) == 2
        assert max(silent_sizes) == 2

    def test_keep_sorted_result_does_not_sort_on_each_overflow(self):
        import mcp_server

        class NoSortList(list):
            def sort(self, *args, **kwargs):
                raise AssertionError("_keep_sorted_result should not sort the retained buffer")

        buffer = NoSortList()
        for key in (5, 1, 3, 2, 4):
            mcp_server._keep_sorted_result(buffer, {"key": key}, (key,), 3)

        assert len(buffer) == 3
        assert [item["key"] for item in mcp_server._sorted_results(buffer)] == [1, 2, 3]

    def test_forward_reachable_nodes_reuses_shared_callee_cache(self):
        import mcp_server

        class CountingAdj(dict):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self.lookups = {}

            def get(self, key, default=None):
                self.lookups[key] = self.lookups.get(key, 0) + 1
                return super().get(key, default)

        adj = CountingAdj({
            "entry0": ["shared"],
            "entry1": ["shared"],
            "shared": ["leaf"],
            "leaf": [],
        })
        cache = {}

        first = mcp_server._forward_reachable_nodes(adj, "entry0", cache)
        second = mcp_server._forward_reachable_nodes(adj, "entry1", cache)

        assert first == {"entry0", "shared", "leaf"}
        assert second == {"entry1", "shared", "leaf"}
        assert cache["shared"] == {"shared", "leaf"}
        assert adj.lookups["shared"] == 1

    def test_audit_taint_summary_reports_full_total(self, tmp_db):
        import mcp_server

        db = GraphDB(tmp_db)
        db.insert_node(
            id="Vault.sol::Vault.transfer(address,uint256)",
            label="transfer",
            type="function",
            file="Vault.sol",
            metadata=json.dumps({"is_sink": True, "sink_type": "fund_transfer"}),
        )
        for i in range(5):
            entry_id = f"Vault.sol::Vault.entry{i}(uint256)"
            db.insert_node(
                id=entry_id,
                label=f"entry{i}",
                type="function",
                visibility="external",
                file="Vault.sol",
                signature=f"function entry{i}(uint256 amount) external",
            )
            db.insert_edge(entry_id, "Vault.sol::Vault.transfer(address,uint256)", "calls")

        audit = json.loads(mcp_server.cs_audit(db=tmp_db, top=1))

        assert len(audit["taint_paths"]) == 1
        assert audit["taint_summary"]["total"] == 5
        assert audit["_summary"]["sections"]["taint_paths"] == {
            "total": 5,
            "shown": 1,
            "truncated": True,
        }

    def test_audit_uses_bounded_queries_for_reentrancy_and_sinks(self, tmp_db, monkeypatch):
        import mcp_server

        db = GraphDB(tmp_db)
        sink_id = "Vault.sol::Vault.transfer(address,uint256)"
        db.insert_node(
            id=sink_id,
            label="transfer",
            type="function",
            file="Vault.sol",
            metadata=json.dumps({"is_sink": True, "sink_type": "fund_transfer"}),
        )
        for i in range(80):
            func_id = f"Vault.sol::Vault.entry{i}(uint256)"
            state_id = f"Vault.sol::Vault.total{i}"
            guard_id = f"Vault.sol::Vault.onlyRole{i}"
            db.insert_node(
                id=func_id,
                label=f"entry{i}",
                type="function",
                visibility="external",
                file="Vault.sol",
                signature=f"function entry{i}(uint256 amount) external",
                metadata=json.dumps({"reentrancy_risk": True}),
            )
            db.insert_node(
                id=state_id,
                label=f"total{i}",
                type="state_var",
                file="Vault.sol",
            )
            db.insert_node(
                id=guard_id,
                label=f"onlyRole{i}",
                type="guard",
                file="Vault.sol",
            )
            db.insert_edge(func_id, state_id, "writes_state")
            db.insert_edge(func_id, sink_id, "calls")
            db.insert_edge(guard_id, func_id, "guards")

        real_open = mcp_server._open_query_connection
        statements = []

        class CountingConnection:
            def __init__(self, conn):
                self._conn = conn

            def execute(self, sql, *args, **kwargs):
                statements.append(sql)
                return self._conn.execute(sql, *args, **kwargs)

            def close(self):
                self._conn.close()

        def counting_open(*args, **kwargs):
            return CountingConnection(real_open(*args, **kwargs))

        monkeypatch.setattr(mcp_server, "_open_query_connection", counting_open)

        audit = json.loads(mcp_server.cs_audit(db=tmp_db, top=10))

        assert audit["_summary"]["sections"]["reentrancy"] == {
            "total": 80,
            "shown": 10,
            "truncated": True,
        }
        assert audit["reentrancy"][0]["modifiers"]
        assert audit["taint_summary"]["total"] == 80
        assert len(statements) <= 20
        assert not any(
            "WHERE e.target = ? AND e.relation = 'guards'" in " ".join(sql.split())
            for sql in statements
        )

    def test_audit_scopes_external_call_counts_to_included_functions(self, tmp_db, monkeypatch):
        import mcp_server

        db = GraphDB(tmp_db)
        prod_id = "prod/Vault.sol::Vault.set(uint256)"
        script_id = "scripts/Deploy.sol::Deploy.run(uint256)"
        for func_id, context in ((prod_id, "production"), (script_id, "script")):
            db.insert_node(
                id=func_id,
                label="set" if context == "production" else "run",
                type="function",
                visibility="external",
                file=func_id.split("::", 1)[0],
                metadata=json.dumps({"source_context": context}),
            )
            db.insert_edge(
                func_id,
                f"{func_id}::_unresolved",
                "calls",
                attributes=json.dumps({"unresolved": True}),
            )
            db.insert_node(
                id=f"{func_id}::total",
                label="total",
                type="state_var",
                file=func_id.split("::", 1)[0],
                metadata=json.dumps({"source_context": context}),
            )
            db.insert_edge(func_id, f"{func_id}::total", "writes_state")
            db.insert_node(
                id=f"{func_id}::onlyOwner",
                label="onlyOwner",
                type="modifier",
                file=func_id.split("::", 1)[0],
                metadata=json.dumps({"source_context": context}),
            )
            db.insert_edge(f"{func_id}::onlyOwner", func_id, "guards")
            db.insert_node(
                id=f"{func_id}::Updated",
                label="Updated",
                type="event",
                file=func_id.split("::", 1)[0],
                metadata=json.dumps({"source_context": context}),
            )
            db.insert_edge(func_id, f"{func_id}::Updated", "emits_event")

        real_open = mcp_server._open_query_connection
        real_external_counts = mcp_server._external_call_counts
        calls = []
        statements = []

        class CountingConnection:
            def __init__(self, conn):
                self._conn = conn

            def execute(self, sql, *args, **kwargs):
                statements.append((" ".join(sql.split()), args))
                return self._conn.execute(sql, *args, **kwargs)

            def close(self):
                self._conn.close()

        def tracking_external_counts(conn, include_cpi=False, source_ids=None):
            calls.append({
                "include_cpi": include_cpi,
                "source_ids": set(source_ids or ()),
            })
            return real_external_counts(conn, include_cpi=include_cpi, source_ids=source_ids)

        monkeypatch.setattr(
            mcp_server,
            "_open_query_connection",
            lambda *args, **kwargs: CountingConnection(real_open(*args, **kwargs)),
        )
        monkeypatch.setattr(mcp_server, "_external_call_counts", tracking_external_counts)

        audit = json.loads(mcp_server.cs_audit(db=tmp_db, top=10, exclude_research=True))

        assert calls == [{"include_cpi": True, "source_ids": {prod_id}}]
        assert audit["hotspot_summary"]["total_scored"] == 1
        assert audit["critical_hotspots"][0]["function"] == "set"
        scoped_preloads = [
            (sql, args[0] if args else ())
            for sql, args in statements
            if "source IN" in sql or "e.target IN" in sql
        ]
        assert any("relation = ?" in sql and params == (prod_id, "writes_state") for sql, params in scoped_preloads)
        assert any("relation = ?" in sql and params == (prod_id, "emits_event") for sql, params in scoped_preloads)
        assert any("e.target IN" in sql and params == (prod_id,) for sql, params in scoped_preloads)
        assert all(script_id not in params for _, params in scoped_preloads)

    def test_audit_filters_research_before_preload_parse(self, tmp_db, monkeypatch):
        import mcp_server

        db = GraphDB(tmp_db)
        prod_meta = json.dumps({
            "source_context": "production",
            "no_input_validation": True,
        })
        script_meta = json.dumps({
            "source_context": "script",
            "no_input_validation": True,
        })
        db.insert_node(
            id="prod/Vault.sol::Vault.set(uint256)",
            label="set",
            type="function",
            visibility="external",
            file="prod/Vault.sol",
            metadata=prod_meta,
        )
        db.insert_node(
            id="scripts/Deploy.sol::Deploy.run(uint256)",
            label="run",
            type="function",
            visibility="external",
            file="scripts/Deploy.sol",
            metadata=script_meta,
        )

        real_load = mcp_server._load_metadata
        parsed = []

        def counting_load(raw):
            parsed.append(raw)
            return real_load(raw)

        monkeypatch.setattr(mcp_server, "_load_metadata", counting_load)

        audit = json.loads(mcp_server.cs_audit(db=tmp_db, top=10, exclude_research=True))

        assert audit["source_context_summary"] == {"production": 1}
        assert parsed.count(prod_meta) == 1
        assert parsed.count(script_meta) == 0

    def test_audit_and_hotspots_surface_source_context(self, tmp_path, tmp_db):
        import mcp_server

        repo = tmp_path / "repo"
        repo.mkdir()
        scripts = repo / "scripts"
        scripts.mkdir()
        (repo / "Vault.sol").write_text(
            "pragma solidity ^0.8.0; contract Vault { uint256 public total; function set(uint256 x) external { total = x; } }"
        )
        (scripts / "Deploy.s.sol").write_text(
            "pragma solidity ^0.8.0; contract DeployScript { uint256 public total; function run(uint256 x) external { total = x; } }"
        )

        indexer = Indexer(str(repo), include_research=True)
        indexer.index(tmp_db)

        audit = json.loads(mcp_server.cs_audit(db=tmp_db, top=10))
        assert audit["source_context_summary"]["production"] >= 1
        assert audit["source_context_summary"]["script"] >= 1

        hotspots = json.loads(mcp_server.cs_hotspots(db=tmp_db, top=20))
        contexts = {item["function"]: item["source_context"] for item in hotspots["hotspots"]}
        assert contexts["set"] == "production"
        assert contexts["run"] == "script"

        prod_audit = json.loads(mcp_server.cs_audit(db=tmp_db, top=10, exclude_research=True))
        assert prod_audit["query_scope"] == "production_only"
        assert "script" not in prod_audit["source_context_summary"]
        prod_audit_hotspots = {item["function"] for item in prod_audit.get("critical_hotspots", [])}
        assert "run" not in prod_audit_hotspots
        assert "set" in prod_audit_hotspots

        prod_hotspots = json.loads(mcp_server.cs_hotspots(db=tmp_db, top=20, exclude_research=True))
        prod_contexts = {item["function"]: item["source_context"] for item in prod_hotspots["hotspots"]}
        assert "run" not in prod_contexts
        assert prod_contexts["set"] == "production"
        assert prod_hotspots["_summary"]["query_scope"] == "production_only"

    def test_audit_exclude_research_filters_top_level_stats(self, tmp_db):
        import mcp_server

        db = GraphDB(tmp_db)
        for prefix, source_context in (("prod", "production"), ("script", "script")):
            func_id = f"{prefix}/Vault.sol::Vault.set(uint256)"
            state_id = f"{prefix}/Vault.sol::Vault.total"
            guard_id = f"{prefix}/Vault.sol::Vault.onlyOwner"
            sink_id = f"{prefix}/Vault.sol::Vault.danger"
            meta = json.dumps({"source_context": source_context})
            db.insert_node(
                id=func_id,
                label="set",
                type="function",
                visibility="external",
                file=f"{prefix}/Vault.sol",
                metadata=meta,
            )
            db.insert_node(
                id=state_id,
                label="total",
                type="state_var",
                file=f"{prefix}/Vault.sol",
                metadata=meta,
            )
            db.insert_node(
                id=guard_id,
                label="onlyOwner",
                type="modifier",
                file=f"{prefix}/Vault.sol",
                metadata=meta,
            )
            db.insert_node(
                id=sink_id,
                label="danger",
                type="sink",
                file=f"{prefix}/Vault.sol",
                metadata=json.dumps({"source_context": source_context, "is_sink": True}),
            )
            db.insert_edge(func_id, state_id, "writes_state")
            db.insert_edge(guard_id, func_id, "guards")
            db.insert_transition("Lifecycle", "Open", "Closed", func_id)

        audit = json.loads(mcp_server.cs_audit(db=tmp_db, top=10))
        prod_audit = json.loads(mcp_server.cs_audit(db=tmp_db, top=10, exclude_research=True))

        assert audit["stats"]["nodes"] == 8
        assert audit["stats"]["edges"] == 4
        assert audit["stats"]["functions"] == 2
        assert audit["stats"]["state_vars"] == 2
        assert audit["stats"]["entry_points"] == 2
        assert audit["stats"]["guarded_entry_points"] == 2
        assert audit["stats"]["sinks"] == 2
        assert audit["stats"]["transitions"] == 2

        assert prod_audit["stats"]["nodes"] == 4
        assert prod_audit["stats"]["edges"] == 2
        assert prod_audit["stats"]["functions"] == 1
        assert prod_audit["stats"]["state_vars"] == 1
        assert prod_audit["stats"]["entry_points"] == 1
        assert prod_audit["stats"]["guarded_entry_points"] == 1
        assert prod_audit["stats"]["sinks"] == 1
        assert prod_audit["stats"]["transitions"] == 1
        assert prod_audit["stats"]["node_types"] == {
            "function": 1,
            "modifier": 1,
            "sink": 1,
            "state_var": 1,
        }
        assert prod_audit["stats"]["edge_relations"] == {
            "guards": 1,
            "writes_state": 1,
        }
        assert audit["sink_summary"]["by_type"] == {"unknown": 2}
        assert prod_audit["sink_summary"]["by_type"] == {"unknown": 1}

    def test_reverse_reachable_nodes_reuses_shared_caller_cache(self):
        import mcp_server

        class CountingAdj(dict):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self.accesses = {}

            def get(self, key, default=None):
                self.accesses[key] = self.accesses.get(key, 0) + 1
                return super().get(key, default)

        reverse_adj = CountingAdj({
            "sinkA": ["shared"],
            "sinkB": ["shared"],
            "shared": ["entry"],
            "entry": [],
        })
        cache = {}

        first = mcp_server._reverse_reachable_nodes(reverse_adj, "sinkA", cache)
        second = mcp_server._reverse_reachable_nodes(reverse_adj, "sinkB", cache)

        assert first == {"sinkA", "shared", "entry"}
        assert second == {"sinkB", "shared", "entry"}
        assert reverse_adj.accesses["shared"] == 1
        assert reverse_adj.accesses["entry"] == 1

    def test_audit_sink_summary_counts_shared_reachable_functions_once(self, tmp_db):
        import mcp_server

        db = GraphDB(tmp_db)
        for fn_id, label in (
            ("Vault.sol::Vault.entry(uint256)", "entry"),
            ("Vault.sol::Vault.route(uint256)", "route"),
            ("Vault.sol::Vault.sinkA(uint256)", "sinkA"),
            ("Vault.sol::Vault.sinkB(uint256)", "sinkB"),
        ):
            metadata = {"source_context": "production"}
            if label.startswith("sink"):
                metadata.update({"is_sink": True, "sink_type": "fund_transfer"})
            db.insert_node(
                id=fn_id,
                label=label,
                type="function",
                visibility="external" if label == "entry" else "internal",
                file="Vault.sol",
                signature=f"function {label}(uint256 amount)",
                metadata=json.dumps(metadata),
            )
        db.insert_edge("Vault.sol::Vault.entry(uint256)", "Vault.sol::Vault.route(uint256)", "calls")
        db.insert_edge("Vault.sol::Vault.route(uint256)", "Vault.sol::Vault.sinkA(uint256)", "calls")
        db.insert_edge("Vault.sol::Vault.route(uint256)", "Vault.sol::Vault.sinkB(uint256)", "calls")

        audit = json.loads(mcp_server.cs_audit(db=tmp_db, top=10))

        assert audit["sink_summary"]["by_type"] == {"fund_transfer": 2}
        assert audit["sink_summary"]["reachable_functions"] == {"fund_transfer": 4}

    def test_hotspots_do_not_mark_inline_role_guard_as_no_access_control(self, tmp_path, tmp_db):
        import mcp_server

        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "Vault.sol").write_text(
            "pragma solidity ^0.8.0;\n"
            "contract Vault {\n"
            "    address public owner;\n"
            "    uint256 public total;\n"
            "    constructor() { owner = msg.sender; }\n"
            "    function set(uint256 x) external {\n"
            "        require(msg.sender == owner, \"owner\");\n"
            "        total = x;\n"
            "    }\n"
            "}\n"
        )

        indexer = Indexer(str(repo))
        indexer.index(tmp_db)

        hotspots = json.loads(mcp_server.cs_hotspots(db=tmp_db, top=20))
        set_rows = [item for item in hotspots["hotspots"] if item["function"] == "set"]
        assert set_rows
        assert "no_access_control" not in set_rows[0]["reasons"]

    def test_scanners_filter_research_findings_at_query_time(self, tmp_path, tmp_db):
        import mcp_server

        repo = tmp_path / "repo"
        repo.mkdir()
        scripts = repo / "scripts"
        scripts.mkdir()
        (repo / "Vault.sol").write_text(
            "pragma solidity ^0.8.0;\n"
            "contract Vault {\n"
            "    function live(uint256 deadline) external view returns (bool) {\n"
            "        return block.timestamp < deadline;\n"
            "    }\n"
            "}\n"
        )
        (scripts / "Deploy.sol").write_text(
            "pragma solidity ^0.8.0;\n"
            "contract DeployScript {\n"
            "    function scripted(uint256 deadline) external view returns (bool) {\n"
            "        return block.timestamp < deadline;\n"
            "    }\n"
            "}\n"
        )
        (repo / "ops.py").write_text(
            "import subprocess\n\n"
            "def run_live(cmd):\n"
            "    return subprocess.run(cmd, shell=True)\n"
        )
        (scripts / "helper.py").write_text(
            "import subprocess\n\n"
            "def run_script(cmd):\n"
            "    return subprocess.run(cmd, shell=True)\n"
        )

        indexer = Indexer(str(repo), include_research=True)
        indexer.index(tmp_db)

        defi = json.loads(mcp_server.cs_defi(db=tmp_db, category="timestamp"))
        defi_contexts = {item["function"]: item["source_context"] for item in defi["timestamp_dependence"]}
        assert defi_contexts["live"] == "production"
        assert defi_contexts["scripted"] == "script"
        assert defi["_summary"]["query_scope"] == "all_sources"

        prod_defi = json.loads(mcp_server.cs_defi(db=tmp_db, category="timestamp", exclude_research=True))
        prod_defi_contexts = {item["function"]: item["source_context"] for item in prod_defi["timestamp_dependence"]}
        assert prod_defi_contexts == {"live": "production"}
        assert prod_defi["_summary"]["query_scope"] == "production_only"

        unsafe = json.loads(mcp_server.cs_unsafe(db=tmp_db, category="command"))
        unsafe_contexts = {item["function"]: item["source_context"] for item in unsafe["command_execution"]}
        assert unsafe_contexts["run_live"] == "production"
        assert unsafe_contexts["run_script"] == "script"
        assert unsafe["_summary"]["query_scope"] == "all_sources"

        prod_unsafe = json.loads(mcp_server.cs_unsafe(db=tmp_db, category="command", exclude_research=True))
        prod_unsafe_contexts = {item["function"]: item["source_context"] for item in prod_unsafe["command_execution"]}
        assert prod_unsafe_contexts == {"run_live": "production"}
        assert prod_unsafe["_summary"]["query_scope"] == "production_only"

    def test_scanners_cap_category_results_for_llm_context(self, tmp_db):
        import mcp_server

        db = GraphDB(tmp_db)
        for i in range(5):
            db.insert_node(
                id=f"Vault{i}.sol::Vault{i}.checkDeadline(uint256)",
                label=f"checkDeadline{i}",
                type="function",
                visibility="external",
                file=f"Vault{i}.sol",
                line_start=i + 1,
                metadata=json.dumps({
                    "timestamp_dependence": [{"line": i + 1, "expr": "block.timestamp < deadline"}],
                    "source_context": "production",
                }),
            )
            db.insert_node(
                id=f"ops{i}.py::run_cmd",
                label=f"run_cmd_{i}",
                type="function",
                visibility="",
                file=f"ops{i}.py",
                line_start=i + 1,
                metadata=json.dumps({
                    "command_injection_risk": [{"line": i + 1, "call": "subprocess.run"}],
                    "language": "python",
                    "source_context": "production",
                }),
            )

        capped_defi = json.loads(mcp_server.cs_defi(db=tmp_db, category="timestamp", max_per_category=2))
        uncapped_defi = json.loads(mcp_server.cs_defi(db=tmp_db, category="timestamp", max_per_category=0))
        capped_unsafe = json.loads(mcp_server.cs_unsafe(db=tmp_db, category="command", max_per_category=2))
        uncapped_unsafe = json.loads(mcp_server.cs_unsafe(db=tmp_db, category="command", max_per_category=0))

        assert len(capped_defi["timestamp_dependence"]) == 2
        assert capped_defi["_summary"]["total_findings"] == 5
        assert capped_defi["_summary"]["shown_findings"] == 2
        assert capped_defi["_summary"]["category_totals"] == {"timestamp_dependence": 5}
        assert capped_defi["_summary"]["truncated_categories"]["timestamp_dependence"]["hidden"] == 3
        assert capped_defi["_summary"]["max_per_category"] == 2
        assert len(uncapped_defi["timestamp_dependence"]) == 5
        assert uncapped_defi["_summary"]["truncated"] is False

        assert len(capped_unsafe["command_execution"]) == 2
        assert capped_unsafe["_summary"]["total_findings"] == 5
        assert capped_unsafe["_summary"]["shown_findings"] == 2
        assert capped_unsafe["_summary"]["category_totals"] == {"command_execution": 5}
        assert capped_unsafe["_summary"]["truncated_categories"]["command_execution"]["hidden"] == 3
        assert capped_unsafe["_summary"]["max_per_category"] == 2
        assert len(uncapped_unsafe["command_execution"]) == 5
        assert uncapped_unsafe["_summary"]["truncated"] is False

    def test_scanners_index_only_capped_category_rows(self, tmp_db, monkeypatch):
        import mcp_server

        db = GraphDB(tmp_db)
        for i in range(12):
            db.insert_node(
                id=f"Vault{i}.sol::Vault{i}.checkDeadline(uint256)",
                label=f"checkDeadline{i}",
                type="function",
                visibility="external",
                file=f"Vault{i}.sol",
                line_start=i + 1,
                metadata=json.dumps({
                    "timestamp_dependence": [{"line": i + 1}],
                    "source_context": "production",
                }),
            )
            db.insert_node(
                id=f"ops{i}.py::run_cmd",
                label=f"run_cmd_{i}",
                type="function",
                file=f"ops{i}.py",
                line_start=i + 1,
                metadata=json.dumps({
                    "command_injection_risk": [{"line": i + 1}],
                    "language": "python",
                    "source_context": "production",
                }),
            )

        real_index = mcp_server._metadata_rows_by_key
        snapshots = []

        def tracking_index(rows, keys, exclude_research, max_per_key=0):
            seen_labels = []

            def tracked_rows():
                for row in rows:
                    seen_labels.append(row["label"])
                    yield row

            indexed, totals = real_index(tracked_rows(), keys, exclude_research, max_per_key)
            snapshots.append({
                "keys": keys,
                "max_per_key": max_per_key,
                "seen_labels": seen_labels,
                "sizes": {key: len(values) for key, values in indexed.items() if values},
                "totals": {key: total for key, total in totals.items() if total},
            })
            return indexed, totals

        monkeypatch.setattr(mcp_server, "_metadata_rows_by_key", tracking_index)

        defi = json.loads(mcp_server.cs_defi(db=tmp_db, category="timestamp", max_per_category=3))
        unsafe = json.loads(mcp_server.cs_unsafe(db=tmp_db, category="command", max_per_category=3))

        assert defi["_summary"]["category_totals"] == {"timestamp_dependence": 12}
        assert unsafe["_summary"]["category_totals"] == {"command_execution": 12}
        assert snapshots[0]["keys"] == ["timestamp_dependence"]
        assert snapshots[0]["max_per_key"] == 3
        assert len(snapshots[0]["seen_labels"]) == 12
        assert all(label.startswith("checkDeadline") for label in snapshots[0]["seen_labels"])
        assert snapshots[0]["sizes"] == {"timestamp_dependence": 3}
        assert snapshots[0]["totals"] == {"timestamp_dependence": 12}
        assert snapshots[1]["keys"] == ["command_injection_risk"]
        assert snapshots[1]["max_per_key"] == 3
        assert len(snapshots[1]["seen_labels"]) == 12
        assert all(label.startswith("run_cmd_") for label in snapshots[1]["seen_labels"])
        assert snapshots[1]["sizes"] == {"command_injection_risk": 3}
        assert snapshots[1]["totals"] == {"command_injection_risk": 12}

    def test_scanners_parse_only_retained_all_source_rows(self, tmp_db, monkeypatch):
        import mcp_server

        db = GraphDB(tmp_db)
        defi_metadata = []
        unsafe_metadata = []
        for i in range(12):
            raw = json.dumps({
                "timestamp_dependence": [{"line": i + 1}],
                "large": ["x"] * 20,
            })
            defi_metadata.append(raw)
            db.insert_node(
                id=f"Vault{i}.sol::Vault{i}.checkDeadline(uint256)",
                label=f"checkDeadline{i}",
                type="function",
                visibility="external",
                file=f"Vault{i}.sol",
                line_start=i + 1,
                metadata=raw,
            )
            raw = json.dumps({
                "command_injection_risk": [{"line": i + 1}],
                "large": ["x"] * 20,
            })
            unsafe_metadata.append(raw)
            db.insert_node(
                id=f"ops{i}.py::run_cmd",
                label=f"run_cmd_{i}",
                type="function",
                file=f"ops{i}.py",
                line_start=i + 1,
                metadata=raw,
            )

        real_load = mcp_server._load_metadata
        parsed = []

        def counting_load(raw):
            parsed.append(raw)
            return real_load(raw)

        monkeypatch.setattr(mcp_server, "_load_metadata", counting_load)

        defi = json.loads(mcp_server.cs_defi(db=tmp_db, category="timestamp", max_per_category=3))
        assert defi["_summary"]["category_totals"] == {"timestamp_dependence": 12}
        assert len(defi["timestamp_dependence"]) == 3
        assert parsed == [defi_metadata[i] for i in (0, 1, 10)]

        parsed.clear()
        unsafe = json.loads(mcp_server.cs_unsafe(db=tmp_db, category="command", max_per_category=3))
        assert unsafe["_summary"]["category_totals"] == {"command_execution": 12}
        assert len(unsafe["command_execution"]) == 3
        assert parsed == [unsafe_metadata[i] for i in (0, 1, 10)]

    def test_scanners_parse_only_retained_production_rows(self, tmp_db, monkeypatch):
        import mcp_server

        db = GraphDB(tmp_db)
        defi_metadata = []
        unsafe_metadata = []
        for i in range(8):
            raw = json.dumps({
                "timestamp_dependence": [{"line": i + 1}],
                "source_context": "production",
                "large": ["x"] * 20,
            })
            defi_metadata.append(raw)
            db.insert_node(
                id=f"contracts/Vault{i}.sol::Vault{i}.checkDeadline(uint256)",
                label=f"checkDeadline{i}",
                type="function",
                visibility="external",
                file=f"contracts/Vault{i}.sol",
                line_start=i + 1,
                metadata=raw,
            )
            db.insert_node(
                id=f"scripts/Vault{i}.sol::Vault{i}.checkDeadline(uint256)",
                label=f"scriptCheckDeadline{i}",
                type="function",
                visibility="external",
                file=f"scripts/Vault{i}.sol",
                line_start=i + 1,
                metadata=json.dumps({
                    "timestamp_dependence": [{"line": i + 1}],
                    "source_context": "script",
                    "large": ["x"] * 20,
                }),
            )
            raw = json.dumps({
                "command_injection_risk": [{"line": i + 1}],
                "language": "python",
                "source_context": "production",
                "large": ["x"] * 20,
            })
            unsafe_metadata.append(raw)
            db.insert_node(
                id=f"aa_prod{i}.py::run_cmd",
                label=f"run_cmd_{i}",
                type="function",
                file=f"aa_prod{i}.py",
                line_start=i + 1,
                metadata=raw,
            )
            db.insert_node(
                id=f"zz_scripts{i}.py::run_cmd",
                label=f"script_run_cmd_{i}",
                type="function",
                file=f"zz_scripts{i}.py",
                line_start=i + 1,
                metadata=json.dumps({
                    "command_injection_risk": [{"line": i + 1}],
                    "language": "python",
                    "source_context": "script",
                    "large": ["x"] * 20,
                }),
            )

        real_load = mcp_server._load_metadata
        parsed = []

        def counting_load(raw):
            parsed.append(raw)
            return real_load(raw)

        monkeypatch.setattr(mcp_server, "_load_metadata", counting_load)

        defi = json.loads(mcp_server.cs_defi(
            db=tmp_db,
            category="timestamp",
            exclude_research=True,
            max_per_category=3,
        ))
        assert defi["_summary"]["category_totals"] == {"timestamp_dependence": 8}
        assert len(defi["timestamp_dependence"]) == 3
        assert parsed == [defi_metadata[i] for i in (0, 1, 2)]

        parsed.clear()
        unsafe = json.loads(mcp_server.cs_unsafe(
            db=tmp_db,
            category="command",
            exclude_research=True,
            max_per_category=3,
        ))
        assert unsafe["_summary"]["category_totals"] == {"command_execution": 8}
        assert len(unsafe["command_execution"]) == 3
        assert parsed == [unsafe_metadata[i] for i in (0, 1, 2)]

    def test_scanners_stream_function_rows_into_metadata_index(self, monkeypatch):
        import mcp_server

        rows = [
            {
                "id": "Vault.sol::Vault.checkDeadline(uint256)",
                "label": "checkDeadline",
                "file": "Vault.sol",
                "line_start": 7,
                "visibility": "external",
                "signature": "checkDeadline(uint256)",
                "metadata": json.dumps({
                    "timestamp_dependence": [{"line": 7}],
                    "source_context": "production",
                }),
            },
            {
                "id": "ops.py::run_cmd",
                "label": "run_cmd",
                "file": "ops.py",
                "line_start": 3,
                "visibility": "",
                "signature": "run_cmd(cmd)",
                "metadata": json.dumps({
                    "command_injection_risk": [{"line": 3}],
                    "language": "python",
                    "source_context": "production",
                }),
            },
        ]

        class StreamingRows:
            def __iter__(self):
                return iter(rows)

            def fetchall(self):
                raise AssertionError("scanner function rows should stream")

        class FakeConn:
            def execute(self, sql, params=()):
                assert "FROM nodes WHERE type = 'function'" in sql
                assert "metadata LIKE ?" in sql
                assert params in (
                    ('%"timestamp_dependence"%',),
                    ('%"command_injection_risk"%',),
                )
                return StreamingRows()

            def close(self):
                pass

        monkeypatch.setattr(
            mcp_server,
            "_open_query_connection",
            lambda db_path, timeout_seconds: FakeConn(),
        )

        defi = json.loads(mcp_server.cs_defi(db="stream.db", category="timestamp", max_per_category=1))
        unsafe = json.loads(mcp_server.cs_unsafe(db="stream.db", category="command", max_per_category=1))

        assert defi["_summary"]["category_totals"] == {"timestamp_dependence": 1}
        assert defi["timestamp_dependence"][0]["function"] == "checkDeadline"
        assert unsafe["_summary"]["category_totals"] == {"command_execution": 1}
        assert unsafe["command_execution"][0]["function"] == "run_cmd"

    def test_unsafe_scanner_streams_ffi_sink_rows(self, monkeypatch):
        import mcp_server

        ffi_rows = [
            {
                "label": f"transmute_{i}",
                "file": f"src/lib{i}.rs",
                "metadata": json.dumps({
                    "sink_type": "unsafe_ffi",
                    "source_context": "production",
                }),
            }
            for i in range(8)
        ]

        class StreamingRows:
            def __init__(self, rows):
                self.rows = rows

            def __iter__(self):
                return iter(self.rows)

            def fetchall(self):
                raise AssertionError("unsafe ffi sink rows should stream")

        class FakeConn:
            def execute(self, sql, params=()):
                if "FROM nodes WHERE type = 'function'" in sql:
                    raise AssertionError("ffi-only scan should skip function metadata rows")
                if "unsafe_ffi" in sql:
                    return StreamingRows(ffi_rows)
                raise AssertionError(f"unexpected query: {sql}")

            def close(self):
                pass

        monkeypatch.setattr(
            mcp_server,
            "_open_query_connection",
            lambda db_path, timeout_seconds: FakeConn(),
        )

        result = json.loads(mcp_server.cs_unsafe(db="stream.db", category="ffi", max_per_category=3))

        assert len(result["ffi_risks"]) == 3
        assert result["ffi_risks"][0]["operation"] == "transmute_0"
        assert result["_summary"]["total_findings"] == 8
        assert result["_summary"]["shown_findings"] == 3
        assert result["_summary"]["category_totals"] == {"ffi_risks": 8}
        assert result["_summary"]["truncated_categories"]["ffi_risks"] == {
            "shown": 3,
            "total": 8,
            "hidden": 5,
        }

    def test_scanners_parse_matching_metadata_once_per_function(self, tmp_db, monkeypatch):
        import mcp_server

        db = GraphDB(tmp_db)
        for i in range(4):
            db.insert_node(
                id=f"Vault{i}.sol::Vault{i}.swap(uint256)",
                label=f"swap{i}",
                type="function",
                visibility="external",
                file=f"Vault{i}.sol",
                line_start=i + 1,
                metadata=json.dumps({
                    "timestamp_dependence": [{"line": i + 1}],
                    "unchecked_erc20": [{"line": i + 2}],
                    "oracle_risk": [{"line": i + 3}],
                    "source_context": "production",
                }),
            )
            db.insert_node(
                id=f"ops{i}.py::run_cmd",
                label=f"run_cmd_{i}",
                type="function",
                file=f"ops{i}.py",
                line_start=i + 1,
                metadata=json.dumps({
                    "command_injection_risk": [{"line": i + 1}],
                    "weak_crypto": [{"line": i + 2}],
                    "dead_params": ["unused"],
                    "language": "python",
                    "source_context": "production",
                }),
            )

        real_load = mcp_server._load_metadata
        parsed = []

        def counting_load(raw):
            parsed.append(raw)
            return real_load(raw)

        monkeypatch.setattr(mcp_server, "_load_metadata", counting_load)

        defi = json.loads(mcp_server.cs_defi(db=tmp_db, category="all"))
        assert defi["_summary"]["category_totals"] == {
            "timestamp_dependence": 4,
            "unchecked_erc20": 4,
            "oracle_manipulation": 4,
        }
        assert len(parsed) == 4

        parsed.clear()
        unsafe = json.loads(mcp_server.cs_unsafe(db=tmp_db, category="all"))
        assert unsafe["_summary"]["category_totals"] == {
            "command_execution": 4,
            "dead_params": 4,
            "weak_crypto": 4,
        }
        assert len(parsed) == 4

    def test_lookup_and_cross_filter_research_nodes(self, tmp_path, tmp_db):
        import mcp_server

        repo = tmp_path / "repo"
        repo.mkdir()
        scripts = repo / "scripts"
        scripts.mkdir()
        (repo / "Vault.sol").write_text(
            "pragma solidity ^0.8.0;\n"
            "contract Vault {\n"
            "    function ping(address target) external {\n"
            "        target.call(\"\");\n"
            "    }\n"
            "}\n"
        )
        (scripts / "Deploy.s.sol").write_text(
            "pragma solidity ^0.8.0;\n"
            "contract DeployScript {\n"
            "    function ping(address target) external {\n"
            "        target.call(\"\");\n"
            "    }\n"
            "}\n"
        )

        indexer = Indexer(str(repo), include_research=True)
        indexer.index(tmp_db)

        lookup = json.loads(mcp_server.cs_lookup(name="ping", db=tmp_db))
        assert lookup["matches"] == 2
        contexts = {item["file"]: item["metadata"].get("source_context", "production") for item in lookup["functions"]}
        assert contexts["Vault.sol"] == "production"
        assert contexts["scripts/Deploy.s.sol"] == "script"
        assert lookup["query_scope"] == "all_sources"

        prod_lookup = json.loads(mcp_server.cs_lookup(name="ping", db=tmp_db, exclude_research=True))
        assert prod_lookup["matches"] == 1
        assert prod_lookup["functions"][0]["file"] == "Vault.sol"
        assert prod_lookup["query_scope"] == "production_only"

        cross = json.loads(mcp_server.cs_cross(db=tmp_db))
        cross_sources = {(item["source_file"], item["source_context"]) for item in cross["calls"] if item["source_label"] == "ping"}
        assert ("Vault.sol", "production") in cross_sources
        assert ("scripts/Deploy.s.sol", "script") in cross_sources

        prod_cross = json.loads(mcp_server.cs_cross(db=tmp_db, exclude_research=True))
        prod_cross_sources = {(item["source_file"], item["source_context"]) for item in prod_cross["calls"] if item["source_label"] == "ping"}
        assert prod_cross_sources == {("Vault.sol", "production")}

    def test_cross_summary_caps_output_and_filters_false_attributes(self, tmp_db):
        import mcp_server

        db = GraphDB(tmp_db)
        for i in range(5):
            db.insert_node(
                id=f"Vault.sol::Vault.call{i}()",
                label=f"call{i}",
                type="function",
                visibility="external",
                file="Vault.sol",
                metadata=json.dumps({"source_context": "production"}),
            )
            db.insert_edge(
                source=f"Vault.sol::Vault.call{i}()",
                target=f"External{i}.doThing()",
                relation="calls",
                attributes=json.dumps({"unresolved": True, "interface": f"IExternal{i}"}),
            )

        db.insert_node(
            id="scripts/Deploy.s.sol::Deploy.run()",
            label="run",
            type="function",
            visibility="external",
            file="scripts/Deploy.s.sol",
            metadata=json.dumps({"source_context": "script"}),
        )
        db.insert_edge(
            source="scripts/Deploy.s.sol::Deploy.run()",
            target="Broadcast.send()",
            relation="calls",
            attributes=json.dumps({"sink": "broadcast"}),
        )

        db.insert_node(
            id="Vault.sol::Vault.internalCall()",
            label="internalCall",
            type="function",
            visibility="external",
            file="Vault.sol",
        )
        db.insert_edge(
            source="Vault.sol::Vault.internalCall()",
            target="Vault.sol::Vault.helper()",
            relation="calls",
            attributes=json.dumps({"unresolved": False}),
        )

        summary = json.loads(mcp_server.cs_cross_summary(db=tmp_db, top=3))

        assert summary["total"] == 6
        assert summary["shown"] == 3
        assert summary["truncated"] is True
        assert summary["by_attribute"] == {"unresolved": 5, "sink": 1}
        assert summary["by_source_context"] == {"production": 5, "script": 1}
        assert len(summary["calls"]) == 3

        prod_summary = json.loads(mcp_server.cs_cross_summary(db=tmp_db, top=10, exclude_research=True))
        assert prod_summary["total"] == 5
        assert prod_summary["by_source_context"] == {"production": 5}

        raw_cross = json.loads(mcp_server.cs_cross(db=tmp_db))
        assert {item["source_label"] for item in raw_cross["calls"]} == {"call0", "call1", "call2", "call3", "call4", "run"}

    def test_cross_broad_scan_skips_untagged_context_parses(self, tmp_db, monkeypatch):
        import mcp_server

        db = GraphDB(tmp_db)
        neutral_metadata = json.dumps({"large": ["x"] * 20})
        edge_attrs = json.dumps({"unresolved": True})
        for i in range(3):
            source_id = f"Vault.sol::Vault.call{i}()"
            target_id = f"External{i}.sol::External{i}.doThing()"
            db.insert_node(
                id=source_id,
                label=f"call{i}",
                type="function",
                visibility="external",
                file="Vault.sol",
                metadata=neutral_metadata,
            )
            db.insert_node(
                id=target_id,
                label="doThing",
                type="function",
                visibility="external",
                file=f"External{i}.sol",
                metadata=neutral_metadata,
            )
            db.insert_edge(source_id, target_id, "calls", attributes=edge_attrs)

        real_load = mcp_server._load_metadata
        parsed = []

        def counting_load(raw):
            parsed.append(raw)
            return real_load(raw)

        monkeypatch.setattr(mcp_server, "_load_metadata", counting_load)

        cross = json.loads(mcp_server.cs_cross(db=tmp_db, max_results=0))
        summary = json.loads(mcp_server.cs_cross_summary(db=tmp_db, top=3))

        assert cross["total"] == 3
        assert all(item["source_context"] == "production" for item in cross["calls"])
        assert all(item["target_source_context"] == "production" for item in cross["calls"])
        assert summary["by_source_context"] == {"production": 3}
        assert neutral_metadata not in parsed
        assert parsed == [edge_attrs] * 6

    def test_cross_exclude_research_filters_before_attribute_parse(self, tmp_db, monkeypatch):
        import mcp_server

        db = GraphDB(tmp_db)
        prod_edge_attrs = json.dumps({"unresolved": True, "kind": "prod"})
        script_edge_attrs = json.dumps({"unresolved": True, "kind": "script"})
        for i in range(3):
            source_id = f"Vault.sol::Vault.call{i}()"
            target_id = f"External{i}.sol::External{i}.doThing()"
            db.insert_node(
                id=source_id,
                label=f"call{i}",
                type="function",
                visibility="external",
                file="Vault.sol",
                metadata=json.dumps({"source_context": "production", "large": ["x"] * 20}),
            )
            db.insert_node(
                id=target_id,
                label="doThing",
                type="function",
                visibility="external",
                file=f"External{i}.sol",
                metadata=json.dumps({"source_context": "production", "large": ["x"] * 20}),
            )
            db.insert_edge(source_id, target_id, "calls", attributes=prod_edge_attrs)
        for i in range(2):
            source_id = f"scripts/Deploy{i}.sol::Deploy{i}.run()"
            target_id = f"ScriptExternal{i}.sol::ScriptExternal{i}.doThing()"
            db.insert_node(
                id=source_id,
                label=f"run{i}",
                type="function",
                visibility="external",
                file=f"scripts/Deploy{i}.sol",
                metadata=json.dumps({"source_context": "script", "large": ["x"] * 20}),
            )
            db.insert_node(
                id=target_id,
                label="doThing",
                type="function",
                visibility="external",
                file=f"scripts/ScriptExternal{i}.sol",
                metadata=json.dumps({"source_context": "script", "large": ["x"] * 20}),
            )
            db.insert_edge(source_id, target_id, "calls", attributes=script_edge_attrs)

        real_load = mcp_server._load_metadata
        parsed = []

        def counting_load(raw):
            parsed.append(raw)
            return real_load(raw)

        monkeypatch.setattr(mcp_server, "_load_metadata", counting_load)

        cross = json.loads(mcp_server.cs_cross(db=tmp_db, exclude_research=True, max_results=0))
        summary = json.loads(mcp_server.cs_cross_summary(db=tmp_db, exclude_research=True, top=3))

        assert cross["total"] == 3
        assert {item["source_context"] for item in cross["calls"]} == {"production"}
        assert summary["by_source_context"] == {"production": 3}
        assert parsed == [prod_edge_attrs] * 6

    def test_cross_summary_caps_counter_sections_for_llm_context(self, tmp_db):
        import mcp_server

        db = GraphDB(tmp_db)
        for i in range(5):
            db.insert_node(
                id=f"Vault{i}.sol::Vault{i}.call()",
                label=f"call{i}",
                type="function",
                visibility="external",
                file=f"Vault{i}.sol",
            )
            db.insert_edge(
                source=f"Vault{i}.sol::Vault{i}.call()",
                target=f"External{i}.doThing()",
                relation="calls",
                attributes=json.dumps({"unresolved": True}),
            )

        capped = json.loads(mcp_server.cs_cross_summary(db=tmp_db, top=2, max_counter_items=2))
        uncapped = json.loads(mcp_server.cs_cross_summary(db=tmp_db, top=2, max_counter_items=0))

        assert len(capped["top_source_files"]) == 2
        assert len(capped["top_targets"]) == 2
        assert capped["counter_summary"]["top_source_files"] == {"total": 5, "shown": 2, "truncated": True}
        assert capped["counter_summary"]["top_targets"] == {"total": 5, "shown": 2, "truncated": True}
        assert capped["counter_summary"]["truncated"] is True
        assert "max_counter_items=0" in capped["_warnings"][0]

        assert len(uncapped["top_source_files"]) == 5
        assert len(uncapped["top_targets"]) == 5
        assert uncapped["counter_summary"]["truncated"] is False

    def test_cross_summary_ranks_only_capped_counter_items(self, monkeypatch):
        import mcp_server

        def entries():
            for i in range(5):
                yield {
                    "source_label": f"call{i}",
                    "source_file": f"Vault{i}.sol",
                    "source_context": "production",
                    "target_label": f"External{i}.doThing()",
                    "attributes": json.dumps({"unresolved": True}),
                }

        real_top_counter = mcp_server._top_counter
        limits = []

        def tracking_top_counter(counter, limit):
            limits.append((len(counter), limit))
            return real_top_counter(counter, limit)

        monkeypatch.setattr(mcp_server, "_top_counter", tracking_top_counter)

        capped = mcp_server._summarize_cross_entries(
            entries(),
            top=1,
            max_counter_items=2,
        )
        assert capped["counter_summary"]["top_source_files"] == {
            "total": 5,
            "shown": 2,
            "truncated": True,
        }
        assert (5, 2) in limits
        assert (5, 5) not in limits

        limits.clear()
        uncapped = mcp_server._summarize_cross_entries(
            entries(),
            top=1,
            max_counter_items=0,
        )
        assert uncapped["counter_summary"]["truncated"] is False
        assert (5, 5) in limits

    def test_cross_from_func_reports_ambiguous_start_candidates(self, tmp_db):
        import mcp_server

        db = GraphDB(tmp_db)
        for i in range(3):
            db.insert_node(
                id=f"Vault{i}.sol::Vault{i}.ping(address)",
                label="ping",
                type="function",
                visibility="external",
                file=f"Vault{i}.sol",
            )
            db.insert_edge(
                source=f"Vault{i}.sol::Vault{i}.ping(address)",
                target=f"External{i}.doThing()",
                relation="calls",
                attributes=json.dumps({"unresolved": True}),
            )

        cross = json.loads(mcp_server.cs_cross(db=tmp_db, from_func="ping", max_start_candidates=2))
        summary = json.loads(mcp_server.cs_cross_summary(db=tmp_db, from_func="ping", max_start_candidates=2))

        assert "Ambiguous from_func" in cross["error"]
        assert cross["start_candidate_summary"] == {"total": 3, "shown": 2, "truncated": True}
        assert len(cross["start_candidates"]) == 2
        assert "max_start_candidates=0" in cross["_warning"]

        assert summary["tool"] == "cs_cross_summary"
        assert "Ambiguous from_func" in summary["error"]
        assert summary["start_candidate_summary"] == {"total": 3, "shown": 2, "truncated": True}

    def test_cross_ambiguous_candidates_skip_untagged_context_parses(self, tmp_db, monkeypatch):
        import mcp_server

        db = GraphDB(tmp_db)
        neutral_metadata = json.dumps({"large": ["x"] * 20})
        for i in range(3):
            db.insert_node(
                id=f"Vault{i}.sol::Vault{i}.ping(address)",
                label="ping",
                type="function",
                visibility="external",
                file=f"Vault{i}.sol",
                metadata=neutral_metadata,
            )

        real_load = mcp_server._load_metadata
        parsed = []

        def counting_load(raw):
            parsed.append(raw)
            return real_load(raw)

        monkeypatch.setattr(mcp_server, "_load_metadata", counting_load)

        cross = json.loads(mcp_server.cs_cross(db=tmp_db, from_func="ping", max_start_candidates=2))
        summary = json.loads(mcp_server.cs_cross_summary(db=tmp_db, from_func="ping", max_start_candidates=2))

        assert cross["start_candidate_summary"] == {"total": 3, "shown": 2, "truncated": True}
        assert summary["start_candidate_summary"] == {"total": 3, "shown": 2, "truncated": True}
        assert all(item["source_context"] == "production" for item in cross["start_candidates"])
        assert all(item["source_context"] == "production" for item in summary["start_candidates"])
        assert parsed == []

    def test_cross_summary_from_func_streams_without_raw_cross(self, tmp_db, monkeypatch):
        import mcp_server

        db = GraphDB(tmp_db)
        start_id = "Vault.sol::Vault.ping(address)"
        db.insert_node(
            id=start_id,
            label="ping",
            type="function",
            visibility="external",
            file="Vault.sol",
            metadata=json.dumps({"source_context": "production"}),
        )
        for i in range(40):
            db.insert_edge(
                source=start_id,
                target=f"External{i:02d}.doThing()",
                relation="calls",
                attributes=json.dumps({"unresolved": True}),
            )

        def fail_raw_cross(*args, **kwargs):
            raise AssertionError("cs_cross_summary(from_func) should not call raw cs_cross")

        monkeypatch.setattr(mcp_server, "cs_cross", fail_raw_cross)

        summary = json.loads(mcp_server.cs_cross_summary(
            db=tmp_db,
            from_func="ping",
            top=3,
            max_counter_items=2,
        ))

        assert summary["tool"] == "cs_cross_summary"
        assert summary["total"] == 40
        assert summary["shown"] == 3
        assert summary["truncated"] is True
        assert len(summary["calls"]) == 3
        assert summary["counter_summary"]["top_targets"] == {
            "total": 40,
            "shown": 2,
            "truncated": True,
        }

    def test_cross_from_func_ambiguous_returns_before_full_graph_load(self, tmp_db, monkeypatch):
        import mcp_server

        db = GraphDB(tmp_db)
        for i in range(40):
            db.insert_node(
                id=f"Vault{i:02d}.sol::Vault{i:02d}.ping(address)",
                label="ping",
                type="function",
                visibility="external",
                file=f"Vault{i:02d}.sol",
                metadata=json.dumps({"source_context": "production"}),
            )

        real_open = mcp_server._open_query_connection
        real_append = mcp_server._append_capped
        start_buffer_sizes = []

        class CountingConnection:
            def __init__(self, conn):
                self._conn = conn

            def execute(self, sql, *args, **kwargs):
                normalized = " ".join(sql.split())
                if normalized == "SELECT id, label, type, file, metadata FROM nodes":
                    raise AssertionError("ambiguous cs_cross should not load full graph")
                return self._conn.execute(sql, *args, **kwargs)

            def close(self):
                self._conn.close()

        def tracking_append(items, item, total, limit):
            updated = real_append(items, item, total, limit)
            if isinstance(item, dict) and item.get("label") == "ping":
                start_buffer_sizes.append(len(items))
            return updated

        monkeypatch.setattr(
            mcp_server,
            "_open_query_connection",
            lambda *args, **kwargs: CountingConnection(real_open(*args, **kwargs)),
        )
        monkeypatch.setattr(mcp_server, "_append_capped", tracking_append)

        cross = json.loads(mcp_server.cs_cross(
            db=tmp_db,
            from_func="ping",
            max_start_candidates=3,
        ))

        assert "Ambiguous from_func" in cross["error"]
        assert cross["start_candidate_summary"] == {"total": 40, "shown": 3, "truncated": True}
        assert len(cross["start_candidates"]) == 3
        assert max(start_buffer_sizes) == 3

    def test_cross_from_func_streams_start_candidate_matches(self, tmp_db, monkeypatch):
        import mcp_server

        db = GraphDB(tmp_db)
        for i in range(12):
            db.insert_node(
                id=f"Vault{i:02d}.sol::Vault{i:02d}.ping(address)",
                label="ping",
                type="function",
                visibility="external",
                file=f"Vault{i:02d}.sol",
                metadata=json.dumps({"source_context": "production"}),
            )

        real_open = mcp_server._open_query_connection

        class StreamingCursor:
            def __init__(self, cursor):
                self._cursor = cursor

            def __iter__(self):
                return iter(self._cursor)

            def fetchall(self):
                raise AssertionError("cs_cross start candidate matches should stream")

        class CountingConnection:
            def __init__(self, conn):
                self._conn = conn

            def execute(self, sql, *args, **kwargs):
                cursor = self._conn.execute(sql, *args, **kwargs)
                normalized = " ".join(sql.split())
                if "FROM nodes WHERE type = ? AND label = ?" in normalized:
                    return StreamingCursor(cursor)
                return cursor

            def close(self):
                self._conn.close()

        monkeypatch.setattr(
            mcp_server,
            "_open_query_connection",
            lambda *args, **kwargs: CountingConnection(real_open(*args, **kwargs)),
        )

        cross = json.loads(mcp_server.cs_cross(
            db=tmp_db,
            from_func="ping",
            max_start_candidates=3,
        ))

        assert "Ambiguous from_func" in cross["error"]
        assert cross["start_candidate_summary"] == {"total": 12, "shown": 3, "truncated": True}
        assert len(cross["start_candidates"]) == 3

    def test_cross_from_func_avoids_full_graph_metadata_parse(self, tmp_db, monkeypatch):
        import mcp_server

        db = GraphDB(tmp_db)
        db.insert_node(
            id="Vault.sol::Vault.ping(address)",
            label="ping",
            type="function",
            visibility="external",
            file="Vault.sol",
            metadata=json.dumps({"source_context": "production"}),
        )
        db.insert_edge(
            source="Vault.sol::Vault.ping(address)",
            target="External.doThing()",
            relation="calls",
            attributes=json.dumps({"unresolved": True}),
        )
        for i in range(200):
            db.insert_node(
                id=f"Helper{i}.sol::Helper{i}.noop()",
                label=f"noop{i}",
                type="function",
                visibility="internal",
                file=f"Helper{i}.sol",
                metadata=json.dumps({"source_context": "script", "large": ["x"] * 20}),
            )

        real_load = mcp_server._load_metadata
        parsed = []

        def counting_load(raw):
            parsed.append(raw)
            return real_load(raw)

        monkeypatch.setattr(mcp_server, "_load_metadata", counting_load)

        cross = json.loads(mcp_server.cs_cross(db=tmp_db, from_func="ping"))

        assert cross["total"] == 1
        assert cross["calls"][0]["source"]["source_context"] == "production"
        assert len(parsed) == 1

    def test_cross_from_func_filters_research_before_attribute_parse(self, tmp_db, monkeypatch):
        import mcp_server

        db = GraphDB(tmp_db)
        start_id = "Vault.sol::Vault.ping(address)"
        prod_helper_id = "Vault.sol::Vault.prodHelper()"
        script_helper_id = "scripts/Deploy.sol::Deploy.scriptHelper()"
        prod_edge_attrs = json.dumps({"unresolved": True, "kind": "prod"})
        script_edge_attrs = json.dumps({"unresolved": True, "kind": "script"})
        for node_id, label, file, context in (
            (start_id, "ping", "Vault.sol", "production"),
            (prod_helper_id, "prodHelper", "Vault.sol", "production"),
            (script_helper_id, "scriptHelper", "scripts/Deploy.sol", "script"),
        ):
            db.insert_node(
                id=node_id,
                label=label,
                type="function",
                visibility="external",
                file=file,
                metadata=json.dumps({"source_context": context, "large": ["x"] * 20}),
            )
        db.insert_edge(start_id, prod_helper_id, "calls", attributes=json.dumps({}))
        db.insert_edge(start_id, script_helper_id, "calls", attributes=json.dumps({}))
        db.insert_edge(prod_helper_id, "External.prod()", "calls", attributes=prod_edge_attrs)
        db.insert_edge(script_helper_id, "External.script()", "calls", attributes=script_edge_attrs)

        real_load = mcp_server._load_metadata
        parsed = []

        def counting_load(raw):
            parsed.append(raw)
            return real_load(raw)

        monkeypatch.setattr(mcp_server, "_load_metadata", counting_load)

        cross = json.loads(mcp_server.cs_cross(
            db=tmp_db,
            from_func="ping",
            exclude_research=True,
            max_results=0,
        ))
        summary = json.loads(mcp_server.cs_cross_summary(
            db=tmp_db,
            from_func="ping",
            exclude_research=True,
            top=10,
        ))

        assert cross["total"] == 1
        assert cross["calls"][0]["source"]["label"] == "prodHelper"
        assert summary["total"] == 1
        assert summary["by_source_context"] == {"production": 1}
        assert parsed == [prod_edge_attrs, prod_edge_attrs]

    def test_cross_from_func_retains_only_capped_boundary_calls(self, tmp_db, monkeypatch):
        import mcp_server

        db = GraphDB(tmp_db)
        start_id = "Vault.sol::Vault.ping(address)"
        db.insert_node(
            id=start_id,
            label="ping",
            type="function",
            visibility="external",
            file="Vault.sol",
            metadata=json.dumps({"source_context": "production"}),
        )
        for i in range(40):
            db.insert_edge(
                source=start_id,
                target=f"External{i:02d}.doThing()",
                relation="calls",
                attributes=json.dumps({"unresolved": True}),
            )

        real_append = mcp_server._append_capped
        call_buffer_sizes = []

        def tracking_append(items, item, total, limit):
            updated = real_append(items, item, total, limit)
            if isinstance(item, dict) and "source" in item and "target" in item:
                call_buffer_sizes.append(len(items))
            return updated

        monkeypatch.setattr(mcp_server, "_append_capped", tracking_append)

        cross = json.loads(mcp_server.cs_cross(
            db=tmp_db,
            from_func="ping",
            max_results=3,
        ))

        assert cross["total"] == 40
        assert cross["shown"] == 3
        assert cross["truncated"] is True
        assert len(cross["calls"]) == 3
        assert max(call_buffer_sizes) == 3

    def test_cross_from_func_streams_graph_setup_rows(self, tmp_db, monkeypatch):
        import mcp_server

        db = GraphDB(tmp_db)
        start_id = "Vault.sol::Vault.ping(address)"
        db.insert_node(
            id=start_id,
            label="ping",
            type="function",
            visibility="external",
            file="Vault.sol",
            metadata=json.dumps({"source_context": "production"}),
        )
        db.insert_edge(
            source=start_id,
            target="External.doThing()",
            relation="calls",
            attributes=json.dumps({"unresolved": True}),
        )

        real_open = mcp_server._open_query_connection

        class StreamingRows:
            def __init__(self, rows):
                self.rows = rows

            def __iter__(self):
                return iter(self.rows)

            def fetchall(self):
                raise AssertionError("cs_cross graph setup rows should stream")

        class StreamingConnection:
            def __init__(self, conn):
                self._conn = conn

            def execute(self, sql, *args, **kwargs):
                normalized = " ".join(sql.split())
                rows = self._conn.execute(sql, *args, **kwargs)
                if (
                    normalized == "SELECT id, label, type, file, metadata FROM nodes"
                    or (
                        "SELECT source, target FROM edges" in normalized
                        and "relation IN" in normalized
                    )
                ):
                    return StreamingRows(rows)
                return rows

            def close(self):
                self._conn.close()

        monkeypatch.setattr(
            mcp_server,
            "_open_query_connection",
            lambda *args, **kwargs: StreamingConnection(real_open(*args, **kwargs)),
        )

        cross = json.loads(mcp_server.cs_cross(db=tmp_db, from_func="ping"))

        assert cross["total"] == 1
        assert cross["shown"] == 1
        assert cross["calls"][0]["source"]["label"] == "ping"

    def test_cross_from_func_walks_only_reachable_sources_with_index(self, tmp_db, monkeypatch):
        import mcp_server

        db = GraphDB(tmp_db)
        start_id = "Vault.sol::Vault.ping(address)"
        helper_id = "Vault.sol::Vault.helper()"
        db.insert_node(
            id=start_id,
            label="ping",
            type="function",
            visibility="external",
            file="Vault.sol",
        )
        db.insert_node(
            id=helper_id,
            label="helper",
            type="function",
            visibility="internal",
            file="Vault.sol",
        )
        db.insert_edge(
            source=start_id,
            target=helper_id,
            relation="calls",
            attributes=json.dumps({}),
        )
        db.insert_edge(
            source=helper_id,
            target="External.doThing()",
            relation="calls",
            attributes=json.dumps({"unresolved": True}),
        )
        for i in range(40):
            db.insert_node(
                id=f"Unrelated{i:02d}.sol::Unrelated{i:02d}.call()",
                label=f"call{i}",
                type="function",
                visibility="external",
                file=f"Unrelated{i:02d}.sol",
            )
            db.insert_edge(
                source=f"Unrelated{i:02d}.sol::Unrelated{i:02d}.call()",
                target=f"External{i:02d}.doThing()",
                relation="calls",
                attributes=json.dumps({"unresolved": True}),
            )

        real_open = mcp_server._open_query_connection
        statements = []

        class CountingConnection:
            def __init__(self, conn):
                self._conn = conn

            def execute(self, sql, *args, **kwargs):
                normalized = " ".join(sql.split())
                statements.append(normalized)
                if normalized == "SELECT id, label, type, file, metadata FROM nodes":
                    raise AssertionError("cs_cross(from_func) should not preload all nodes")
                if normalized == "SELECT source, target FROM edges WHERE relation IN (?, ?, ?)":
                    raise AssertionError("cs_cross(from_func) should not scan all traversal edges")
                if normalized == "SELECT source, target, attributes FROM edges WHERE relation = 'calls'":
                    raise AssertionError("cs_cross(from_func) should not scan all call edges")
                return self._conn.execute(sql, *args, **kwargs)

            def close(self):
                self._conn.close()

        monkeypatch.setattr(
            mcp_server,
            "_open_query_connection",
            lambda *args, **kwargs: CountingConnection(real_open(*args, **kwargs)),
        )

        cross = json.loads(mcp_server.cs_cross(db=tmp_db, from_func="ping"))

        assert cross["total"] == 1
        assert cross["shown"] == 1
        assert cross["calls"][0]["source"]["label"] == "helper"
        assert any("INDEXED BY idx_edges_source_relation" in sql for sql in statements)
        assert any("e.source = ? AND e.relation IN" in sql for sql in statements)
        assert any("e.source = ? AND e.relation = 'calls'" in sql for sql in statements)

    def test_cross_from_func_ignores_non_function_candidates(self, tmp_db):
        import mcp_server

        db = GraphDB(tmp_db)
        db.insert_node(
            id="Vault.sol::Vault.Deposited",
            label="Deposited",
            type="event",
            file="Vault.sol",
        )
        db.insert_node(
            id="Vault.sol::Vault.deposit(address,uint256)",
            label="deposit",
            type="function",
            visibility="external",
            file="Vault.sol",
        )
        db.insert_edge(
            source="Vault.sol::Vault.deposit(address,uint256)",
            target="External.doThing()",
            relation="calls",
            attributes=json.dumps({"unresolved": True}),
        )

        cross = json.loads(mcp_server.cs_cross(db=tmp_db, from_func="Vault.deposit"))

        assert "error" not in cross
        assert cross["total"] == 1
        assert cross["calls"][0]["source"]["label"] == "deposit"

    def test_cross_caps_raw_output_for_llm_context(self, tmp_db):
        import mcp_server

        db = GraphDB(tmp_db)
        for i in range(5):
            db.insert_node(
                id=f"Vault.sol::Vault.call{i}()",
                label=f"call{i}",
                type="function",
                visibility="external",
                file="Vault.sol",
            )
            db.insert_edge(
                source=f"Vault.sol::Vault.call{i}()",
                target=f"External{i}.doThing()",
                relation="calls",
                attributes=json.dumps({"unresolved": True}),
            )

        capped = json.loads(mcp_server.cs_cross(db=tmp_db, max_results=2))
        uncapped = json.loads(mcp_server.cs_cross(db=tmp_db, max_results=0))

        assert capped["total"] == 5
        assert capped["shown"] == 2
        assert capped["truncated"] is True
        assert capped["max_results"] == 2
        assert len(capped["calls"]) == 2
        assert "max_results=0" in capped["_warning"]

        assert uncapped["total"] == 5
        assert uncapped["shown"] == 5
        assert uncapped["truncated"] is False
        assert len(uncapped["calls"]) == 5

    def test_cross_broad_scan_streams_capped_results(self, tmp_db, monkeypatch):
        import mcp_server

        GraphDB(tmp_db)

        def fake_cross_entries(conn, exclude_research):
            for i in range(80):
                yield {
                    "source": f"Vault.sol::Vault.call{i}()",
                    "target": f"External{i}.doThing()",
                    "attributes": json.dumps({"unresolved": True}),
                    "source_label": f"call{i}",
                    "source_file": "Vault.sol",
                    "target_label": None,
                    "target_file": None,
                    "source_context": "production",
                }

        def fail_full_cross_rows(conn, exclude_research):
            raise AssertionError("broad cs_cross should not materialize all rows")

        monkeypatch.setattr(mcp_server, "_iter_cross_call_rows", fake_cross_entries)
        monkeypatch.setattr(mcp_server, "_cross_call_rows", fail_full_cross_rows)

        capped = json.loads(mcp_server.cs_cross(db=tmp_db, max_results=2))

        assert capped["total"] == 80
        assert capped["shown"] == 2
        assert capped["truncated"] is True
        assert len(capped["calls"]) == 2
        assert capped["calls"][0]["source_label"] == "call0"

    def test_sinks_caps_output_and_filters_scope_for_llm_context(self, tmp_db):
        import mcp_server

        db = GraphDB(tmp_db)
        for i in range(6):
            source_context = "script" if i == 5 else "production"
            db.insert_node(
                id=f"Vault{i}.sol::Vault{i}.transfer()",
                label=f"transfer{i}",
                type="function",
                visibility="",
                file=f"Vault{i}.sol",
                line_start=i + 1,
                metadata=json.dumps({
                    "is_sink": True,
                    "sink_type": "fund_transfer",
                    "source_context": source_context,
                }),
            )
            db.insert_node(
                id=f"Vault{i}.sol::Vault{i}.callTransfer()",
                label=f"callTransfer{i}",
                type="function",
                visibility="external" if i % 2 == 0 else "internal",
                file=f"Vault{i}.sol",
                line_start=20 + i,
                metadata=json.dumps({"source_context": source_context}),
            )
            db.insert_edge(
                source=f"Vault{i}.sol::Vault{i}.callTransfer()",
                target=f"Vault{i}.sol::Vault{i}.transfer()",
                relation="calls",
            )

        for i in range(3):
            db.insert_node(
                id=f"Wrapper{i}.sol::Wrapper{i}.wrap()",
                label=f"wrap{i}",
                type="function",
                visibility="external",
                file=f"Wrapper{i}.sol",
                line_start=i + 1,
            )
            db.insert_edge(
                source=f"Wrapper{i}.sol::Wrapper{i}.wrap()",
                target="Vault0.sol::Vault0.transfer()",
                relation="calls",
            )

        capped = json.loads(mcp_server.cs_sinks(
            db=tmp_db,
            sink_type="fund_transfer",
            max_results=2,
            max_callers_per_sink=2,
        ))
        uncapped_production = json.loads(mcp_server.cs_sinks(
            db=tmp_db,
            sink_type="fund_transfer",
            exclude_research=True,
            max_results=0,
            max_callers_per_sink=0,
        ))
        external_only = json.loads(mcp_server.cs_sinks(
            db=tmp_db,
            sink_type="fund_transfer",
            external_only=True,
            max_results=0,
            max_callers_per_sink=0,
        ))

        assert capped["total"] == 6
        assert capped["shown"] == 2
        assert capped["truncated"] is True
        assert capped["by_type"] == {"fund_transfer": 6}
        assert "max_results=0" in capped["_warning"]
        assert capped["sinks"][0]["caller_summary"] == {"total": 4, "shown": 2, "truncated": True}
        assert len(capped["sinks"][0]["callers"]) == 2
        assert "max_callers_per_sink=0" in capped["_warnings"][0]

        assert uncapped_production["total"] == 5
        assert uncapped_production["shown"] == 5
        assert uncapped_production["truncated"] is False
        assert all(sink["source_context"] == "production" for sink in uncapped_production["sinks"])

        internal_labels = {
            caller["label"]
            for sink in external_only["sinks"]
            for caller in sink["callers"]
            if caller["visibility"] == "internal"
        }
        assert internal_labels == set()

    def test_sinks_retains_only_capped_sink_rows(self, tmp_db, monkeypatch):
        import mcp_server

        db = GraphDB(tmp_db)
        for i in range(30):
            db.insert_node(
                id=f"Vault{i:02d}.sol::Vault{i:02d}.transfer()",
                label=f"transfer{i:02d}",
                type="function",
                visibility="public",
                file=f"Vault{i:02d}.sol",
                line_start=i + 1,
                metadata=json.dumps({
                    "is_sink": True,
                    "sink_type": "fund_transfer",
                    "source_context": "production",
                }),
            )

        real_append = mcp_server._append_capped
        sink_buffer_sizes = []

        def tracking_append(items, item, total, limit):
            updated = real_append(items, item, total, limit)
            if isinstance(item, dict) and item.get("sink_type") == "fund_transfer":
                sink_buffer_sizes.append(len(items))
            return updated

        monkeypatch.setattr(mcp_server, "_append_capped", tracking_append)

        result = json.loads(mcp_server.cs_sinks(
            db=tmp_db,
            sink_type="fund_transfer",
            max_results=3,
        ))

        assert result["total"] == 30
        assert result["shown"] == 3
        assert result["truncated"] is True
        assert result["by_type"] == {"fund_transfer": 30}
        assert [sink["label"] for sink in result["sinks"]] == [
            "transfer00",
            "transfer01",
            "transfer02",
        ]
        assert max(sink_buffer_sizes) == 3

    def test_sinks_omit_metadata_by_default_for_mcp_context(self, tmp_db):
        import mcp_server

        db = GraphDB(tmp_db)
        db.insert_node(
            id="Vault.sol::Vault.transfer()",
            label="transfer",
            type="function",
            visibility="public",
            file="Vault.sol",
            metadata=json.dumps({
                "is_sink": True,
                "sink_type": "fund_transfer",
                "source_context": "production",
                "large": ["x"] * 50,
            }),
        )

        compact = json.loads(mcp_server.cs_sinks(
            db=tmp_db,
            sink_type="fund_transfer",
            max_results=1,
        ))
        detailed = json.loads(mcp_server.cs_sinks(
            db=tmp_db,
            sink_type="fund_transfer",
            max_results=1,
            include_metadata=True,
        ))

        assert compact["include_metadata"] is False
        assert compact["sinks"][0]["sink_type"] == "fund_transfer"
        assert compact["sinks"][0]["source_context"] == "production"
        assert "metadata" not in compact["sinks"][0]
        assert detailed["include_metadata"] is True
        assert detailed["sinks"][0]["metadata"]["large"] == ["x"] * 50

    def test_sinks_prefilters_sink_type_before_metadata_parse(self, tmp_db, monkeypatch):
        import mcp_server

        db = GraphDB(tmp_db)
        for i in range(30):
            db.insert_node(
                id=f"Log{i}.sol::Log{i}.log()",
                label=f"log{i}",
                type="function",
                file=f"Log{i}.sol",
                metadata=json.dumps({
                    "is_sink": True,
                    "sink_type": "event_log",
                    "large": ["x"] * 20,
                }),
            )
        db.insert_node(
            id="Vault.sol::Vault.transfer()",
            label="transfer",
            type="function",
            visibility="public",
            file="Vault.sol",
            metadata=json.dumps({
                "is_sink": True,
                "sink_type": "fund_transfer",
                "source_context": "production",
            }),
        )

        real_load = mcp_server._load_metadata
        parsed = []

        def counting_load(raw):
            parsed.append(raw)
            return real_load(raw)

        monkeypatch.setattr(mcp_server, "_load_metadata", counting_load)

        result = json.loads(mcp_server.cs_sinks(
            db=tmp_db,
            sink_type="fund_transfer",
            max_results=1,
        ))

        assert result["total"] == 1
        assert result["sinks"][0]["label"] == "transfer"
        assert len(parsed) == 1
        assert "event_log" not in parsed[0]

    def test_sinks_streams_rows_and_uncaps_callers_with_zero(self, tmp_db, monkeypatch):
        import mcp_server

        db = GraphDB(tmp_db)
        sink_id = "Vault.sol::Vault.transfer()"
        db.insert_node(
            id=sink_id,
            label="transfer",
            type="function",
            visibility="public",
            file="Vault.sol",
            metadata=json.dumps({
                "is_sink": True,
                "sink_type": "fund_transfer",
                "source_context": "production",
            }),
        )
        for i in range(5):
            caller_id = f"Caller{i}.sol::Caller{i}.callTransfer()"
            db.insert_node(
                id=caller_id,
                label=f"callTransfer{i}",
                type="function",
                visibility="external",
                file=f"Caller{i}.sol",
                line_start=i + 1,
                metadata=json.dumps({"source_context": "production"}),
            )
            db.insert_edge(caller_id, sink_id, "calls")

        real_open = mcp_server._open_query_connection

        class StreamingRows:
            def __init__(self, rows):
                self.rows = rows

            def __iter__(self):
                return iter(self.rows)

            def fetchall(self):
                raise AssertionError("cs_sinks rows should stream")

        class StreamingConnection:
            def __init__(self, conn):
                self._conn = conn

            def execute(self, sql, *args, **kwargs):
                return StreamingRows(self._conn.execute(sql, *args, **kwargs))

            def close(self):
                self._conn.close()

        monkeypatch.setattr(
            mcp_server,
            "_open_query_connection",
            lambda *args, **kwargs: StreamingConnection(real_open(*args, **kwargs)),
        )

        result = json.loads(mcp_server.cs_sinks(
            db=tmp_db,
            sink_type="fund_transfer",
            max_results=1,
            max_callers_per_sink=0,
        ))

        assert result["total"] == 1
        assert result["sinks"][0]["caller_summary"] == {"total": 5, "shown": 5, "truncated": False}
        assert len(result["sinks"][0]["callers"]) == 5

    def test_sinks_expands_callers_with_indexed_lazy_queries(self, tmp_db, monkeypatch):
        import mcp_server

        db = GraphDB(tmp_db)
        sink_id = "Vault.sol::Vault.transfer()"
        db.insert_node(
            id=sink_id,
            label="transfer",
            type="function",
            file="Vault.sol",
            metadata=json.dumps({
                "is_sink": True,
                "sink_type": "fund_transfer",
                "source_context": "production",
            }),
        )
        db.insert_node(
            id="Vault.sol::Vault.callTransfer()",
            label="callTransfer",
            type="function",
            visibility="external",
            file="Vault.sol",
            metadata=json.dumps({"source_context": "production"}),
        )
        db.insert_edge("Vault.sol::Vault.callTransfer()", sink_id, "calls")
        for i in range(30):
            db.insert_node(
                id=f"Vault.sol::Vault.state{i}",
                label=f"state{i}",
                type="state_var",
                file="Vault.sol",
            )

        real_open = mcp_server._open_query_connection
        statements = []

        class CountingConnection:
            def __init__(self, conn):
                self._conn = conn

            def execute(self, sql, *args, **kwargs):
                normalized = " ".join(sql.split())
                statements.append(normalized)
                if normalized == (
                    "SELECT id, label, type, visibility, file, line_start, line_end, "
                    "signature, metadata FROM nodes WHERE type = 'function'"
                ):
                    raise AssertionError("cs_sinks should not preload all function nodes")
                if normalized == "SELECT source, target FROM edges WHERE relation = 'calls'":
                    raise AssertionError("cs_sinks should not preload all call edges")
                return self._conn.execute(sql, *args, **kwargs)

            def close(self):
                self._conn.close()

        monkeypatch.setattr(
            mcp_server,
            "_open_query_connection",
            lambda *args, **kwargs: CountingConnection(real_open(*args, **kwargs)),
        )

        result = json.loads(mcp_server.cs_sinks(
            db=tmp_db,
            sink_type="fund_transfer",
            max_results=1,
            max_callers_per_sink=1,
        ))

        assert result["sinks"][0]["caller_summary"] == {"total": 1, "shown": 1, "truncated": False}
        assert any("INDEXED BY idx_edges_target_relation" in sql for sql in statements)
        assert any("WHERE e.target = ? AND e.relation = 'calls'" in sql for sql in statements)
        assert any("FROM nodes WHERE id = ?" in sql for sql in statements)

    def test_sinks_caps_callers_before_metadata_formatting(self, tmp_db, monkeypatch):
        import mcp_server

        db = GraphDB(tmp_db)
        sink_id = "Vault.sol::Vault.transfer()"
        db.insert_node(
            id=sink_id,
            label="transfer",
            type="function",
            visibility="public",
            file="Vault.sol",
            metadata=json.dumps({"is_sink": True, "sink_type": "fund_transfer"}),
        )
        for i in range(80):
            caller_id = f"Caller{i}.sol::Caller{i}.callTransfer()"
            db.insert_node(
                id=caller_id,
                label=f"callTransfer{i}",
                type="function",
                visibility="external",
                file=f"Caller{i}.sol",
                metadata=json.dumps({"source_context": f"custom{i}", "large": ["x"] * 20}),
            )
            db.insert_edge(caller_id, sink_id, "calls")
        for i in range(200):
            db.insert_node(
                id=f"Helper{i}.sol::Helper{i}.noop()",
                label=f"noop{i}",
                type="function",
                visibility="internal",
                file=f"Helper{i}.sol",
                metadata=json.dumps({"source_context": "script", "large": ["x"] * 20}),
            )

        real_load = mcp_server._load_metadata
        parsed = []

        def counting_load(raw):
            parsed.append(raw)
            return real_load(raw)

        monkeypatch.setattr(mcp_server, "_load_metadata", counting_load)

        result = json.loads(mcp_server.cs_sinks(
            db=tmp_db,
            sink_type="fund_transfer",
            max_results=1,
            max_callers_per_sink=2,
        ))

        assert result["total"] == 1
        assert result["sinks"][0]["caller_summary"] == {"total": 80, "shown": 2, "truncated": True}
        assert len(result["sinks"][0]["callers"]) == 2
        assert len(parsed) == 3

    def test_sinks_exclude_research_uses_raw_context_filter(self, tmp_db, monkeypatch):
        import mcp_server

        db = GraphDB(tmp_db)
        prod_sink_id = "contracts/Vault.sol::Vault.transfer()"
        prod_sink_metadata = json.dumps({
            "is_sink": True,
            "sink_type": "fund_transfer",
            "source_context": "production",
            "large": ["x"] * 20,
        })
        db.insert_node(
            id=prod_sink_id,
            label="transfer",
            type="function",
            visibility="public",
            file="contracts/Vault.sol",
            metadata=prod_sink_metadata,
        )
        db.insert_node(
            id="scripts/Vault.sol::Vault.transfer()",
            label="scriptTransfer",
            type="function",
            visibility="public",
            file="scripts/Vault.sol",
            metadata=json.dumps({
                "is_sink": True,
                "sink_type": "fund_transfer",
                "source_context": "script",
                "large": ["x"] * 20,
            }),
        )
        for i in range(8):
            caller_id = f"contracts/Caller{i:02d}.sol::Caller{i:02d}.callTransfer()"
            db.insert_node(
                id=caller_id,
                label=f"callTransfer{i:02d}",
                type="function",
                visibility="external",
                file=f"contracts/Caller{i:02d}.sol",
                line_start=i + 1,
                metadata=json.dumps({"source_context": "production", "large": ["x"] * 20}),
            )
            db.insert_edge(caller_id, prod_sink_id, "calls")
        for i in range(8):
            caller_id = f"scripts/Caller{i:02d}.sol::Caller{i:02d}.callTransfer()"
            db.insert_node(
                id=caller_id,
                label=f"scriptCallTransfer{i:02d}",
                type="function",
                visibility="external",
                file=f"scripts/Caller{i:02d}.sol",
                line_start=i + 1,
                metadata=json.dumps({"source_context": "script", "large": ["x"] * 20}),
            )
            db.insert_edge(caller_id, prod_sink_id, "calls")

        real_load = mcp_server._load_metadata
        parsed = []

        def counting_load(raw):
            parsed.append(raw)
            return real_load(raw)

        monkeypatch.setattr(mcp_server, "_load_metadata", counting_load)

        result = json.loads(mcp_server.cs_sinks(
            db=tmp_db,
            sink_type="fund_transfer",
            exclude_research=True,
            max_results=1,
            max_callers_per_sink=3,
        ))

        sink = result["sinks"][0]
        assert result["total"] == 1
        assert sink["caller_summary"] == {"total": 8, "shown": 3, "truncated": True}
        assert [caller["label"] for caller in sink["callers"]] == [
            "callTransfer00",
            "callTransfer01",
            "callTransfer02",
        ]
        assert parsed == [prod_sink_metadata]

    def test_sinks_skips_untagged_caller_context_parses(self, tmp_db, monkeypatch):
        import mcp_server

        db = GraphDB(tmp_db)
        sink_id = "Vault.sol::Vault.transfer()"
        db.insert_node(
            id=sink_id,
            label="transfer",
            type="function",
            visibility="public",
            file="Vault.sol",
            metadata=json.dumps({"is_sink": True, "sink_type": "fund_transfer"}),
        )
        caller_metadata = json.dumps({"large": ["x"] * 20})
        for i in range(3):
            caller_id = f"Caller{i}.sol::Caller{i}.callTransfer()"
            db.insert_node(
                id=caller_id,
                label=f"callTransfer{i}",
                type="function",
                visibility="external",
                file=f"Caller{i}.sol",
                metadata=caller_metadata,
            )
            db.insert_edge(caller_id, sink_id, "calls")

        real_load = mcp_server._load_metadata
        parsed = []

        def counting_load(raw):
            parsed.append(raw)
            return real_load(raw)

        monkeypatch.setattr(mcp_server, "_load_metadata", counting_load)

        result = json.loads(mcp_server.cs_sinks(
            db=tmp_db,
            sink_type="fund_transfer",
            max_results=1,
            max_callers_per_sink=0,
        ))

        callers = result["sinks"][0]["callers"]
        assert result["sinks"][0]["caller_summary"] == {"total": 3, "shown": 3, "truncated": False}
        assert all(caller["source_context"] == "production" for caller in callers)
        assert caller_metadata not in parsed

    def test_sinks_retains_only_capped_callers(self, tmp_db, monkeypatch):
        import mcp_server

        db = GraphDB(tmp_db)
        sink_id = "Vault.sol::Vault.transfer()"
        db.insert_node(
            id=sink_id,
            label="transfer",
            type="function",
            visibility="public",
            file="Vault.sol",
            metadata=json.dumps({"is_sink": True, "sink_type": "fund_transfer"}),
        )
        for i in range(30):
            caller_id = f"Caller{i:02d}.sol::Caller{i:02d}.callTransfer()"
            db.insert_node(
                id=caller_id,
                label=f"callTransfer{i:02d}",
                type="function",
                visibility="external",
                file=f"Caller{i:02d}.sol",
                line_start=i + 1,
                metadata=json.dumps({"source_context": "production"}),
            )
            db.insert_edge(caller_id, sink_id, "calls")

        real_keep_sorted = mcp_server._keep_sorted_result
        caller_buffer_sizes = []

        def tracking_keep_sorted(buffer, item, sort_key, limit):
            real_keep_sorted(buffer, item, sort_key, limit)
            if isinstance(item, dict) and item.get("distance") is not None:
                caller_buffer_sizes.append(len(buffer))

        monkeypatch.setattr(mcp_server, "_keep_sorted_result", tracking_keep_sorted)

        result = json.loads(mcp_server.cs_sinks(
            db=tmp_db,
            sink_type="fund_transfer",
            max_results=1,
            max_callers_per_sink=3,
        ))

        assert result["sinks"][0]["caller_summary"] == {"total": 30, "shown": 3, "truncated": True}
        assert [caller["label"] for caller in result["sinks"][0]["callers"]] == [
            "callTransfer00",
            "callTransfer01",
            "callTransfer02",
        ]
        assert max(caller_buffer_sizes) == 3

    def test_hotspots_do_not_count_false_unresolved_call_edges(self, tmp_db):
        import mcp_server

        db = GraphDB(tmp_db)
        db.insert_node(
            id="Vault.sol::Vault.safeSet(uint256)",
            label="safeSet",
            type="function",
            visibility="external",
            file="Vault.sol",
        )
        db.insert_node(
            id="Vault.sol::Vault.total",
            label="total",
            type="variable",
            file="Vault.sol",
        )
        db.insert_edge(
            source="Vault.sol::Vault.safeSet(uint256)",
            target="Vault.sol::Vault.total",
            relation="writes_state",
        )
        db.insert_edge(
            source="Vault.sol::Vault.safeSet(uint256)",
            target="Vault.sol::Vault.helper()",
            relation="calls",
            attributes=json.dumps({"unresolved": False}),
        )

        hotspots = json.loads(mcp_server.cs_hotspots(db=tmp_db, top=10))
        safe_set = next(item for item in hotspots["hotspots"] if item["function"] == "safeSet")

        assert "ext_calls(1)" not in safe_set["reasons"]

    def test_hotspots_uses_bounded_queries_for_broad_scans(self, tmp_db, monkeypatch):
        import mcp_server

        db = GraphDB(tmp_db)
        for i in range(400):
            func_id = f"Vault.sol::Vault.entry{i}()"
            state_id = f"Vault.sol::Vault.total{i}"
            db.insert_node(
                id=func_id,
                label=f"entry{i}",
                type="function",
                visibility="external",
                file="Vault.sol",
            )
            db.insert_node(
                id=state_id,
                label=f"total{i}",
                type="state_var",
                file="Vault.sol",
            )
            db.insert_edge(func_id, state_id, "writes_state")
            db.insert_edge(
                func_id,
                f"Vault.sol::_unresolved::external{i}",
                "calls",
                attributes=json.dumps({"unresolved": True}),
            )

        real_open = mcp_server._open_query_connection
        statements = []

        class CountingConnection:
            def __init__(self, conn):
                self._conn = conn

            def execute(self, sql, *args, **kwargs):
                statements.append(sql)
                return self._conn.execute(sql, *args, **kwargs)

            def close(self):
                self._conn.close()

        def counting_open(*args, **kwargs):
            return CountingConnection(real_open(*args, **kwargs))

        monkeypatch.setattr(mcp_server, "_open_query_connection", counting_open)

        hotspots = json.loads(mcp_server.cs_hotspots(db=tmp_db, top=25, exclude_research=True))

        assert hotspots["_summary"]["total_scored"] == 400
        assert hotspots["_summary"]["top_shown"] == 25
        graph_statements = [
            sql for sql in statements
            if "sqlite_master" not in sql
        ]
        assert len(graph_statements) == 4
        assert any("idx_edges_relation_target" in sql for sql in statements)
        assert any("idx_edges_source_relation" in sql and "EXISTS" in sql for sql in statements)

    def test_hotspots_guard_counts_only_writable_entries(self, tmp_db, monkeypatch):
        import mcp_server

        db = GraphDB(tmp_db)
        rows = (
            ("Vault.sol::Vault.writeEntry()", "writeEntry", "external", True),
            ("Vault.sol::Vault.readEntry()", "readEntry", "external", False),
            ("Vault.sol::Vault.writeInternal()", "writeInternal", "internal", True),
        )
        for func_id, label, visibility, writes in rows:
            db.insert_node(
                id=func_id,
                label=label,
                type="function",
                visibility=visibility,
                file="Vault.sol",
            )
            db.insert_node(
                id=f"Vault.sol::Vault.onlyOwner_{label}",
                label=f"onlyOwner_{label}",
                type="modifier",
                file="Vault.sol",
            )
            db.insert_edge(f"Vault.sol::Vault.onlyOwner_{label}", func_id, "guards")
            if writes:
                db.insert_edge(func_id, f"Vault.sol::Vault.total_{label}", "writes_state")

        conn = db.get_connection()
        try:
            counts = mcp_server._guard_counts_for_writable_entries(conn)
        finally:
            conn.close()

        assert counts == {"Vault.sol::Vault.writeEntry()": 1}

        statements = []

        class CountingConnection:
            def __init__(self, wrapped):
                self._wrapped = wrapped

            def execute(self, sql, *args, **kwargs):
                statements.append(sql)
                return self._wrapped.execute(sql, *args, **kwargs)

            def close(self):
                self._wrapped.close()

        monkeypatch.setattr(mcp_server, "_sqlite_index_exists", lambda conn, name: False)
        conn = CountingConnection(db.get_connection())
        try:
            fallback_counts = mcp_server._guard_counts_for_writable_entries(conn)
        finally:
            conn.close()

        assert fallback_counts == counts
        assert all("INDEXED BY" not in sql for sql in statements)

    def test_hotspots_edge_counts_skip_out_of_scope_sources(self, monkeypatch):
        import mcp_server

        statements = []

        class FakeConn:
            def execute(self, sql, *args, **kwargs):
                statements.append((sql, args))
                params = set(args[0]) if args else set()
                if "writes_state" in sql:
                    if params == {"keep"}:
                        return [{"source": "keep", "cnt": 2}]
                    return [{"source": "keep", "cnt": 2}, {"source": "skip", "cnt": 1}]
                if "relation = 'calls'" in sql:
                    rows = [
                        {"source": "keep", "attributes": json.dumps({"unresolved": True})},
                        {"source": "skip", "attributes": json.dumps({"unresolved": True})},
                    ]
                    return [row for row in rows if not params or row["source"] in params]
                raise AssertionError(f"unexpected query: {sql}")

        parsed_attrs = []
        real_load = mcp_server._load_metadata

        def counting_load(raw):
            parsed_attrs.append(raw)
            return real_load(raw)

        monkeypatch.setattr(mcp_server, "_load_metadata", counting_load)

        source_ids = {"keep"}
        assert mcp_server._write_counts_for_sources(FakeConn(), source_ids) == {"keep": 2}
        assert mcp_server._external_call_counts(FakeConn(), source_ids=source_ids) == {"keep": 1}
        assert parsed_attrs == [json.dumps({"unresolved": True})]
        assert any("source IN" in sql and "GROUP BY source" in sql for sql, _ in statements)
        assert any("source IN" in sql and "relation = 'calls'" in sql for sql, _ in statements)

    def test_hotspots_streams_aggregate_rows(self, tmp_db, monkeypatch):
        import mcp_server

        db = GraphDB(tmp_db)
        for i in range(12):
            func_id = f"Vault.sol::Vault.entry{i}()"
            state_id = f"Vault.sol::Vault.total{i}"
            guard_id = f"Vault.sol::Vault.onlyOwner{i}"
            db.insert_node(
                id=func_id,
                label=f"entry{i}",
                type="function",
                visibility="external",
                file="Vault.sol",
            )
            db.insert_node(
                id=state_id,
                label=f"total{i}",
                type="state_var",
                file="Vault.sol",
            )
            db.insert_node(
                id=guard_id,
                label=f"onlyOwner{i}",
                type="modifier",
                file="Vault.sol",
            )
            db.insert_edge(func_id, state_id, "writes_state")
            db.insert_edge(guard_id, func_id, "guards")

        real_open = mcp_server._open_query_connection

        class StreamingCursor:
            def __init__(self, cursor):
                self._cursor = cursor

            def __iter__(self):
                return iter(self._cursor)

            def fetchall(self):
                raise AssertionError("cs_hotspots aggregate rows should stream")

        class CountingConnection:
            def __init__(self, conn):
                self._conn = conn

            def execute(self, sql, *args, **kwargs):
                cursor = self._conn.execute(sql, *args, **kwargs)
                normalized = " ".join(sql.split())
                if (
                    "GROUP BY source" in normalized
                    or "GROUP BY target" in normalized
                ):
                    return StreamingCursor(cursor)
                return cursor

            def close(self):
                self._conn.close()

        monkeypatch.setattr(
            mcp_server,
            "_open_query_connection",
            lambda *args, **kwargs: CountingConnection(real_open(*args, **kwargs)),
        )

        hotspots = json.loads(mcp_server.cs_hotspots(db=tmp_db, top=5))

        assert hotspots["_summary"]["total_scored"] == 12
        assert hotspots["_summary"]["top_shown"] == 5

    def test_hotspots_retains_only_top_results_during_scan(self, tmp_db, monkeypatch):
        import mcp_server

        db = GraphDB(tmp_db)
        for i in range(40):
            func_id = f"Vault.sol::Vault.entry{i}()"
            state_id = f"Vault.sol::Vault.total{i}"
            db.insert_node(
                id=func_id,
                label=f"entry{i}",
                type="function",
                visibility="external",
                file="Vault.sol",
            )
            db.insert_node(
                id=state_id,
                label=f"total{i}",
                type="state_var",
                file="Vault.sol",
            )
            db.insert_edge(func_id, state_id, "writes_state")
            db.insert_edge(
                func_id,
                f"Vault.sol::_unresolved::external{i}",
                "calls",
                attributes=json.dumps({"unresolved": True}),
            )

        real_heappush = mcp_server.heapq.heappush
        real_heapreplace = mcp_server.heapq.heapreplace
        heap_sizes = []

        def tracking_heappush(heap, item):
            real_heappush(heap, item)
            heap_sizes.append(len(heap))

        def tracking_heapreplace(heap, item):
            result = real_heapreplace(heap, item)
            heap_sizes.append(len(heap))
            return result

        monkeypatch.setattr(mcp_server.heapq, "heappush", tracking_heappush)
        monkeypatch.setattr(mcp_server.heapq, "heapreplace", tracking_heapreplace)

        hotspots = json.loads(mcp_server.cs_hotspots(db=tmp_db, top=3))

        assert hotspots["_summary"]["total_scored"] == 40
        assert hotspots["_summary"]["top_shown"] == 3
        assert [item["function"] for item in hotspots["hotspots"]] == ["entry0", "entry1", "entry2"]
        assert max(heap_sizes) == 3

    def test_hotspots_formats_only_top_source_contexts(self, tmp_db, monkeypatch):
        import mcp_server

        db = GraphDB(tmp_db)
        metadata_by_index = {}
        for i in range(10):
            func_id = f"Vault{i:02d}.sol::Vault{i:02d}.entry()"
            state_id = f"Vault{i:02d}.sol::Vault{i:02d}.total"
            metadata_by_index[i] = json.dumps({"source_context": f"custom{i}", "large": ["x"] * 20})
            db.insert_node(
                id=func_id,
                label=f"entry{i:02d}",
                type="function",
                visibility="external",
                file=f"Vault{i:02d}.sol",
                metadata=metadata_by_index[i],
            )
            db.insert_node(
                id=state_id,
                label=f"total{i:02d}",
                type="state_var",
                file=f"Vault{i:02d}.sol",
            )
            db.insert_edge(func_id, state_id, "writes_state")

        real_load = mcp_server._load_metadata
        parsed = []

        def counting_load(raw):
            parsed.append(raw)
            return real_load(raw)

        monkeypatch.setattr(mcp_server, "_load_metadata", counting_load)

        hotspots = json.loads(mcp_server.cs_hotspots(db=tmp_db, top=3))

        assert hotspots["_summary"]["total_scored"] == 10
        assert [item["function"] for item in hotspots["hotspots"]] == ["entry00", "entry01", "entry02"]
        assert [item["source_context"] for item in hotspots["hotspots"]] == ["custom0", "custom1", "custom2"]
        assert parsed == [metadata_by_index[0], metadata_by_index[1], metadata_by_index[2]]

    def test_hotspots_skips_neutral_metadata_parses(self, tmp_db, monkeypatch):
        import mcp_server

        db = GraphDB(tmp_db)
        entry_id = "Vault.sol::Vault.entry()"
        state_id = "Vault.sol::Vault.total"
        neutral_metadata = json.dumps({"large": ["x"] * 20})
        risk_metadata = json.dumps({"reentrancy_risk": True, "large": ["x"] * 20})
        db.insert_node(
            id=entry_id,
            label="entry",
            type="function",
            visibility="external",
            file="Vault.sol",
            metadata=neutral_metadata,
        )
        db.insert_node(
            id=state_id,
            label="total",
            type="state_var",
            file="Vault.sol",
        )
        db.insert_edge(entry_id, state_id, "writes_state")
        db.insert_node(
            id="Vault.sol::Vault.reenter()",
            label="reenter",
            type="function",
            visibility="internal",
            file="Vault.sol",
            metadata=risk_metadata,
        )
        for i in range(40):
            db.insert_node(
                id=f"Helper{i}.sol::Helper{i}.noop()",
                label=f"noop{i}",
                type="function",
                visibility="internal",
                file=f"Helper{i}.sol",
                metadata=neutral_metadata,
            )

        real_load = mcp_server._load_metadata
        real_guard_counts = mcp_server._guard_counts_for_writable_entries
        parsed = []
        guard_scopes = []

        def counting_load(raw):
            parsed.append(raw)
            return real_load(raw)

        def tracking_guard_counts(conn, source_ids=None):
            guard_scopes.append(set(source_ids or ()))
            return real_guard_counts(conn, source_ids)

        monkeypatch.setattr(mcp_server, "_load_metadata", counting_load)
        monkeypatch.setattr(mcp_server, "_guard_counts_for_writable_entries", tracking_guard_counts)

        hotspots = json.loads(mcp_server.cs_hotspots(db=tmp_db, top=10))

        assert hotspots["_summary"]["total_scored"] == 2
        assert {item["function"] for item in hotspots["hotspots"]} == {"entry", "reenter"}
        assert parsed == [risk_metadata]
        assert guard_scopes == [{entry_id}]

    def test_lookup_query_connection_falls_back_to_immutable(self, tmp_db, monkeypatch):
        import mcp_server

        db = GraphDB(tmp_db)
        db.insert_node(id="Vault.sol::Vault.ping()", label="ping", type="function", file="Vault.sol")

        real_connect = mcp_server.sqlite3.connect
        attempts = []

        class UnreadableReadOnlyConnection:
            row_factory = None

            def execute(self, *args, **kwargs):
                raise mcp_server.sqlite3.OperationalError("unable to open database file")

            def close(self):
                pass

        def fake_connect(database_uri, *args, **kwargs):
            attempts.append(database_uri)
            if "immutable=1" not in database_uri:
                return UnreadableReadOnlyConnection()
            return real_connect(database_uri, *args, **kwargs)

        monkeypatch.setattr(mcp_server.sqlite3, "connect", fake_connect)

        result = json.loads(mcp_server.cs_lookup(name="ping", db=tmp_db))

        assert result["matches"] == 1
        assert any("mode=ro" in uri and "immutable=1" not in uri for uri in attempts)
        assert any("mode=ro&immutable=1" in uri for uri in attempts)

    def test_lookup_caps_ambiguous_matches_for_llm_context(self, tmp_db):
        import mcp_server

        db = GraphDB(tmp_db)
        for i in range(5):
            db.insert_node(
                id=f"Vault{i}.sol::Vault{i}.transfer(address,uint256)",
                label="transfer",
                type="function",
                visibility="external",
                file=f"Vault{i}.sol",
                line_start=i + 1,
                signature="function transfer(address to, uint256 amount) external",
            )

        capped = json.loads(mcp_server.cs_lookup(name="transfer", db=tmp_db, max_matches=2, max_candidates=3))
        uncapped = json.loads(mcp_server.cs_lookup(name="transfer", db=tmp_db, max_matches=0))

        assert capped["matches"] == 2
        assert capped["matches_total"] == 5
        assert capped["truncated"] is True
        assert "candidates" in capped
        assert len(capped["candidates"]) == 3
        assert capped["candidate_summary"] == {"total": 5, "shown": 3, "truncated": True}
        assert capped["max_candidates"] == 3
        assert "max_candidates=0" in capped["_warnings"][0]
        assert "max_matches=0" in capped["_warning"]

        assert uncapped["matches"] == 5
        assert uncapped["matches_total"] == 5
        assert uncapped["truncated"] is False
        assert uncapped["max_candidates"] == 50
        assert "candidates" not in uncapped

    def test_lookup_matches_only_functions_for_function_profiles(self, tmp_db):
        import mcp_server

        db = GraphDB(tmp_db)
        db.insert_node(
            id="Vault.sol::Vault.transfer",
            label="transfer",
            type="state_var",
            file="Vault.sol",
        )
        db.insert_node(
            id="Vault.sol::Vault.transfer(address,uint256)",
            label="transfer",
            type="function",
            visibility="external",
            file="Vault.sol",
            signature="function transfer(address to, uint256 amount) external",
        )

        lookup = json.loads(mcp_server.cs_lookup(name="transfer", db=tmp_db))

        assert lookup["matches"] == 1
        assert lookup["functions"][0]["type"] == "function"
        assert lookup["functions"][0]["signature"] == "function transfer(address to, uint256 amount) external"

    def test_lookup_parses_only_full_profiles_for_known_candidates(self, tmp_db, monkeypatch):
        import mcp_server

        db = GraphDB(tmp_db)
        for i in range(12):
            db.insert_node(
                id=f"Vault{i:02d}.sol::Vault{i:02d}.transfer(address,uint256)",
                label="transfer",
                type="function",
                visibility="external",
                file=f"Vault{i:02d}.sol",
                line_start=i + 1,
                signature="function transfer(address to, uint256 amount) external",
                metadata=json.dumps({"source_context": "production", "large": ["x"] * 20}),
            )

        real_load = mcp_server._load_metadata
        parsed = []

        def counting_load(raw):
            parsed.append(raw)
            return real_load(raw)

        monkeypatch.setattr(mcp_server, "_load_metadata", counting_load)

        lookup = json.loads(mcp_server.cs_lookup(
            name="transfer",
            db=tmp_db,
            max_matches=2,
            max_candidates=4,
        ))

        assert lookup["matches"] == 2
        assert lookup["matches_total"] == 12
        assert lookup["candidate_summary"] == {"total": 12, "shown": 4, "truncated": True}
        assert len(lookup["candidates"]) == 4
        assert len(parsed) == 2

    def test_lookup_exclude_research_retains_only_capped_matches(self, tmp_db, monkeypatch):
        import mcp_server

        db = GraphDB(tmp_db)
        for i in range(40):
            db.insert_node(
                id=f"Vault{i:02d}.sol::Vault{i:02d}.transfer(address,uint256)",
                label="transfer",
                type="function",
                visibility="external",
                file=f"Vault{i:02d}.sol",
                line_start=i + 1,
                signature="function transfer(address to, uint256 amount) external",
                metadata=json.dumps({"source_context": "production"}),
            )
        for i in range(5):
            db.insert_node(
                id=f"scripts/Helper{i:02d}.sol::Helper{i:02d}.transfer(address,uint256)",
                label="transfer",
                type="function",
                visibility="external",
                file=f"scripts/Helper{i:02d}.sol",
                line_start=i + 1,
                metadata=json.dumps({"source_context": "script"}),
            )

        real_append = mcp_server._append_capped
        real_load = mcp_server._load_metadata
        match_buffer_sizes = []
        parsed = []

        def tracking_append(items, item, total, limit):
            updated = real_append(items, item, total, limit)
            if isinstance(item, str) and ".transfer(" in item:
                match_buffer_sizes.append(len(items))
            return updated

        def counting_load(raw):
            parsed.append(raw)
            return real_load(raw)

        monkeypatch.setattr(mcp_server, "_append_capped", tracking_append)
        monkeypatch.setattr(mcp_server, "_load_metadata", counting_load)

        lookup = json.loads(mcp_server.cs_lookup(
            name="transfer",
            db=tmp_db,
            exclude_research=True,
            max_matches=2,
            max_candidates=4,
        ))

        assert lookup["matches"] == 2
        assert lookup["matches_total"] == 40
        assert lookup["candidate_summary"] == {"total": 40, "shown": 4, "truncated": True}
        assert len(lookup["candidates"]) == 4
        assert max(match_buffer_sizes) == 4
        assert len(parsed) == 2

    def test_lookup_batches_ambiguous_candidate_loads(self, tmp_db, monkeypatch):
        import mcp_server

        db = GraphDB(tmp_db)
        for i in range(80):
            db.insert_node(
                id=f"Vault{i}.sol::Vault{i}.transfer(address,uint256)",
                label="transfer",
                type="function",
                visibility="external",
                file=f"Vault{i}.sol",
                line_start=i + 1,
                signature="function transfer(address to, uint256 amount) external",
            )

        real_open = mcp_server._open_query_connection
        statements = []
        id_batch_sizes = []

        class CountingConnection:
            def __init__(self, conn):
                self._conn = conn

            def execute(self, sql, *args, **kwargs):
                normalized = " ".join(sql.split())
                statements.append(normalized)
                if "FROM nodes WHERE id IN" in normalized:
                    id_batch_sizes.append(len(args[0]))
                return self._conn.execute(sql, *args, **kwargs)

            def close(self):
                self._conn.close()

        def counting_open(*args, **kwargs):
            return CountingConnection(real_open(*args, **kwargs))

        monkeypatch.setattr(mcp_server, "_open_query_connection", counting_open)

        lookup = json.loads(mcp_server.cs_lookup(
            name="transfer",
            db=tmp_db,
            max_matches=2,
            max_candidates=3,
        ))

        assert lookup["matches_total"] == 80
        assert lookup["matches"] == 2
        assert len(lookup["candidates"]) == 3
        assert id_batch_sizes == [2, 1]
        assert len(statements) <= 20
        assert not any("FROM nodes WHERE id = ?" in sql for sql in statements)

    def test_lookup_streams_ambiguous_match_candidates(self, tmp_db, monkeypatch):
        import mcp_server

        db = GraphDB(tmp_db)
        for i in range(12):
            db.insert_node(
                id=f"Vault{i:02d}.sol::Vault{i:02d}.transfer(address,uint256)",
                label="transfer",
                type="function",
                visibility="external",
                file=f"Vault{i:02d}.sol",
                line_start=i + 1,
                signature="function transfer(address to, uint256 amount) external",
                metadata=json.dumps({"source_context": "production"}),
            )

        real_open = mcp_server._open_query_connection

        class StreamingCursor:
            def __init__(self, cursor):
                self._cursor = cursor

            def __iter__(self):
                return iter(self._cursor)

            def fetchall(self):
                raise AssertionError("cs_lookup match candidates should stream")

        class CountingConnection:
            def __init__(self, conn):
                self._conn = conn

            def execute(self, sql, *args, **kwargs):
                cursor = self._conn.execute(sql, *args, **kwargs)
                normalized = " ".join(sql.split())
                if "FROM nodes WHERE type = ? AND label = ?" in normalized:
                    return StreamingCursor(cursor)
                return cursor

            def close(self):
                self._conn.close()

        monkeypatch.setattr(
            mcp_server,
            "_open_query_connection",
            lambda *args, **kwargs: CountingConnection(real_open(*args, **kwargs)),
        )

        lookup = json.loads(mcp_server.cs_lookup(
            name="transfer",
            db=tmp_db,
            max_matches=2,
            max_candidates=3,
        ))

        assert lookup["matches_total"] == 12
        assert lookup["matches"] == 2
        assert lookup["candidate_summary"] == {"total": 12, "shown": 3, "truncated": True}
        assert len(lookup["candidates"]) == 3

    def test_lookup_streams_batched_node_loads(self, tmp_db, monkeypatch):
        import mcp_server

        db = GraphDB(tmp_db)
        for i in range(12):
            db.insert_node(
                id=f"Vault{i:02d}.sol::Vault{i:02d}.transfer(address,uint256)",
                label="transfer",
                type="function",
                visibility="external",
                file=f"Vault{i:02d}.sol",
                line_start=i + 1,
                signature="function transfer(address to, uint256 amount) external",
                metadata=json.dumps({"source_context": "production"}),
            )

        real_open = mcp_server._open_query_connection

        class StreamingCursor:
            def __init__(self, cursor):
                self._cursor = cursor

            def __iter__(self):
                return iter(self._cursor)

            def fetchall(self):
                raise AssertionError("batched node loads should stream")

        class CountingConnection:
            def __init__(self, conn):
                self._conn = conn

            def execute(self, sql, *args, **kwargs):
                cursor = self._conn.execute(sql, *args, **kwargs)
                normalized = " ".join(sql.split())
                if "FROM nodes WHERE id IN" in normalized:
                    return StreamingCursor(cursor)
                return cursor

            def close(self):
                self._conn.close()

        monkeypatch.setattr(
            mcp_server,
            "_open_query_connection",
            lambda *args, **kwargs: CountingConnection(real_open(*args, **kwargs)),
        )

        lookup = json.loads(mcp_server.cs_lookup(
            name="transfer",
            db=tmp_db,
            max_matches=2,
            max_candidates=3,
        ))

        assert lookup["matches_total"] == 12
        assert lookup["matches"] == 2
        assert lookup["candidate_summary"] == {"total": 12, "shown": 3, "truncated": True}
        assert len(lookup["candidates"]) == 3

    def test_lookup_caps_relation_lists_for_llm_context(self, tmp_db):
        import mcp_server

        db = GraphDB(tmp_db)
        db.insert_node(
            id="Vault.sol::Vault.ping()",
            label="ping",
            type="function",
            visibility="external",
            file="Vault.sol",
        )
        for i in range(5):
            caller_id = f"Caller{i}.sol::Caller{i}.callPing()"
            db.insert_node(
                id=caller_id,
                label=f"callPing{i}",
                type="function",
                visibility="external",
                file=f"Caller{i}.sol",
            )
            db.insert_edge(caller_id, "Vault.sol::Vault.ping()", "calls")

        capped = json.loads(mcp_server.cs_lookup(name="ping", db=tmp_db, max_relation_items=2))
        uncapped = json.loads(mcp_server.cs_lookup(name="ping", db=tmp_db, max_relation_items=0))

        capped_fn = capped["functions"][0]
        uncapped_fn = uncapped["functions"][0]

        assert len(capped_fn["callers"]) == 2
        assert capped_fn["_relation_summary"]["callers"] == {"total": 5, "shown": 2, "truncated": True}
        assert capped["relation_truncated"] is True
        assert capped["max_relation_items"] == 2
        assert "max_relation_items=0" in capped["_warnings"][0]

        assert len(uncapped_fn["callers"]) == 5
        assert uncapped_fn["_relation_summary"]["callers"] == {"total": 5, "shown": 5, "truncated": False}
        assert "relation_truncated" not in uncapped

    def test_lookup_relation_caps_limit_materialized_rows(self, tmp_db, monkeypatch):
        import mcp_server

        db = GraphDB(tmp_db)
        db.insert_node(
            id="Vault.sol::Vault.ping()",
            label="ping",
            type="function",
            visibility="external",
            file="Vault.sol",
            metadata=json.dumps({"source_context": "production"}),
        )
        for i in range(80):
            caller_id = f"Caller{i}.sol::Caller{i}.callPing()"
            db.insert_node(
                id=caller_id,
                label=f"callPing{i}",
                type="function",
                visibility="external",
                file=f"Caller{i}.sol",
            )
            db.insert_edge(caller_id, "Vault.sol::Vault.ping()", "calls")

        real_open = mcp_server._open_query_connection
        real_load = mcp_server._load_metadata
        statements = []
        parsed = []

        class StreamingCursor:
            def __init__(self, cursor):
                self._cursor = cursor

            def __iter__(self):
                return iter(self._cursor)

            def fetchall(self):
                raise AssertionError("limited lookup relation rows should stream")

        class CountingConnection:
            def __init__(self, conn):
                self._conn = conn

            def execute(self, sql, *args, **kwargs):
                normalized = " ".join(sql.split())
                statements.append(normalized)
                cursor = self._conn.execute(sql, *args, **kwargs)
                if "LIMIT ?" in normalized:
                    return StreamingCursor(cursor)
                return cursor

            def close(self):
                self._conn.close()

        def counting_open(*args, **kwargs):
            return CountingConnection(real_open(*args, **kwargs))

        def counting_load(raw):
            parsed.append(raw)
            return real_load(raw)

        monkeypatch.setattr(mcp_server, "_open_query_connection", counting_open)
        monkeypatch.setattr(mcp_server, "_load_metadata", counting_load)

        lookup = json.loads(mcp_server.cs_lookup(
            name="ping",
            db=tmp_db,
            max_relation_items=2,
        ))

        fn = lookup["functions"][0]
        assert len(fn["callers"]) == 2
        assert fn["_relation_summary"]["callers"] == {"total": 80, "shown": 2, "truncated": True}
        assert len(parsed) == 1
        assert any("INDEXED BY idx_edges_target_relation" in sql for sql in statements)
        assert any("INDEXED BY idx_edges_source_relation" in sql for sql in statements)
        assert any("WHERE e.target = ? AND e.relation = 'calls' LIMIT ?" in sql for sql in statements)
        assert any(
            "SELECT COUNT(*) FROM edges AS e INDEXED BY idx_edges_target_relation" in sql
            and "WHERE e.target = ? AND e.relation = 'calls'" in sql
            for sql in statements
        )
        assert not any(
            sql.startswith("SELECT COUNT(*) FROM edges AS e JOIN")
            or sql.startswith("SELECT COUNT(*) FROM edges e JOIN")
            for sql in statements
        )

    def test_lookup_formats_known_relation_contexts_without_parse(self, tmp_db, monkeypatch):
        import mcp_server

        db = GraphDB(tmp_db)
        target_metadata = json.dumps({"source_context": "production"})
        db.insert_node(
            id="Vault.sol::Vault.ping()",
            label="ping",
            type="function",
            visibility="external",
            file="Vault.sol",
            metadata=target_metadata,
        )
        db.insert_node(
            id="Vault.sol::Vault.prodCaller()",
            label="prodCaller",
            type="function",
            visibility="external",
            file="Vault.sol",
            metadata=json.dumps({}),
        )
        db.insert_node(
            id="scripts/Deploy.sol::Deploy.run()",
            label="run",
            type="function",
            visibility="external",
            file="scripts/Deploy.sol",
            metadata=json.dumps({"source_context": "script", "large": ["x"] * 20}),
        )
        db.insert_edge("Vault.sol::Vault.prodCaller()", "Vault.sol::Vault.ping()", "calls")
        db.insert_edge("scripts/Deploy.sol::Deploy.run()", "Vault.sol::Vault.ping()", "calls")

        real_load = mcp_server._load_metadata
        parsed = []

        def counting_load(raw):
            parsed.append(raw)
            return real_load(raw)

        monkeypatch.setattr(mcp_server, "_load_metadata", counting_load)

        lookup = json.loads(mcp_server.cs_lookup(
            name="ping",
            db=tmp_db,
            max_relation_items=10,
        ))

        callers = {
            caller["label"]: caller["source_context"]
            for caller in lookup["functions"][0]["callers"]
        }
        assert callers == {"prodCaller": "production", "run": "script"}
        assert parsed == [target_metadata]

    def test_lookup_exclude_research_filters_relations_without_parse(self, tmp_db, monkeypatch):
        import mcp_server

        db = GraphDB(tmp_db)
        target_metadata = json.dumps({"source_context": "production"})
        prod_caller_metadata = json.dumps({"source_context": "production", "large": ["x"] * 20})
        script_caller_metadata = json.dumps({"source_context": "script", "large": ["x"] * 20})
        db.insert_node(
            id="Vault.sol::Vault.ping()",
            label="ping",
            type="function",
            visibility="external",
            file="Vault.sol",
            metadata=target_metadata,
        )
        db.insert_node(
            id="Vault.sol::Vault.prodCaller()",
            label="prodCaller",
            type="function",
            visibility="external",
            file="Vault.sol",
            metadata=prod_caller_metadata,
        )
        db.insert_node(
            id="scripts/Deploy.sol::Deploy.run()",
            label="run",
            type="function",
            visibility="external",
            file="scripts/Deploy.sol",
            metadata=script_caller_metadata,
        )
        db.insert_edge("Vault.sol::Vault.prodCaller()", "Vault.sol::Vault.ping()", "calls")
        db.insert_edge("scripts/Deploy.sol::Deploy.run()", "Vault.sol::Vault.ping()", "calls")

        real_load = mcp_server._load_metadata
        parsed = []

        def counting_load(raw):
            parsed.append(raw)
            return real_load(raw)

        monkeypatch.setattr(mcp_server, "_load_metadata", counting_load)

        lookup = json.loads(mcp_server.cs_lookup(
            name="ping",
            db=tmp_db,
            exclude_research=True,
            max_relation_items=10,
        ))

        callers = lookup["functions"][0]["callers"]
        assert [caller["label"] for caller in callers] == ["prodCaller"]
        assert callers[0]["source_context"] == "production"
        assert lookup["functions"][0]["_relation_summary"]["callers"] == {
            "total": 1,
            "shown": 1,
            "truncated": False,
        }
        assert parsed == [target_metadata]

    def test_trace_filters_research_state_accessors(self, tmp_path, tmp_db):
        import mcp_server

        repo = tmp_path / "repo"
        repo.mkdir()
        scripts = repo / "scripts"
        scripts.mkdir()
        (repo / "Vault.sol").write_text(
            "pragma solidity ^0.8.0;\n"
            "contract Vault {\n"
            "    uint256 public total;\n"
            "    function set(uint256 x) external {\n"
            "        total = x;\n"
            "    }\n"
            "}\n"
        )
        (scripts / "Deploy.s.sol").write_text(
            "pragma solidity ^0.8.0;\n"
            "contract DeployScript {\n"
            "    uint256 public total;\n"
            "    function run(uint256 x) external {\n"
            "        total = x;\n"
            "    }\n"
            "}\n"
        )

        indexer = Indexer(str(repo), include_research=True)
        indexer.index(tmp_db)

        trace = json.loads(mcp_server.cs_trace(var="total", db=tmp_db))
        writer_contexts = {item["label"]: item["source_context"] for item in trace["writers"]}
        variable_contexts = {item["file"]: item["source_context"] for item in trace["variables"]}
        assert trace["variable_matches"] == 2
        assert trace["query_scope"] == "all_sources"
        assert writer_contexts["set"] == "production"
        assert writer_contexts["run"] == "script"
        assert variable_contexts["Vault.sol"] == "production"
        assert variable_contexts["scripts/Deploy.s.sol"] == "script"

        prod_trace = json.loads(mcp_server.cs_trace(var="total", db=tmp_db, exclude_research=True))
        prod_writer_contexts = {item["label"]: item["source_context"] for item in prod_trace["writers"]}
        assert prod_trace["variable_matches"] == 1
        assert prod_trace["query_scope"] == "production_only"
        assert prod_writer_contexts == {"set": "production"}

    def test_trace_preserves_exact_match_stage_when_excluding_research(self, tmp_db, monkeypatch):
        import mcp_server

        db = GraphDB(tmp_db)
        db.insert_node(
            id="scripts/Deploy.sol::Deploy.total",
            label="total",
            type="state_var",
            file="scripts/Deploy.sol",
            metadata=json.dumps({"source_context": "script"}),
        )
        db.insert_node(
            id="Vault.sol::Vault.totalSupply",
            label="totalSupply",
            type="state_var",
            file="Vault.sol",
            metadata=json.dumps({"source_context": "production"}),
        )

        real_load = mcp_server._load_metadata
        parsed = []

        def counting_load(raw):
            parsed.append(raw)
            return real_load(raw)

        monkeypatch.setattr(mcp_server, "_load_metadata", counting_load)

        trace = json.loads(mcp_server.cs_trace(
            var="total",
            db=tmp_db,
            exclude_research=True,
        ))

        assert trace == {"error": "No production state variable found matching 'total'"}
        assert parsed == []

    def test_trace_caps_ambiguous_variables_for_llm_context(self, tmp_db):
        import mcp_server

        db = GraphDB(tmp_db)
        for i in range(5):
            db.insert_node(
                id=f"Vault{i}.sol::Vault{i}.total",
                label="total",
                type="state_var",
                file=f"Vault{i}.sol",
                signature="uint256 public total",
            )
            db.insert_node(
                id=f"Vault{i}.sol::Vault{i}.set(uint256)",
                label=f"set{i}",
                type="function",
                visibility="external",
                file=f"Vault{i}.sol",
                line_start=i + 1,
            )
            db.insert_edge(
                source=f"Vault{i}.sol::Vault{i}.set(uint256)",
                target=f"Vault{i}.sol::Vault{i}.total",
                relation="writes_state",
            )

        capped = json.loads(mcp_server.cs_trace(var="total", db=tmp_db, max_matches=2, max_candidates=3))
        uncapped = json.loads(mcp_server.cs_trace(var="total", db=tmp_db, max_matches=0))

        assert capped["variable_matches"] == 2
        assert capped["variable_matches_total"] == 5
        assert capped["truncated"] is True
        assert capped["max_matches"] == 2
        assert capped["max_candidates"] == 3
        assert len(capped["candidates"]) == 3
        assert capped["candidate_summary"] == {"total": 5, "shown": 3, "truncated": True}
        assert "max_candidates=0" in capped["_warnings"][0]
        assert len(capped["writers"]) == 2
        assert "max_matches=0" in capped["_warning"]

        assert uncapped["variable_matches"] == 5
        assert uncapped["variable_matches_total"] == 5
        assert uncapped["truncated"] is False
        assert uncapped["max_candidates"] == 50
        assert len(uncapped["writers"]) == 5
        assert "candidates" not in uncapped

    def test_trace_state_var_matching_uses_type_scoped_query(self, tmp_db, monkeypatch):
        import mcp_server

        db = GraphDB(tmp_db)
        db.insert_node(
            id="Vault.sol::Vault.total",
            label="total",
            type="state_var",
            file="Vault.sol",
        )
        db.insert_node(
            id="Vault.sol::Vault.set(uint256)",
            label="set",
            type="function",
            visibility="external",
            file="Vault.sol",
        )
        db.insert_edge(
            "Vault.sol::Vault.set(uint256)",
            "Vault.sol::Vault.total",
            "writes_state",
        )

        real_open = mcp_server._open_query_connection
        match_queries = []
        edge_queries = []

        class CountingConnection:
            def __init__(self, conn):
                self._conn = conn

            def execute(self, sql, *args, **kwargs):
                normalized = " ".join(sql.split())
                if "FROM nodes" in normalized and "state_var" in normalized:
                    match_queries.append(normalized)
                if (
                    "FROM edges" in normalized
                    and "e.target = ?" in normalized
                    and "e.relation = ?" in normalized
                ):
                    edge_queries.append(normalized)
                return self._conn.execute(sql, *args, **kwargs)

            def close(self):
                self._conn.close()

        monkeypatch.setattr(
            mcp_server,
            "_open_query_connection",
            lambda *args, **kwargs: CountingConnection(real_open(*args, **kwargs)),
        )

        trace = json.loads(mcp_server.cs_trace(var="total", db=tmp_db))

        assert trace["variable_matches_total"] == 1
        assert any("WHERE type = 'state_var' AND label = ?" in sql for sql in match_queries)
        assert not any("WHERE label = ? AND type = 'state_var'" in sql for sql in match_queries)
        assert any("INDEXED BY idx_edges_target_relation" in sql for sql in edge_queries)

    def test_trace_formats_only_capped_variable_candidates(self, tmp_db, monkeypatch):
        import mcp_server

        db = GraphDB(tmp_db)
        for i in range(12):
            db.insert_node(
                id=f"Vault{i:02d}.sol::Vault{i:02d}.total",
                label="total",
                type="state_var",
                file=f"Vault{i:02d}.sol",
                signature="uint256 public total",
                metadata=json.dumps({"source_context": f"custom{i}", "large": ["x"] * 20}),
            )

        real_load = mcp_server._load_metadata
        parsed = []

        def counting_load(raw):
            parsed.append(raw)
            return real_load(raw)

        monkeypatch.setattr(mcp_server, "_load_metadata", counting_load)

        trace = json.loads(mcp_server.cs_trace(
            var="total",
            db=tmp_db,
            max_matches=2,
            max_candidates=4,
        ))

        assert trace["variable_matches"] == 2
        assert trace["variable_matches_total"] == 12
        assert trace["candidate_summary"] == {"total": 12, "shown": 4, "truncated": True}
        assert len(trace["candidates"]) == 4
        assert len(parsed) == 4

    def test_trace_omits_variable_metadata_by_default_for_mcp_context(self, tmp_db):
        import mcp_server

        db = GraphDB(tmp_db)
        db.insert_node(
            id="Vault.sol::Vault.total",
            label="total",
            type="state_var",
            file="Vault.sol",
            signature="uint256 public total",
            metadata=json.dumps({
                "source_context": "production",
                "large": ["x"] * 50,
            }),
        )
        db.insert_node(
            id="Vault.sol::Vault.set(uint256)",
            label="set",
            type="function",
            visibility="external",
            file="Vault.sol",
            metadata=json.dumps({"source_context": "production"}),
        )
        db.insert_edge(
            "Vault.sol::Vault.set(uint256)",
            "Vault.sol::Vault.total",
            "writes_state",
        )

        compact = json.loads(mcp_server.cs_trace(var="total", db=tmp_db))
        detailed = json.loads(mcp_server.cs_trace(var="total", db=tmp_db, include_metadata=True))

        assert compact["include_metadata"] is False
        assert compact["variable"]["source_context"] == "production"
        assert "metadata" not in compact["variable"]
        assert "metadata" not in compact["variables"][0]
        assert compact["writers"][0]["source_context"] == "production"
        assert detailed["include_metadata"] is True
        assert detailed["variable"]["metadata"]["large"] == ["x"] * 50

    def test_trace_retains_only_capped_variable_rows(self, tmp_db, monkeypatch):
        import mcp_server

        db = GraphDB(tmp_db)
        for i in range(40):
            db.insert_node(
                id=f"Vault{i:02d}.sol::Vault{i:02d}.total",
                label="total",
                type="state_var",
                file=f"Vault{i:02d}.sol",
                signature="uint256 public total",
                metadata=json.dumps({"source_context": "production"}),
            )

        real_append = mcp_server._append_capped
        variable_buffer_sizes = []

        def tracking_append(items, item, total, limit):
            updated = real_append(items, item, total, limit)
            if (
                isinstance(item, dict)
                and item.get("type") is None
                and item.get("label") == "total"
            ):
                variable_buffer_sizes.append(len(items))
            return updated

        monkeypatch.setattr(mcp_server, "_append_capped", tracking_append)

        trace = json.loads(mcp_server.cs_trace(
            var="total",
            db=tmp_db,
            max_matches=2,
            max_candidates=4,
        ))

        assert trace["variable_matches"] == 2
        assert trace["variable_matches_total"] == 40
        assert trace["candidate_summary"] == {"total": 40, "shown": 4, "truncated": True}
        assert max(variable_buffer_sizes) == 4

    def test_trace_caps_show_callers_for_llm_context(self, tmp_db):
        import mcp_server

        db = GraphDB(tmp_db)
        db.insert_node(
            id="Vault.sol::Vault.total",
            label="total",
            type="state_var",
            file="Vault.sol",
        )
        db.insert_node(
            id="Vault.sol::Vault.set(uint256)",
            label="set",
            type="function",
            visibility="internal",
            file="Vault.sol",
        )
        db.insert_edge("Vault.sol::Vault.set(uint256)", "Vault.sol::Vault.total", "writes_state")
        for i in range(5):
            caller_id = f"Caller{i}.sol::Caller{i}.callSet()"
            db.insert_node(
                id=caller_id,
                label=f"callSet{i}",
                type="function",
                visibility="external",
                file=f"Caller{i}.sol",
            )
            db.insert_edge(caller_id, "Vault.sol::Vault.set(uint256)", "calls")

        capped = json.loads(mcp_server.cs_trace(
            var="total",
            db=tmp_db,
            show_callers=True,
            max_callers_per_accessor=2,
        ))
        uncapped = json.loads(mcp_server.cs_trace(
            var="total",
            db=tmp_db,
            show_callers=True,
            max_callers_per_accessor=0,
        ))

        writer = capped["writers"][0]
        assert len(writer["callers"]) == 2
        assert writer["callers_summary"] == {"total": 5, "shown": 2, "truncated": True}
        assert capped["caller_truncated"] is True
        assert "max_callers_per_accessor=0" in capped["_warnings"][0]

        uncapped_writer = uncapped["writers"][0]
        assert len(uncapped_writer["callers"]) == 5
        assert uncapped_writer["callers_summary"] == {"total": 5, "shown": 5, "truncated": False}
        assert "caller_truncated" not in uncapped

    def test_trace_caps_accessor_lists_for_llm_context(self, tmp_db, monkeypatch):
        import mcp_server

        db = GraphDB(tmp_db)
        state_id = "Vault.sol::Vault.total"
        db.insert_node(
            id=state_id,
            label="total",
            type="state_var",
            file="Vault.sol",
            metadata=json.dumps({"source_context": "custom_state"}),
        )
        for i in range(8):
            writer_id = f"Writer{i:02d}.sol::Writer{i:02d}.set(uint256)"
            db.insert_node(
                id=writer_id,
                label=f"set{i:02d}",
                type="function",
                visibility="external",
                file=f"Writer{i:02d}.sol",
                line_start=i + 1,
                metadata=json.dumps({"source_context": f"custom_writer{i}", "large": ["x"] * 20}),
            )
            db.insert_edge(writer_id, state_id, "writes_state")

        real_load = mcp_server._load_metadata
        parsed = []

        def counting_load(raw):
            parsed.append(raw)
            return real_load(raw)

        monkeypatch.setattr(mcp_server, "_load_metadata", counting_load)

        capped = json.loads(mcp_server.cs_trace(
            var="total",
            db=tmp_db,
            max_accessors_per_relation=3,
        ))
        uncapped = json.loads(mcp_server.cs_trace(
            var="total",
            db=tmp_db,
            max_accessors_per_relation=0,
        ))

        assert capped["writers_summary"] == {"total": 8, "shown": 3, "truncated": True}
        assert capped["readers_summary"] == {"total": 0, "shown": 0, "truncated": False}
        assert capped["accessor_truncated"] is True
        assert "max_accessors_per_relation=0" in capped["_warnings"][0]
        assert capped["max_accessors_per_relation"] == 3
        assert [writer["label"] for writer in capped["writers"]] == ["set00", "set01", "set02"]
        assert len(uncapped["writers"]) == 8
        assert uncapped["writers_summary"] == {"total": 8, "shown": 8, "truncated": False}
        assert "accessor_truncated" not in uncapped
        assert len(parsed) == 13

    def test_trace_streams_accessor_and_caller_rows(self, tmp_db, monkeypatch):
        import mcp_server

        db = GraphDB(tmp_db)
        state_id = "Vault.sol::Vault.total"
        writer_id = "Vault.sol::Vault.set(uint256)"
        db.insert_node(
            id=state_id,
            label="total",
            type="state_var",
            file="Vault.sol",
            metadata=json.dumps({"source_context": "production"}),
        )
        db.insert_node(
            id=writer_id,
            label="set",
            type="function",
            visibility="internal",
            file="Vault.sol",
            metadata=json.dumps({"source_context": "production"}),
        )
        db.insert_edge(writer_id, state_id, "writes_state")
        for i in range(3):
            caller_id = f"Caller{i}.sol::Caller{i}.callSet()"
            db.insert_node(
                id=caller_id,
                label=f"callSet{i}",
                type="function",
                visibility="external",
                file=f"Caller{i}.sol",
                metadata=json.dumps({"source_context": "production"}),
            )
            db.insert_edge(caller_id, writer_id, "calls")

        real_open = mcp_server._open_query_connection

        class StreamingRows:
            def __init__(self, rows):
                self.rows = rows

            def __iter__(self):
                return iter(self.rows)

            def fetchall(self):
                raise AssertionError("cs_trace rows should stream")

        class StreamingConnection:
            def __init__(self, conn):
                self._conn = conn

            def execute(self, sql, *args, **kwargs):
                cursor = self._conn.execute(sql, *args, **kwargs)
                if "COUNT(*)" in " ".join(sql.split()):
                    return cursor
                return StreamingRows(cursor)

            def close(self):
                self._conn.close()

        monkeypatch.setattr(
            mcp_server,
            "_open_query_connection",
            lambda *args, **kwargs: StreamingConnection(real_open(*args, **kwargs)),
        )

        trace = json.loads(mcp_server.cs_trace(
            var="total",
            db=tmp_db,
            show_callers=True,
            max_callers_per_accessor=2,
        ))

        assert trace["writers"][0]["label"] == "set"
        assert trace["writers"][0]["callers_summary"] == {"total": 3, "shown": 2, "truncated": True}
        assert len(trace["writers"][0]["callers"]) == 2

    def test_trace_retains_only_capped_callers(self, tmp_db, monkeypatch):
        import mcp_server

        db = GraphDB(tmp_db)
        db.insert_node(
            id="Vault.sol::Vault.total",
            label="total",
            type="state_var",
            file="Vault.sol",
            metadata=json.dumps({"source_context": "production"}),
        )
        db.insert_node(
            id="Vault.sol::Vault.set(uint256)",
            label="set",
            type="function",
            visibility="internal",
            file="Vault.sol",
            metadata=json.dumps({"source_context": "production"}),
        )
        db.insert_edge("Vault.sol::Vault.set(uint256)", "Vault.sol::Vault.total", "writes_state")
        for i in range(40):
            caller_id = f"Caller{i:02d}.sol::Caller{i:02d}.callSet()"
            db.insert_node(
                id=caller_id,
                label=f"callSet{i:02d}",
                type="function",
                visibility="external",
                file=f"Caller{i:02d}.sol",
                metadata=json.dumps({"source_context": f"custom_caller{i}", "large": ["x"] * 20}),
            )
            db.insert_edge(caller_id, "Vault.sol::Vault.set(uint256)", "calls")

        real_open = mcp_server._open_query_connection
        real_load = mcp_server._load_metadata
        statements = []
        parsed = []

        class StreamingCursor:
            def __init__(self, cursor):
                self._cursor = cursor

            def __iter__(self):
                return iter(self._cursor)

            def fetchall(self):
                raise AssertionError("limited trace caller rows should stream")

        class CountingConnection:
            def __init__(self, conn):
                self._conn = conn

            def execute(self, sql, *args, **kwargs):
                normalized = " ".join(sql.split())
                statements.append(normalized)
                cursor = self._conn.execute(sql, *args, **kwargs)
                if "ORDER BY n.file, n.id LIMIT ?" in normalized:
                    return StreamingCursor(cursor)
                return cursor

            def close(self):
                self._conn.close()

        def counting_load(raw):
            parsed.append(raw)
            return real_load(raw)

        monkeypatch.setattr(
            mcp_server,
            "_open_query_connection",
            lambda *args, **kwargs: CountingConnection(real_open(*args, **kwargs)),
        )
        monkeypatch.setattr(mcp_server, "_load_metadata", counting_load)

        trace = json.loads(mcp_server.cs_trace(
            var="total",
            db=tmp_db,
            show_callers=True,
            max_callers_per_accessor=3,
        ))

        writer = trace["writers"][0]
        assert writer["callers_summary"] == {"total": 40, "shown": 3, "truncated": True}
        assert [caller["label"] for caller in writer["callers"]] == ["callSet00", "callSet01", "callSet02"]
        assert any("SELECT COUNT(*) FROM edges AS e INDEXED BY idx_edges_target_relation" in sql for sql in statements)
        assert any("ORDER BY n.file, n.id LIMIT ?" in sql for sql in statements)
        assert len(parsed) == 3

    def test_trace_skips_untagged_source_context_parses(self, tmp_db, monkeypatch):
        import mcp_server

        db = GraphDB(tmp_db)
        state_id = "Vault.sol::Vault.total"
        writer_id = "Vault.sol::Vault.set(uint256)"
        caller_id = "Caller.sol::Caller.callSet()"
        untagged_metadata = json.dumps({"large": ["x"] * 20})
        db.insert_node(
            id=state_id,
            label="total",
            type="state_var",
            file="Vault.sol",
            metadata=untagged_metadata,
        )
        db.insert_node(
            id=writer_id,
            label="set",
            type="function",
            visibility="internal",
            file="Vault.sol",
            metadata=untagged_metadata,
        )
        db.insert_node(
            id=caller_id,
            label="callSet",
            type="function",
            visibility="external",
            file="Caller.sol",
            metadata=untagged_metadata,
        )
        db.insert_edge(writer_id, state_id, "writes_state")
        db.insert_edge(caller_id, writer_id, "calls")

        real_load = mcp_server._load_metadata
        parsed = []

        def counting_load(raw):
            parsed.append(raw)
            return real_load(raw)

        monkeypatch.setattr(mcp_server, "_load_metadata", counting_load)

        trace = json.loads(mcp_server.cs_trace(
            var="total",
            db=tmp_db,
            show_callers=True,
            max_accessors_per_relation=0,
            max_callers_per_accessor=0,
        ))

        writer = trace["writers"][0]
        caller = writer["callers"][0]
        assert trace["variables"][0]["source_context"] == "production"
        assert writer["source_context"] == "production"
        assert caller["source_context"] == "production"
        assert parsed == []

    def test_paths_filter_research_paths(self, tmp_path, tmp_db):
        import mcp_server

        repo = tmp_path / "repo"
        repo.mkdir()
        scripts = repo / "scripts"
        scripts.mkdir()
        (repo / "Vault.sol").write_text(
            "pragma solidity ^0.8.0;\n"
            "contract Vault {\n"
            "    function finish() internal {}\n"
            "    function start() external {\n"
            "        finish();\n"
            "    }\n"
            "}\n"
        )
        (scripts / "Deploy.s.sol").write_text(
            "pragma solidity ^0.8.0;\n"
            "contract DeployScript {\n"
            "    function finish() internal {}\n"
            "    function start() external {\n"
            "        finish();\n"
            "    }\n"
            "}\n"
        )

        indexer = Indexer(str(repo), include_research=True)
        indexer.index(tmp_db)

        paths = json.loads(mcp_server.cs_paths(from_label="start", to_label="finish", db=tmp_db))
        assert paths["query_scope"] == "all_sources"
        assert ["Vault.start", "Vault.finish"] in paths["paths"]
        assert ["DeployScript.start", "DeployScript.finish"] in paths["paths"]

        prod_paths = json.loads(mcp_server.cs_paths(
            from_label="start",
            to_label="finish",
            db=tmp_db,
            exclude_research=True,
        ))
        assert prod_paths["query_scope"] == "production_only"
        assert prod_paths["paths"] == [["Vault.start", "Vault.finish"]]

    def test_paths_avoids_metadata_parse_for_all_source_search(self, tmp_db, monkeypatch):
        import mcp_server

        db = GraphDB(tmp_db)
        db.insert_node(
            id="Vault.sol::Vault.start()",
            label="start",
            type="function",
            file="Vault.sol",
            metadata=json.dumps({"source_context": "production"}),
        )
        db.insert_node(
            id="Vault.sol::Vault.finish()",
            label="finish",
            type="function",
            file="Vault.sol",
            metadata=json.dumps({"source_context": "production"}),
        )
        db.insert_edge("Vault.sol::Vault.start()", "Vault.sol::Vault.finish()", "calls")
        for i in range(200):
            db.insert_node(
                id=f"scripts/Helper{i}.sol::Helper{i}.noop()",
                label=f"noop{i}",
                type="function",
                file=f"scripts/Helper{i}.sol",
                metadata=json.dumps({"source_context": "script", "large": ["x"] * 20}),
            )

        real_load = mcp_server._load_metadata
        parsed = []

        def counting_load(raw):
            parsed.append(raw)
            return real_load(raw)

        monkeypatch.setattr(mcp_server, "_load_metadata", counting_load)

        paths = json.loads(mcp_server.cs_paths(
            from_label="start",
            to_label="finish",
            db=tmp_db,
        ))

        assert paths["paths"] == [["start", "finish"]]
        assert parsed == []

    def test_paths_streams_graph_rows(self, tmp_db, monkeypatch):
        import mcp_server

        db = GraphDB(tmp_db)
        start_id = "Vault.sol::Vault.start()"
        finish_id = "Vault.sol::Vault.finish()"
        db.insert_node(
            id=start_id,
            label="start",
            type="function",
            file="Vault.sol",
            metadata=json.dumps({"source_context": "production"}),
        )
        db.insert_node(
            id=finish_id,
            label="finish",
            type="function",
            file="Vault.sol",
            metadata=json.dumps({"source_context": "production"}),
        )
        db.insert_edge(start_id, finish_id, "calls")

        real_open = mcp_server._open_query_connection
        statements = []

        class StreamingRows:
            def __init__(self, rows):
                self.rows = rows

            def __iter__(self):
                return iter(self.rows)

            def fetchall(self):
                raise AssertionError("cs_paths graph rows should stream")

        class StreamingConnection:
            def __init__(self, conn):
                self._conn = conn

            def execute(self, sql, *args, **kwargs):
                normalized = " ".join(sql.split())
                statements.append(normalized)
                if normalized == "SELECT id, label, file, metadata FROM nodes":
                    raise AssertionError("cs_paths should not preload all nodes")
                if "SELECT source, target FROM edges" in normalized and "relation IN" in normalized:
                    raise AssertionError("cs_paths should not scan all traversal edges")
                rows = self._conn.execute(sql, *args, **kwargs)
                if "INDEXED BY idx_edges_source_relation" in normalized:
                    return StreamingRows(rows)
                return rows

            def close(self):
                self._conn.close()

        monkeypatch.setattr(
            mcp_server,
            "_open_query_connection",
            lambda *args, **kwargs: StreamingConnection(real_open(*args, **kwargs)),
        )

        paths = json.loads(mcp_server.cs_paths(
            from_label="start",
            to_label="finish",
            db=tmp_db,
        ))

        assert paths["paths"] == [["start", "finish"]]
        assert paths["_summary"]["paths_found"] == 1
        assert any("INDEXED BY idx_edges_source_relation" in sql for sql in statements)
        assert any("e.source = ? AND e.relation IN" in sql for sql in statements)

    def test_paths_preserves_exact_match_stage_when_excluding_research(self, tmp_db, monkeypatch):
        import mcp_server

        db = GraphDB(tmp_db)
        db.insert_node(
            id="scripts/Deploy.sol::Deploy.start()",
            label="start",
            type="function",
            file="scripts/Deploy.sol",
            metadata=json.dumps({"source_context": "script"}),
        )
        db.insert_node(
            id="Vault.sol::Vault.startProduction()",
            label="startProduction",
            type="function",
            file="Vault.sol",
            metadata=json.dumps({"source_context": "production"}),
        )
        db.insert_node(
            id="Vault.sol::Vault.finish()",
            label="finish",
            type="function",
            file="Vault.sol",
            metadata=json.dumps({"source_context": "production"}),
        )

        real_load = mcp_server._load_metadata
        parsed = []

        def counting_load(raw):
            parsed.append(raw)
            return real_load(raw)

        monkeypatch.setattr(mcp_server, "_load_metadata", counting_load)

        paths = json.loads(mcp_server.cs_paths(
            from_label="start",
            to_label="finish",
            db=tmp_db,
            exclude_research=True,
        ))

        assert paths == {"error": "No production node found matching 'start'"}
        assert parsed == []

    def test_paths_cap_ambiguous_endpoints_for_llm_context(self, tmp_db):
        import mcp_server

        db = GraphDB(tmp_db)
        for i in range(5):
            start_id = f"Vault{i}.sol::Vault{i}.start()"
            finish_id = f"Vault{i}.sol::Vault{i}.finish()"
            db.insert_node(
                id=start_id,
                label="start",
                type="function",
                visibility="external",
                file=f"Vault{i}.sol",
                line_start=i + 1,
            )
            db.insert_node(
                id=finish_id,
                label="finish",
                type="function",
                visibility="internal",
                file=f"Vault{i}.sol",
                line_start=i + 10,
            )
            db.insert_edge(start_id, finish_id, "calls")

        capped = json.loads(mcp_server.cs_paths(
            from_label="start",
            to_label="finish",
            db=tmp_db,
            max_paths=2,
            max_endpoint_matches=2,
            max_endpoint_candidates=3,
        ))
        uncapped = json.loads(mcp_server.cs_paths(
            from_label="start",
            to_label="finish",
            db=tmp_db,
            max_paths=0,
            max_endpoint_matches=0,
        ))

        assert len(capped["paths"]) == 2
        assert capped["_summary"]["paths_found"] == 2
        assert capped["_summary"]["path_limit_reached"] is True
        assert capped["_summary"]["from_matches_total"] == 5
        assert capped["_summary"]["from_matches_used"] == 2
        assert capped["_summary"]["to_matches_total"] == 5
        assert capped["_summary"]["to_matches_used"] == 2
        assert capped["_summary"]["endpoint_matches_truncated"] is True
        assert capped["_summary"]["truncated"] is True
        assert capped["_summary"]["max_endpoint_candidates"] == 3
        assert len(capped["from_candidates"]) == 3
        assert len(capped["to_candidates"]) == 3
        assert capped["_summary"]["from_candidates"] == {"total": 5, "shown": 3, "truncated": True}
        assert capped["_summary"]["to_candidates"] == {"total": 5, "shown": 3, "truncated": True}
        assert "max_endpoint_candidates=0" in capped["_warnings"][0]

        assert len(uncapped["paths"]) == 5
        assert uncapped["_summary"]["path_limit_reached"] is False
        assert uncapped["_summary"]["endpoint_matches_truncated"] is False
        assert uncapped["_summary"]["truncated"] is False

    def test_paths_formats_only_capped_endpoint_candidates(self, tmp_db, monkeypatch):
        import mcp_server

        db = GraphDB(tmp_db)
        for i in range(8):
            start_id = f"Vault{i}.sol::Vault{i}.start()"
            finish_id = f"Vault{i}.sol::Vault{i}.finish()"
            metadata = json.dumps({"source_context": "production", "large": ["x"] * 20})
            db.insert_node(
                id=start_id,
                label="start",
                type="function",
                visibility="external",
                file=f"Vault{i}.sol",
                line_start=i + 1,
                metadata=metadata,
            )
            db.insert_node(
                id=finish_id,
                label="finish",
                type="function",
                visibility="internal",
                file=f"Vault{i}.sol",
                line_start=i + 10,
                metadata=metadata,
            )
            db.insert_edge(start_id, finish_id, "calls")

        real_load = mcp_server._load_metadata
        parsed = []

        def counting_load(raw):
            parsed.append(raw)
            return real_load(raw)

        monkeypatch.setattr(mcp_server, "_load_metadata", counting_load)

        paths = json.loads(mcp_server.cs_paths(
            from_label="start",
            to_label="finish",
            db=tmp_db,
            max_paths=1,
            max_endpoint_matches=1,
            max_endpoint_candidates=2,
        ))

        assert paths["_summary"]["from_candidates"] == {"total": 8, "shown": 2, "truncated": True}
        assert paths["_summary"]["to_candidates"] == {"total": 8, "shown": 2, "truncated": True}
        assert len(paths["from_candidates"]) == 2
        assert len(paths["to_candidates"]) == 2
        assert len(parsed) == 4

    def test_paths_retains_only_capped_endpoint_rows(self, tmp_db, monkeypatch):
        import mcp_server

        db = GraphDB(tmp_db)
        for i in range(40):
            db.insert_node(
                id=f"Vault{i:02d}.sol::Vault{i:02d}.start()",
                label="start",
                type="function",
                visibility="external",
                file=f"Vault{i:02d}.sol",
                line_start=i + 1,
                metadata=json.dumps({"source_context": "production"}),
            )
            db.insert_node(
                id=f"Vault{i:02d}.sol::Vault{i:02d}.finish()",
                label="finish",
                type="function",
                visibility="internal",
                file=f"Vault{i:02d}.sol",
                line_start=i + 100,
                metadata=json.dumps({"source_context": "production"}),
            )

        real_append = mcp_server._append_capped
        endpoint_buffer_sizes = {"start": [], "finish": []}

        def tracking_append(items, item, total, limit):
            updated = real_append(items, item, total, limit)
            if isinstance(item, dict) and item.get("label") in endpoint_buffer_sizes:
                endpoint_buffer_sizes[item["label"]].append(len(items))
            return updated

        monkeypatch.setattr(mcp_server, "_append_capped", tracking_append)

        paths = json.loads(mcp_server.cs_paths(
            from_label="start",
            to_label="finish",
            db=tmp_db,
            max_paths=1,
            max_endpoint_matches=2,
            max_endpoint_candidates=3,
        ))

        assert paths["_summary"]["from_matches_total"] == 40
        assert paths["_summary"]["from_matches_used"] == 2
        assert paths["_summary"]["to_matches_total"] == 40
        assert paths["_summary"]["to_matches_used"] == 2
        assert paths["_summary"]["from_candidates"] == {"total": 40, "shown": 3, "truncated": True}
        assert paths["_summary"]["to_candidates"] == {"total": 40, "shown": 3, "truncated": True}
        assert max(endpoint_buffer_sizes["start"]) == 3
        assert max(endpoint_buffer_sizes["finish"]) == 3

    def test_paths_streams_guard_and_state_annotations(self, tmp_db, monkeypatch):
        import mcp_server

        db = GraphDB(tmp_db)
        start_id = "Vault.sol::Vault.start()"
        finish_id = "Vault.sol::Vault.finish()"
        guard_id = "Vault.sol::Vault.onlyOwner"
        state_id = "Vault.sol::Vault.total"
        db.insert_node(
            id=start_id,
            label="start",
            type="function",
            visibility="external",
            file="Vault.sol",
            metadata=json.dumps({"source_context": "production"}),
        )
        db.insert_node(
            id=finish_id,
            label="finish",
            type="function",
            visibility="internal",
            file="Vault.sol",
            metadata=json.dumps({"source_context": "production"}),
        )
        db.insert_node(
            id=guard_id,
            label="onlyOwner",
            type="modifier",
            file="Vault.sol",
            metadata=json.dumps({"source_context": "production"}),
        )
        db.insert_node(
            id=state_id,
            label="total",
            type="state_var",
            file="Vault.sol",
            metadata=json.dumps({"source_context": "production"}),
        )
        db.insert_edge(start_id, finish_id, "calls")
        db.insert_edge(guard_id, start_id, "guards")
        db.insert_edge(start_id, state_id, "reads_state")
        db.insert_edge(finish_id, state_id, "writes_state")

        real_open = mcp_server._open_query_connection
        statements = []

        class StreamingRows:
            def __init__(self, rows):
                self.rows = rows

            def __iter__(self):
                return iter(self.rows)

            def fetchall(self):
                raise AssertionError("cs_paths annotations should stream")

        class StreamingConnection:
            def __init__(self, conn):
                self._conn = conn

            def execute(self, sql, *args, **kwargs):
                normalized = " ".join(sql.split())
                statements.append(normalized)
                if normalized == "SELECT target FROM edges WHERE source=? AND relation='reads_state'":
                    raise AssertionError("cs_paths show_state should not issue a separate reads query")
                if normalized == "SELECT target FROM edges WHERE source=? AND relation='writes_state'":
                    raise AssertionError("cs_paths show_state should not issue a separate writes query")
                rows = self._conn.execute(sql, *args, **kwargs)
                if (
                    "e.relation = 'guards'" in normalized
                    or "e.relation IN ('reads_state', 'writes_state')" in normalized
                ):
                    return StreamingRows(rows)
                return rows

            def close(self):
                self._conn.close()

        monkeypatch.setattr(
            mcp_server,
            "_open_query_connection",
            lambda *args, **kwargs: StreamingConnection(real_open(*args, **kwargs)),
        )

        paths = json.loads(mcp_server.cs_paths(
            from_label="start",
            to_label="finish",
            db=tmp_db,
            show_guards=True,
            show_state=True,
        ))

        assert paths["guards"] == {"start": ["onlyOwner"]}
        assert paths["state_access"]["start"]["reads"] == ["Vault.total"]
        assert paths["state_access"]["finish"]["writes"] == ["Vault.total"]
        assert any("INDEXED BY idx_edges_source_relation" in sql for sql in statements)
        assert any("INDEXED BY idx_edges_target_relation" in sql for sql in statements)
        assert any("e.relation IN ('reads_state', 'writes_state')" in sql for sql in statements)

    def test_paths_show_state_omits_empty_state_access_entries(self, tmp_db):
        import mcp_server

        db = GraphDB(tmp_db)
        start_id = "Vault.sol::Vault.start()"
        middle_id = "Vault.sol::Vault.middle()"
        finish_id = "Vault.sol::Vault.finish()"
        state_id = "Vault.sol::Vault.total"
        for node_id, label in (
            (start_id, "start"),
            (middle_id, "middle"),
            (finish_id, "finish"),
        ):
            db.insert_node(
                id=node_id,
                label=label,
                type="function",
                file="Vault.sol",
            )
        db.insert_node(
            id=state_id,
            label="total",
            type="state_var",
            file="Vault.sol",
        )
        db.insert_edge(start_id, middle_id, "calls")
        db.insert_edge(middle_id, finish_id, "calls")
        db.insert_edge(start_id, state_id, "reads_state")

        paths = json.loads(mcp_server.cs_paths(
            from_label="start",
            to_label="finish",
            db=tmp_db,
            show_state=True,
        ))

        assert paths["paths"] == [["start", "middle", "finish"]]
        assert paths["state_access"] == {
            "start": {
                "reads": ["Vault.total"],
                "writes": [],
            }
        }

    def test_paths_show_guards_skips_metadata_parse_for_all_sources(self, tmp_db, monkeypatch):
        import mcp_server

        db = GraphDB(tmp_db)
        start_id = "Vault.sol::Vault.start()"
        finish_id = "Vault.sol::Vault.finish()"
        guard_id = "Vault.sol::Vault.onlyOwner"
        db.insert_node(
            id=start_id,
            label="start",
            type="function",
            file="Vault.sol",
        )
        db.insert_node(
            id=finish_id,
            label="finish",
            type="function",
            file="Vault.sol",
        )
        db.insert_node(
            id=guard_id,
            label="onlyOwner",
            type="modifier",
            file="Vault.sol",
            metadata=json.dumps({"source_context": "production", "large": ["x"] * 20}),
        )
        db.insert_edge(start_id, finish_id, "calls")
        db.insert_edge(guard_id, start_id, "guards")

        real_load = mcp_server._load_metadata
        parsed = []

        def counting_load(raw):
            parsed.append(raw)
            return real_load(raw)

        monkeypatch.setattr(mcp_server, "_load_metadata", counting_load)

        paths = json.loads(mcp_server.cs_paths(
            from_label="start",
            to_label="finish",
            db=tmp_db,
            show_guards=True,
        ))

        assert paths["guards"] == {"start": ["onlyOwner"]}
        assert parsed == []

    def test_state_filters_research_transitions(self, tmp_path, tmp_db):
        import mcp_server

        repo = tmp_path / "repo"
        repo.mkdir()
        scripts = repo / "scripts"
        scripts.mkdir()
        (repo / "Vault.sol").write_text(
            "pragma solidity ^0.8.0;\n"
            "contract Vault {\n"
            "    enum VaultState { Inactive, Closed }\n"
            "    VaultState public state;\n"
            "    function close() external {\n"
            "        state = VaultState.Closed;\n"
            "    }\n"
            "}\n"
        )
        (scripts / "Deploy.s.sol").write_text(
            "pragma solidity ^0.8.0;\n"
            "contract DeployScript {\n"
            "    enum VaultState { Inactive, Closed }\n"
            "    VaultState public state;\n"
            "    function close() external {\n"
            "        state = VaultState.Closed;\n"
            "    }\n"
            "}\n"
        )

        indexer = Indexer(str(repo), include_research=True)
        indexer.index(tmp_db)

        state = json.loads(mcp_server.cs_state(db=tmp_db))
        assert state["query_scope"] == "all_sources"
        assert "VaultState" in state["entities"]
        contexts = {item["function_file"]: item["source_context"] for item in state["entities"]["VaultState"]}
        assert contexts["Vault.sol"] == "production"
        assert contexts["scripts/Deploy.s.sol"] == "script"
        assert any("UNGUARDED: close() transitions VaultState to Closed" in warning for warning in state["warnings"])

        prod_state = json.loads(mcp_server.cs_state(db=tmp_db, exclude_research=True))
        assert prod_state["query_scope"] == "production_only"
        prod_contexts = {item["function_file"]: item["source_context"] for item in prod_state["entities"]["VaultState"]}
        assert prod_contexts == {"Vault.sol": "production"}
        assert prod_state["warnings"] == ["UNGUARDED: close() transitions VaultState to Closed without checking current state", "TERMINAL: VaultState::Closed has no outgoing transitions"]

    def test_state_caps_broad_entity_output_for_llm_context(self, tmp_db):
        import mcp_server

        db = GraphDB(tmp_db)
        for i in range(5):
            fn_id = f"Vault{i}.sol::Vault{i}.advance()"
            db.insert_node(
                id=fn_id,
                label=f"advance{i}",
                type="function",
                visibility="external",
                file=f"Vault{i}.sol",
                metadata=json.dumps({"source_context": "production"}),
            )
            db.insert_transition(f"State{i}", "*", "Active", fn_id)
            db.insert_transition(f"State{i}", "Active", "Paused", fn_id)
            db.insert_transition(f"State{i}", "Paused", "Closed", fn_id)

        capped = json.loads(mcp_server.cs_state(
            db=tmp_db,
            max_entities=2,
            max_transitions_per_entity=2,
            max_warnings=3,
        ))
        uncapped = json.loads(mcp_server.cs_state(
            db=tmp_db,
            max_entities=0,
            max_transitions_per_entity=0,
            max_warnings=0,
        ))

        assert list(capped["entities"]) == ["State0", "State1"]
        assert all(len(transitions) == 2 for transitions in capped["entities"].values())
        assert len(capped["warnings"]) == 3
        assert capped["_summary"]["entities_total"] == 5
        assert capped["_summary"]["entities_shown"] == 2
        assert capped["_summary"]["hidden_entities"] == 3
        assert capped["_summary"]["transitions_total"] == 15
        assert capped["_summary"]["transitions_shown"] == 4
        assert capped["_summary"]["warnings_total"] > capped["_summary"]["warnings_shown"]
        assert capped["_summary"]["truncated"] is True
        assert capped["_summary"]["truncated_entities"]["State0"]["hidden"] == 1

        assert len(uncapped["entities"]) == 5
        assert all(len(transitions) == 3 for transitions in uncapped["entities"].values())
        assert uncapped["_summary"]["transitions_total"] == 15
        assert uncapped["_summary"]["transitions_shown"] == 15
        assert uncapped["_summary"]["warnings_total"] == uncapped["_summary"]["warnings_shown"]
        assert uncapped["_summary"]["truncated"] is False

    def test_state_detects_toggle_warnings_from_indexed_edges(self, tmp_db):
        import mcp_server

        db = GraphDB(tmp_db)
        for name in ("activate", "pause"):
            db.insert_node(
                id=f"Vault.sol::Vault.{name}()",
                label=name,
                type="function",
                visibility="external",
                file="Vault.sol",
                metadata=json.dumps({"source_context": "production"}),
            )

        db.insert_transition(
            "VaultState",
            "Active",
            "Paused",
            "Vault.sol::Vault.pause()",
            conditions="[]",
        )
        db.insert_transition(
            "VaultState",
            "Paused",
            "Active",
            "Vault.sol::Vault.activate()",
            conditions='["onlyOwner"]',
        )

        state = json.loads(mcp_server.cs_state(db=tmp_db, entity="VaultState"))

        toggle_warnings = [
            warning for warning in state["warnings"]
            if warning.startswith("TOGGLE: VaultState can toggle between Active <-> Paused")
        ]
        assert len(toggle_warnings) == 1

    def test_state_streams_transition_rows_for_broad_output(self, monkeypatch):
        import mcp_server

        rows = []
        for i in range(3):
            for j in range(4):
                rows.append({
                    "entity": f"State{i}",
                    "from_state": "*" if j == 0 else f"S{j}",
                    "to_state": f"S{j + 1}",
                    "function_id": f"Vault{i}.sol::Vault{i}.advance()",
                    "conditions": "[]",
                    "function_file": f"Vault{i}.sol",
                    "function_label": f"advance{i}",
                    "function_metadata": json.dumps({"source_context": "production"}),
                })

        class StreamingRows:
            def __iter__(self):
                return iter(rows)

            def fetchall(self):
                raise AssertionError("cs_state transition rows should stream")

        class FakeConn:
            def execute(self, sql, params=()):
                assert "FROM state_transitions" in sql
                assert "ORDER BY st.entity, st.from_state, st.to_state, st.function_id" in sql
                return StreamingRows()

            def close(self):
                pass

        monkeypatch.setattr(
            mcp_server,
            "_open_query_connection",
            lambda db_path, timeout_seconds: FakeConn(),
        )

        state = json.loads(mcp_server.cs_state(
            db="stream.db",
            max_entities=1,
            max_transitions_per_entity=2,
            max_warnings=2,
        ))

        assert list(state["entities"]) == ["State0"]
        assert len(state["entities"]["State0"]) == 2
        assert state["_summary"]["entities_total"] == 3
        assert state["_summary"]["transitions_total"] == 12
        assert state["_summary"]["transitions_shown"] == 2
        assert state["_summary"]["truncated"] is True

    def test_state_parses_transition_conditions_once_per_row(self, tmp_db, monkeypatch):
        import mcp_server

        db = GraphDB(tmp_db)
        fn_id = "Vault.sol::Vault.write()"
        db.insert_node(
            id=fn_id,
            label="write",
            type="function",
            visibility="external",
            file="Vault.sol",
            metadata=json.dumps({"source_context": "production"}),
        )
        db.insert_transition("Audience", "*", "exists", fn_id, conditions='["no_validation"]')
        db.insert_transition("Audience", "exists", "deleted", fn_id, conditions='["read"]')
        db.insert_transition("Audience", "deleted", "exists", fn_id, conditions="[]")

        real_loads = mcp_server.json.loads
        condition_loads = []

        def counting_loads(raw, *args, **kwargs):
            if isinstance(raw, str) and raw.startswith("["):
                condition_loads.append(raw)
            return real_loads(raw, *args, **kwargs)

        monkeypatch.setattr(mcp_server.json, "loads", counting_loads)

        state = json.loads(mcp_server.cs_state(
            db=tmp_db,
            max_entities=0,
            max_transitions_per_entity=0,
            max_warnings=0,
        ))

        assert state["_summary"]["transitions_total"] == 3
        assert condition_loads == ['["no_validation"]', "[]", '["read"]']
        assert all(
            "_conditions_parsed" not in item
            for transitions in state["entities"].values()
            for item in transitions
        )

    def test_state_retains_only_capped_warnings(self, tmp_db, monkeypatch):
        import mcp_server

        db = GraphDB(tmp_db)
        for i in range(12):
            fn_id = f"Vault{i}.sol::Vault{i}.advance()"
            db.insert_node(
                id=fn_id,
                label=f"advance{i}",
                type="function",
                visibility="external",
                file=f"Vault{i}.sol",
                metadata=json.dumps({"source_context": "production"}),
            )
            db.insert_transition(f"State{i}", "*", "Active", fn_id)

        real_append = mcp_server._append_capped
        warning_sizes = []

        def tracking_append(items, item, total, limit):
            updated = real_append(items, item, total, limit)
            if isinstance(item, str):
                warning_sizes.append(len(items))
            return updated

        monkeypatch.setattr(mcp_server, "_append_capped", tracking_append)

        state = json.loads(mcp_server.cs_state(
            db=tmp_db,
            max_entities=0,
            max_transitions_per_entity=0,
            max_warnings=4,
        ))

        assert state["_summary"]["warnings_total"] > 4
        assert state["_summary"]["warnings_shown"] == 4
        assert len(state["warnings"]) == 4
        assert max(warning_sizes) == 4

    def test_state_caps_before_source_context_formatting(self, tmp_db, monkeypatch):
        import mcp_server

        db = GraphDB(tmp_db)
        metadata_by_entity = {}
        for i in range(5):
            fn_id = f"Vault{i}.sol::Vault{i}.advance()"
            metadata_by_entity[i] = json.dumps({"source_context": f"custom{i}", "entity": i, "large": ["x"] * 20})
            db.insert_node(
                id=fn_id,
                label=f"advance{i}",
                type="function",
                visibility="external",
                file=f"Vault{i}.sol",
                metadata=metadata_by_entity[i],
            )
            for j in range(20):
                db.insert_transition(f"State{i}", f"S{j}", f"S{j + 1}", fn_id)

        real_load = mcp_server._load_metadata
        parsed = []

        def counting_load(raw):
            parsed.append(raw)
            return real_load(raw)

        monkeypatch.setattr(mcp_server, "_load_metadata", counting_load)

        state = json.loads(mcp_server.cs_state(
            db=tmp_db,
            max_entities=2,
            max_transitions_per_entity=3,
            max_warnings=0,
        ))

        assert state["_summary"]["transitions_total"] == 100
        assert state["_summary"]["transitions_shown"] == 6
        assert len(parsed) == 6
        assert set(parsed) == {metadata_by_entity[0], metadata_by_entity[1]}
        assert all(
            item["source_context"] in {"custom0", "custom1"}
            for transitions in state["entities"].values()
            for item in transitions
        )

    def test_state_skips_untagged_source_context_parses(self, tmp_db, monkeypatch):
        import mcp_server

        db = GraphDB(tmp_db)
        fn_id = "Vault.sol::Vault.advance()"
        db.insert_node(
            id=fn_id,
            label="advance",
            type="function",
            visibility="external",
            file="Vault.sol",
            metadata=json.dumps({}),
        )
        for i in range(3):
            db.insert_transition("VaultState", f"S{i}", f"S{i + 1}", fn_id, conditions='["onlyOwner"]')

        real_load = mcp_server._load_metadata
        parsed = []

        def counting_load(raw):
            parsed.append(raw)
            return real_load(raw)

        monkeypatch.setattr(mcp_server, "_load_metadata", counting_load)

        state = json.loads(mcp_server.cs_state(
            db=tmp_db,
            entity="VaultState",
            max_transitions_per_entity=0,
            max_warnings=0,
        ))

        assert state["_summary"]["transitions_shown"] == 3
        assert parsed == []
        assert all(
            item["source_context"] == "production"
            for item in state["entities"]["VaultState"]
        )


class TestFileFiltering:
    def test_collect_files_prioritizes_protocol_sources_for_partial_builds(self, tmp_path):
        repo = tmp_path / "repo"
        repo.mkdir()
        devtools = repo / "devtools"
        devtools.mkdir()
        src = repo / "src"
        src.mkdir()
        (devtools / "config.ts").write_text("export function configure() { return 1 }\n")
        (src / "Vault.sol").write_text("pragma solidity ^0.8.0;\ncontract Vault { function deposit() external {} }\n")

        indexer = Indexer(str(repo))
        collected = [Path(path).relative_to(repo).as_posix() for path in indexer._collect_files()]

        assert collected[0] == "src/Vault.sol"
        assert collected[-1] == "devtools/config.ts"

    def test_partial_build_indexes_protocol_sources_first(self, tmp_path, tmp_db):
        repo = tmp_path / "repo"
        repo.mkdir()
        devtools = repo / "devtools"
        devtools.mkdir()
        src = repo / "src"
        src.mkdir()
        (devtools / "config.ts").write_text("export function configure() { return 1 }\n")
        (src / "Vault.sol").write_text("pragma solidity ^0.8.0;\ncontract Vault { function deposit() external {} }\n")

        stats = Indexer(str(repo)).index(tmp_db, max_files=1)
        db = GraphDB(tmp_db)
        conn = db.get_connection()
        try:
            labels = {row["label"] for row in conn.execute("SELECT label FROM nodes").fetchall()}
        finally:
            conn.close()

        assert stats["files_considered"] == 2
        assert stats["files_indexed"] == 1
        assert "deposit" in labels
        assert "configure" not in labels

    def test_ignores_test_files(self, tmp_path, tmp_db):
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "contract.sol").write_text("pragma solidity ^0.8.0;\ncontract A { function foo() public {} }")
        (repo / "Vault.t.sol").write_text("pragma solidity ^0.8.0;\ncontract VaultTest {}")
        (repo / "Deploy.s.sol").write_text("pragma solidity ^0.8.0;\ncontract DeployScript {}")
        (repo / "test_oracle.py").write_text("def test_oracle(): pass")
        (repo / "client.test.tsx").write_text("export function test() { return 1 }")
        (repo / "keeper_test.go").write_text("package keeper")
        (repo / "service.pb.go").write_text("package pb")
        (repo / "GeneratedProto.java").write_text("class GeneratedProto {}")
        test_dir = repo / "test"
        test_dir.mkdir()
        (test_dir / "test_contract.sol").write_text("pragma solidity ^0.8.0;\ncontract TestA {}")
        indexer = Indexer(str(repo))
        stats = indexer.index(tmp_db)
        assert stats["files_indexed"] == 1

    def test_ignores_node_modules(self, tmp_path, tmp_db):
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "contract.sol").write_text("pragma solidity ^0.8.0;\ncontract A { function foo() public {} }")
        nm = repo / "node_modules" / "lib"
        nm.mkdir(parents=True)
        (nm / "dep.sol").write_text("pragma solidity ^0.8.0;\ncontract Dep {}")
        indexer = Indexer(str(repo))
        stats = indexer.index(tmp_db)
        assert stats["files_indexed"] == 1

    def test_reports_extractor_failures(self, tmp_path, tmp_db, monkeypatch):
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "contract.sol").write_text("pragma solidity ^0.8.0;\ncontract A { function foo() public {} }")

        class BrokenExtractor:
            def extract_from_source(self, source, file_path):
                raise RuntimeError("boom")

        indexer = Indexer(str(repo))
        monkeypatch.setattr(indexer, "_get_extractor", lambda chain: BrokenExtractor())
        stats = indexer.index(tmp_db)
        assert stats["files_considered"] == 1
        assert stats["files_indexed"] == 0
        assert stats["extractor_runs"] == 1
        assert stats["extractor_failures"] == 1
        assert stats["failed_files"] == 1
        assert stats["failure_examples"][0]["file"] == "contract.sol"
        assert stats["confidence"]["tier"] in {"very_low", "low"}

    def test_include_research_indexes_script_and_poc_dirs(self, tmp_path, tmp_db):
        repo = tmp_path / "repo"
        repo.mkdir()
        scripts = repo / "scripts"
        poc = repo / "poc"
        scripts.mkdir()
        poc.mkdir()
        (scripts / "Deploy.s.sol").write_text("pragma solidity ^0.8.0;\ncontract DeployScript { function run() external {} }")
        (poc / "Exploit.sol").write_text("pragma solidity ^0.8.0;\ncontract Exploit { function poke() external {} }")

        strict = Indexer(str(repo))
        strict_stats = strict.index(tmp_db)
        assert strict_stats["files_indexed"] == 0

        research_db = str(tmp_path / "research.db")
        research = Indexer(str(repo), include_research=True)
        research_stats = research.index(research_db)
        assert research_stats["files_indexed"] == 2
        db = GraphDB(research_db)
        conn = db.get_connection()
        try:
            rows = conn.execute("SELECT label, metadata FROM nodes WHERE type='function'").fetchall()
        finally:
            conn.close()
        meta_by_label = {row["label"]: json.loads(row["metadata"] or "{}") for row in rows}
        assert meta_by_label["run"]["source_context"] == "script"
        assert meta_by_label["run"]["source_kind"] == "research"
        assert meta_by_label["poke"]["source_context"] == "poc"


class TestLangOverride:
    def test_lang_flag_sets_default(self, tmp_path, tmp_db):
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "lib.rs").write_text("pub fn foo() {}")
        indexer = Indexer(str(repo), lang_override="substrate")
        assert indexer.default_chain == "substrate"
