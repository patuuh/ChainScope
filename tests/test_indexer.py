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

    def test_build_missing_repo_returns_json_error(self):
        import mcp_server

        result = json.loads(mcp_server.cs_build(repo_path="/not/a/dir"))

        assert result["tool"] == "cs_build"
        assert result["repo_path"] == "/not/a/dir"
        assert "not a directory" in result["error"]

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

        prod_hotspots = json.loads(mcp_server.cs_hotspots(db=tmp_db, top=20, exclude_research=True))
        prod_contexts = {item["function"]: item["source_context"] for item in prod_hotspots["hotspots"]}
        assert "run" not in prod_contexts
        assert prod_contexts["set"] == "production"
        assert prod_hotspots["_summary"]["query_scope"] == "production_only"

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

        capped = json.loads(mcp_server.cs_lookup(name="transfer", db=tmp_db, max_matches=2))
        uncapped = json.loads(mcp_server.cs_lookup(name="transfer", db=tmp_db, max_matches=0))

        assert capped["matches"] == 2
        assert capped["matches_total"] == 5
        assert capped["truncated"] is True
        assert "candidates" in capped
        assert len(capped["candidates"]) == 5
        assert "max_matches=0" in capped["_warning"]

        assert uncapped["matches"] == 5
        assert uncapped["matches_total"] == 5
        assert uncapped["truncated"] is False
        assert "candidates" not in uncapped

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

        capped = json.loads(mcp_server.cs_trace(var="total", db=tmp_db, max_matches=2))
        uncapped = json.loads(mcp_server.cs_trace(var="total", db=tmp_db, max_matches=0))

        assert capped["variable_matches"] == 2
        assert capped["variable_matches_total"] == 5
        assert capped["truncated"] is True
        assert capped["max_matches"] == 2
        assert len(capped["candidates"]) == 5
        assert len(capped["writers"]) == 2
        assert "max_matches=0" in capped["_warning"]

        assert uncapped["variable_matches"] == 5
        assert uncapped["variable_matches_total"] == 5
        assert uncapped["truncated"] is False
        assert len(uncapped["writers"]) == 5
        assert "candidates" not in uncapped

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
        assert len(capped["from_candidates"]) == 5
        assert len(capped["to_candidates"]) == 5

        assert len(uncapped["paths"]) == 5
        assert uncapped["_summary"]["path_limit_reached"] is False
        assert uncapped["_summary"]["endpoint_matches_truncated"] is False
        assert uncapped["_summary"]["truncated"] is False

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
