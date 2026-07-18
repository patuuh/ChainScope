import json
import pytest
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
        cross_sources = {(item["source_file"], item["source_context"]) for item in cross if item["source_label"] == "ping"}
        assert ("Vault.sol", "production") in cross_sources
        assert ("scripts/Deploy.s.sol", "script") in cross_sources

        prod_cross = json.loads(mcp_server.cs_cross(db=tmp_db, exclude_research=True))
        prod_cross_sources = {(item["source_file"], item["source_context"]) for item in prod_cross if item["source_label"] == "ping"}
        assert prod_cross_sources == {("Vault.sol", "production")}

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


class TestFileFiltering:
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
