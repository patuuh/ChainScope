"""End-to-end: build graph from fixture repo, run all query tools, verify output."""
import subprocess
import sys
import json
import pytest
from pathlib import Path
from core.indexer import Indexer

CS_DIR = Path(__file__).parent.parent


def run_tool(script: str, args: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(CS_DIR / script)] + args,
        capture_output=True, text=True, cwd=str(CS_DIR)
    )


class TestEndToEnd:
    @pytest.fixture(autouse=True)
    def setup_graph(self, sol_repo, tmp_path):
        self.db = str(tmp_path / "e2e.db")
        self.repo = sol_repo
        result = run_tool("cs_build.py", [self.repo, "--db", self.db])
        assert result.returncode == 0, f"Build failed: {result.stderr}"

    def test_summary_runs(self):
        result = run_tool("cs_summary.py", ["--db", self.db])
        assert result.returncode == 0
        assert "node" in result.stdout.lower() or "function" in result.stdout.lower()

    def test_build_json_output(self, tmp_path):
        db = str(tmp_path / "json-build.db")
        result = run_tool("cs_build.py", [self.repo, "--db", db, "--json"])
        assert result.returncode == 0
        data = json.loads(result.stdout)
        assert data["status"] == "success"
        assert data["database"] == db
        assert data["nodes"] > 0
        assert data["files_indexed"] > 0
        assert data["_next_steps"]

    def test_build_missing_repo_returns_error(self, tmp_path):
        missing = tmp_path / "missing"
        result = run_tool("cs_build.py", [str(missing), "--json"])
        assert result.returncode == 1
        assert "not a directory" in result.stderr

    def test_profile_json(self):
        result = run_tool("cs_profile.py", [self.repo, "--json"])
        assert result.returncode == 0
        data = json.loads(result.stdout)
        assert "build_plan" in data
        assert "languages" in data

    def test_summary_attack_surface(self):
        result = run_tool("cs_summary.py", ["--db", self.db, "--attack-surface"])
        assert result.returncode == 0
        assert "deposit" in result.stdout.lower() or "withdraw" in result.stdout.lower()

    def test_summary_attack_surface_top(self):
        result = run_tool("cs_summary.py", ["--db", self.db, "--attack-surface", "--top", "1", "--json"])
        assert result.returncode == 0
        data = json.loads(result.stdout)
        assert len(data["attack_surface"]) <= 1
        assert data["_summary"]["attack_surface"]["shown"] <= 1

    def test_summary_attack_surface_prints_cap_status(self):
        result = run_tool("cs_summary.py", ["--db", self.db, "--attack-surface", "--top", "1"])
        assert result.returncode == 0
        assert "entry points shown" in result.stdout

    def test_summary_missing_db_does_not_create_empty_graph(self, tmp_path):
        missing_db = tmp_path / "missing.db"
        result = run_tool("cs_summary.py", ["--db", str(missing_db)])
        assert result.returncode == 1
        assert "Unable to open graph database" in result.stderr
        assert not missing_db.exists()

    def test_paths_deposit_to_withdraw(self):
        result = run_tool("cs_paths.py", ["--db", self.db, "--from", "deposit", "--to", "withdraw"])
        assert result.returncode == 0

    def test_paths_show_guards(self):
        result = run_tool("cs_paths.py", ["--db", self.db, "--from", "activate", "--to", "activate", "--show-guards"])
        assert result.returncode == 0

    def test_paths_show_state(self):
        result = run_tool("cs_paths.py", ["--db", self.db, "--from", "deposit", "--to", "withdraw", "--show-state"])
        assert result.returncode == 0

    def test_trace_balances(self):
        result = run_tool("cs_trace.py", ["--db", self.db, "--var", "balances"])
        assert result.returncode == 0
        assert "deposit" in result.stdout.lower() or "withdraw" in result.stdout.lower()

    def test_sinks_fund_transfer(self):
        result = run_tool("cs_sinks.py", ["--db", self.db, "--type", "fund_transfer"])
        assert result.returncode == 0

    def test_state_machine(self):
        result = run_tool("cs_state.py", ["--db", self.db, "--all"])
        assert result.returncode == 0
        assert "active" in result.stdout.lower() or "inactive" in result.stdout.lower()

    def test_state_machine_flags_unguarded(self):
        result = run_tool("cs_state.py", ["--db", self.db, "--all"])
        assert result.returncode == 0
        output_lower = result.stdout.lower()
        assert "unguarded" in output_lower or "close" in output_lower

    def test_cross_contract(self):
        result = run_tool("cs_cross.py", ["--db", self.db, "--external-calls"])
        assert result.returncode == 0

    def test_json_output_summary(self):
        result = run_tool("cs_summary.py", ["--db", self.db, "--json"])
        assert result.returncode == 0
        data = json.loads(result.stdout)
        assert "nodes" in data or "functions" in data

    def test_json_output_trace(self):
        result = run_tool("cs_trace.py", ["--db", self.db, "--var", "balances", "--json"])
        assert result.returncode == 0
        data = json.loads(result.stdout)
        assert isinstance(data, (dict, list))

    def test_json_output_state(self):
        result = run_tool("cs_state.py", ["--db", self.db, "--all", "--json"])
        assert result.returncode == 0
        data = json.loads(result.stdout)
        assert isinstance(data, (dict, list))

    def test_sinks_external_only(self):
        result = run_tool("cs_sinks.py", ["--db", self.db, "--type", "fund_transfer", "--external-only"])
        assert result.returncode == 0


class TestResearchAwareCli:
    def test_profile_cli_bounty_and_research(self, tmp_path):
        repo = tmp_path / "workspace"
        repo.mkdir()
        app = repo / "contracts"
        app.mkdir()
        scripts = app / "scripts"
        scripts.mkdir()
        (app / "Vault.sol").write_text(
            "pragma solidity ^0.8.0;\n"
            "contract Vault {\n"
            "    uint256 public total;\n"
            "    function set(uint256 x) external { total = x; }\n"
            "}\n"
        )
        (scripts / "Deploy.s.sol").write_text(
            "pragma solidity ^0.8.0;\n"
            "contract DeployScript {\n"
            "    function run() external {}\n"
            "}\n"
        )

        result = run_tool(
            "cs_profile.py",
            [str(repo), "--strategy", "bounty", "--include-research", "--json"],
        )
        assert result.returncode == 0
        data = json.loads(result.stdout)
        assert data["ranking_strategy"] == "bounty"
        assert data["include_research"] is True
        assert any(item["tool_call"]["include_research"] is True for item in data["build_plan"])

    def test_profile_cli_caps_large_json_sections(self, tmp_path):
        repo = tmp_path / "workspace"
        repo.mkdir()
        for i in range(4):
            pkg = repo / f"pkg{i}"
            pkg.mkdir()
            (pkg / "foundry.toml").write_text("[profile.default]\n")
            (pkg / f"Vault{i}.sol").write_text(
                "pragma solidity ^0.8.0; contract Vault { function ping() external {} }"
            )

        result = run_tool(
            "cs_profile.py",
            [str(repo), "--top", "4", "--max-output-items", "2", "--json"],
        )
        assert result.returncode == 0
        data = json.loads(result.stdout)
        assert len(data["build_plan"]) == 2
        assert data["_summary"]["max_output_items"] == 2
        assert "build_plan" in data["_summary"]["truncated_sections"]

    def test_profile_cli_missing_repo_returns_error(self, tmp_path):
        missing = tmp_path / "missing"
        result = run_tool("cs_profile.py", [str(missing), "--json"])
        assert result.returncode == 1
        assert "not a directory" in result.stderr

    def test_cli_exclude_research_flags(self, tmp_path):
        repo = tmp_path / "repo"
        repo.mkdir()
        scripts = repo / "scripts"
        scripts.mkdir()
        (repo / "Vault.sol").write_text(
            "pragma solidity ^0.8.0;\n"
            "contract Vault {\n"
            "    enum VaultState { Inactive, Closed }\n"
            "    VaultState public state;\n"
            "    uint256 public total;\n"
            "    function finish() internal {}\n"
            "    function start() external {\n"
            "        total = 1;\n"
            "        finish();\n"
            "    }\n"
            "    function close() external {\n"
            "        total = 2;\n"
            "        state = VaultState.Closed;\n"
            "    }\n"
            "    function destroy() external {\n"
            "        selfdestruct(payable(msg.sender));\n"
            "    }\n"
            "}\n"
        )
        (scripts / "Deploy.s.sol").write_text(
            "pragma solidity ^0.8.0;\n"
            "contract DeployScript {\n"
            "    enum VaultState { Inactive, Closed }\n"
            "    VaultState public state;\n"
            "    uint256 public total;\n"
            "    function finish() internal {}\n"
            "    function start() external {\n"
            "        total = 1;\n"
            "        finish();\n"
            "    }\n"
            "    function close() external {\n"
            "        total = 2;\n"
            "        state = VaultState.Closed;\n"
            "    }\n"
            "    function destroy() external {\n"
            "        selfdestruct(payable(msg.sender));\n"
            "    }\n"
            "}\n"
        )

        db = str(tmp_path / "research-cli.db")
        Indexer(str(repo), include_research=True).index(db)

        trace = run_tool("cs_trace.py", ["--db", db, "--var", "total", "--exclude-research", "--json"])
        assert trace.returncode == 0
        trace_data = json.loads(trace.stdout)
        assert trace_data["query_scope"] == "production_only"
        assert {item["label"] for item in trace_data["writers"]} == {"start", "close"}
        assert all(item["source_context"] == "production" for item in trace_data["writers"])

        paths = run_tool(
            "cs_paths.py",
            ["--db", db, "--from", "start", "--to", "finish", "--exclude-research", "--json"],
        )
        assert paths.returncode == 0
        paths_data = json.loads(paths.stdout)
        assert paths_data["query_scope"] == "production_only"
        assert paths_data["paths"] == [["Vault.start", "Vault.finish"]]

        state = run_tool("cs_state.py", ["--db", db, "--all", "--exclude-research", "--json"])
        assert state.returncode == 0
        state_data = json.loads(state.stdout)
        assert state_data["query_scope"] == "production_only"
        assert all(t["source_context"] == "production" for t in state_data["entities"]["VaultState"])

        summary = run_tool("cs_summary.py", ["--db", db, "--exclude-research", "--json"])
        assert summary.returncode == 0
        summary_data = json.loads(summary.stdout)
        assert summary_data["query_scope"] == "production_only"
        assert summary_data["files"] == 1
        assert summary_data["functions"] < 8

        sinks = run_tool("cs_sinks.py", ["--db", db, "--type", "self_destruct", "--exclude-research", "--json"])
        assert sinks.returncode == 0
        sinks_data = json.loads(sinks.stdout)
        assert len(sinks_data) == 1
        assert sinks_data[0]["source_context"] == "production"
