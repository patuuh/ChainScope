import json
import pytest
from pathlib import Path
from core.web3.solidity import SolidityExtractor

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def extractor():
    return SolidityExtractor()


@pytest.fixture
def vault_result(extractor):
    code = (FIXTURES / "simple_vault.sol").read_bytes()
    return extractor.extract_from_source(code, "simple_vault.sol")


@pytest.fixture
def token_result(extractor):
    code = (FIXTURES / "token.sol").read_bytes()
    return extractor.extract_from_source(code, "token.sol")


class TestFunctionExtraction:
    def test_extracts_all_functions(self, vault_result):
        labels = {n["label"] for n in vault_result.nodes if n["type"] == "function"}
        assert "activate" in labels
        assert "deposit" in labels
        assert "withdraw" in labels
        assert "emergencyWithdraw" in labels
        assert "pause" in labels
        assert "close" in labels

    def test_function_visibility(self, vault_result):
        funcs = {n["label"]: n for n in vault_result.nodes if n["type"] == "function"}
        assert funcs["deposit"]["visibility"] == "external"
        assert funcs["withdraw"]["visibility"] == "external"

    def test_function_has_line_range(self, vault_result):
        funcs = {n["label"]: n for n in vault_result.nodes if n["type"] == "function"}
        dep = funcs["deposit"]
        assert dep["line_start"] > 0
        assert dep["line_end"] > dep["line_start"]

    def test_function_signature(self, vault_result):
        funcs = {n["label"]: n for n in vault_result.nodes if n["type"] == "function"}
        assert "uint256 amount" in funcs["deposit"]["signature"]


class TestStateVariables:
    def test_extracts_state_vars(self, vault_result):
        state_vars = {n["label"] for n in vault_result.nodes if n["type"] == "state_var"}
        assert "balances" in state_vars
        assert "totalDeposits" in state_vars
        assert "state" in state_vars
        assert "token" in state_vars
        assert "owner" in state_vars

    def test_extracts_mapping_types(self, token_result):
        state_vars = {n["label"]: n for n in token_result.nodes if n["type"] == "state_var"}
        assert "balanceOf" in state_vars
        assert "allowance" in state_vars


class TestInheritance:
    def test_inherits_edge(self, vault_result):
        inherits = [e for e in vault_result.edges if e["relation"] == "inherits"]
        assert len(inherits) >= 1
        targets = {e["target"] for e in inherits}
        assert any("Ownable" in t for t in targets)


class TestCallEdges:
    def test_internal_calls(self, vault_result):
        calls = [e for e in vault_result.edges if e["relation"] == "calls"]
        sources = {e["source"] for e in calls}
        assert any("deposit" in s for s in sources)

    def test_external_call_detected(self, vault_result):
        calls = [e for e in vault_result.edges if e["relation"] == "calls"]
        withdraw_calls = [e for e in calls if "withdraw" in e["source"]]
        assert len(withdraw_calls) > 0


class TestStateReadWrite:
    def test_writes_state(self, vault_result):
        writes = [e for e in vault_result.edges if e["relation"] == "writes_state"]
        deposit_writes = [e for e in writes if "deposit" in e["source"]]
        written_vars = {e["target"] for e in deposit_writes}
        assert any("balances" in v for v in written_vars)
        assert any("totalDeposits" in v for v in written_vars)

    def test_reads_state(self, vault_result):
        reads = [e for e in vault_result.edges if e["relation"] == "reads_state"]
        withdraw_reads = [e for e in reads if "withdraw" in e["source"]]
        assert len(withdraw_reads) > 0


class TestModifiers:
    def test_modifier_extracted(self, vault_result):
        modifiers = [n for n in vault_result.nodes if n["type"] == "modifier"]
        labels = {m["label"] for m in modifiers}
        assert "onlyOwner" in labels

    def test_guards_edge(self, vault_result):
        guards = [e for e in vault_result.edges if e["relation"] == "guards"]
        guarded_targets = {e["target"] for e in guards}
        assert any("activate" in t for t in guarded_targets)
        assert any("emergencyWithdraw" in t for t in guarded_targets)


class TestEvents:
    def test_events_extracted(self, vault_result):
        events = [n for n in vault_result.nodes if n["type"] == "event"]
        labels = {e["label"] for e in events}
        assert "Deposited" in labels
        assert "Withdrawn" in labels
        assert "StateChanged" in labels

    def test_emits_event_edge(self, vault_result):
        emits = [e for e in vault_result.edges if e["relation"] == "emits_event"]
        assert len(emits) > 0


class TestStateMachine:
    def test_state_transitions(self, vault_result):
        assert len(vault_result.transitions) > 0
        entities = {t["entity"] for t in vault_result.transitions}
        assert "VaultState" in entities or "state" in entities

    def test_activate_transition(self, vault_result):
        transitions = vault_result.transitions
        activate_trans = [t for t in transitions
                         if "activate" in t["function_id"]
                         and "Inactive" in t["from_state"]]
        assert len(activate_trans) >= 1


class TestSinkDetection:
    def _get_sinks(self, result):
        sinks = []
        for n in result.nodes:
            meta = json.loads(n.get("metadata", "{}"))
            if meta.get("is_sink"):
                sinks.append(meta)
        return sinks

    def test_fund_transfer_sinks(self, vault_result):
        sinks = self._get_sinks(vault_result)
        types = {s.get("sink_type") for s in sinks}
        assert "fund_transfer" in types

    def test_delegatecall_sink(self, vault_result):
        sinks = self._get_sinks(vault_result)
        types = {s.get("sink_type") for s in sinks}
        assert "delegate" in types

    def test_selfdestruct_sink(self, vault_result):
        sinks = self._get_sinks(vault_result)
        types = {s.get("sink_type") for s in sinks}
        assert "self_destruct" in types


class TestUnguardedTransitions:
    def test_close_is_unguarded_transition(self, vault_result):
        """close() sets state to Closed without requiring a specific from_state.
        The extractor should produce a transition with from_state='*'."""
        close_trans = [t for t in vault_result.transitions
                       if "close" in t["function_id"]]
        assert len(close_trans) >= 1
        for t in close_trans:
            conds = json.loads(t.get("conditions", "[]"))
            state_conds = [c for c in conds if "state" in c.lower() or "VaultState" in c]
            assert len(state_conds) == 0


class TestContractMetadata:
    def test_contract_in_metadata(self, vault_result):
        funcs = [n for n in vault_result.nodes if n["type"] == "function"]
        for f in funcs:
            meta = json.loads(f.get("metadata", "{}"))
            assert "contract" in meta


class TestPrivilegedHeuristics:
    def test_only_owner_function_gets_role_guard(self, vault_result):
        funcs = {n["label"]: n for n in vault_result.nodes if n["type"] == "function"}
        meta = json.loads(funcs["activate"]["metadata"])
        assert "role_guards" in meta
        assert "owner" in meta["role_guards"]

    def test_delegatecall_function_gets_privileged_ops(self, vault_result):
        funcs = {n["label"]: n for n in vault_result.nodes if n["type"] == "function"}
        meta = json.loads(funcs["migrateToNew"]["metadata"])
        assert "privileged_operations" in meta
        assert "delegate_execution" in meta["privileged_operations"]
        assert meta.get("upgrade_surface") is True

    def test_selfdestruct_function_gets_shutdown_marker(self, vault_result):
        funcs = {n["label"]: n for n in vault_result.nodes if n["type"] == "function"}
        meta = json.loads(funcs["destroy"]["metadata"])
        assert "privileged_operations" in meta
        assert "shutdown" in meta["privileged_operations"]
