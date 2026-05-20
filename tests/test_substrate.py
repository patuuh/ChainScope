import json
import pytest
from pathlib import Path
from core.web3.substrate import SubstrateExtractor

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def extractor():
    return SubstrateExtractor()


@pytest.fixture
def pallet_result(extractor):
    code = (FIXTURES / "substrate_pallet.rs").read_bytes()
    return extractor.extract_from_source(code, "substrate_pallet.rs")


class TestDispatchableExtraction:
    def test_extracts_all_calls(self, pallet_result):
        labels = {n["label"] for n in pallet_result.nodes if n["type"] == "function"}
        assert "create_proposal" in labels
        assert "activate_proposal" in labels
        assert "execute_proposal" in labels
        assert "cancel_proposal" in labels

    def test_function_visibility(self, pallet_result):
        funcs = {n["label"]: n for n in pallet_result.nodes if n["type"] == "function"}
        assert funcs["create_proposal"]["visibility"] == "public"

    def test_function_has_line_range(self, pallet_result):
        funcs = {n["label"]: n for n in pallet_result.nodes if n["type"] == "function"}
        f = funcs["create_proposal"]
        assert f["line_start"] > 0
        assert f["line_end"] > f["line_start"]


class TestOriginChecks:
    def test_signed_origin(self, pallet_result):
        funcs = {n["label"]: n for n in pallet_result.nodes if n["type"] == "function"}
        meta = json.loads(funcs["create_proposal"]["metadata"])
        assert meta.get("origin") == "signed"

    def test_root_origin(self, pallet_result):
        funcs = {n["label"]: n for n in pallet_result.nodes if n["type"] == "function"}
        meta = json.loads(funcs["activate_proposal"]["metadata"])
        assert meta.get("origin") == "root"

    def test_none_origin(self, pallet_result):
        funcs = {n["label"]: n for n in pallet_result.nodes if n["type"] == "function"}
        meta = json.loads(funcs["cancel_proposal"]["metadata"])
        assert meta.get("origin") == "none"

    def test_custom_origin(self, pallet_result):
        funcs = {n["label"]: n for n in pallet_result.nodes if n["type"] == "function"}
        meta = json.loads(funcs["governance_action"]["metadata"])
        assert meta.get("origin") == "custom:GovernanceOrigin"


class TestStorageDetection:
    def test_extracts_storage_items(self, pallet_result):
        storage = {n["label"]: n for n in pallet_result.nodes if n["type"] == "state_var"}
        assert "Proposals" in storage
        assert "ProposalCount" in storage
        assert "TotalLocked" in storage

    def test_storage_type_detected(self, pallet_result):
        storage = {n["label"]: n for n in pallet_result.nodes if n["type"] == "state_var"}
        proposals_meta = json.loads(storage["Proposals"]["metadata"])
        assert proposals_meta["storage_type"] == "StorageMap"
        count_meta = json.loads(storage["ProposalCount"]["metadata"])
        assert count_meta["storage_type"] == "StorageValue"

    def test_unbounded_storage_detected(self, pallet_result):
        storage = {n["label"]: n for n in pallet_result.nodes if n["type"] == "state_var"}
        assert "PendingActions" in storage
        meta = json.loads(storage["PendingActions"]["metadata"])
        assert meta.get("unbounded") is True

    def test_bounded_storage_not_flagged(self, pallet_result):
        storage = {n["label"]: n for n in pallet_result.nodes if n["type"] == "state_var"}
        # Proposals uses StorageMap which doesn't have unbounded Vec
        meta = json.loads(storage["Proposals"]["metadata"])
        assert "unbounded" not in meta

    def test_storage_double_map_detected(self, pallet_result):
        """C1: StorageDoubleMap must not be misclassified as StorageMap."""
        storage = {n["label"]: n for n in pallet_result.nodes if n["type"] == "state_var"}
        assert "Votes" in storage
        meta = json.loads(storage["Votes"]["metadata"])
        assert meta["storage_type"] == "StorageDoubleMap"

    def test_counted_storage_map_detected(self, pallet_result):
        """C2: CountedStorageMap detection."""
        storage = {n["label"]: n for n in pallet_result.nodes if n["type"] == "state_var"}
        assert "ActiveVoters" in storage
        meta = json.loads(storage["ActiveVoters"]["metadata"])
        assert meta["storage_type"] == "CountedStorageMap"

    def test_string_unbounded_detected(self, pallet_result):
        """H4: String type should be flagged as unbounded."""
        storage = {n["label"]: n for n in pallet_result.nodes if n["type"] == "state_var"}
        assert "Description" in storage
        meta = json.loads(storage["Description"]["metadata"])
        assert meta.get("unbounded") is True


class TestStorageReadWrite:
    def test_writes_state(self, pallet_result):
        writes = [e for e in pallet_result.edges if e["relation"] == "writes_state"]
        create_writes = [e for e in writes if "create_proposal" in e["source"]]
        written = {e["target"] for e in create_writes}
        assert any("Proposals" in v for v in written)
        assert any("ProposalCount" in v for v in written)

    def test_reads_state(self, pallet_result):
        reads = [e for e in pallet_result.edges if e["relation"] == "reads_state"]
        create_reads = [e for e in reads if "create_proposal" in e["source"]]
        assert len(create_reads) > 0

    def test_non_turbofish_read(self, pallet_result):
        """H3: <StorageName<T>>::get() syntax should be detected as a read."""
        reads = [e for e in pallet_result.edges if e["relation"] == "reads_state"]
        create_reads = [e for e in reads if "create_proposal" in e["source"]]
        read_targets = {e["target"] for e in create_reads}
        assert any("ProposalCount" in t for t in read_targets)


class TestEvents:
    def test_events_extracted(self, pallet_result):
        events = {n["label"] for n in pallet_result.nodes if n["type"] == "event"}
        assert "ProposalCreated" in events
        assert "ProposalActivated" in events
        assert "ProposalExecuted" in events
        assert "FundsLocked" in events

    def test_emits_event_edge(self, pallet_result):
        emits = [e for e in pallet_result.edges if e["relation"] == "emits_event"]
        assert len(emits) > 0
        # create_proposal emits ProposalCreated
        create_emits = [e for e in emits if "create_proposal" in e["source"]]
        assert any("ProposalCreated" in e["target"] for e in create_emits)


class TestStateMachine:
    def test_state_transitions(self, pallet_result):
        assert len(pallet_result.transitions) > 0
        entities = {t["entity"] for t in pallet_result.transitions}
        assert "ProposalState" in entities

    def test_activate_transition(self, pallet_result):
        activate_trans = [t for t in pallet_result.transitions
                         if "activate_proposal" in t["function_id"]]
        assert len(activate_trans) >= 1
        assert activate_trans[0]["to_state"] == "Active"
        assert activate_trans[0]["from_state"] == "Pending"

    def test_cancel_is_unguarded(self, pallet_result):
        cancel_trans = [t for t in pallet_result.transitions
                        if "cancel_proposal" in t["function_id"]]
        assert len(cancel_trans) >= 1
        assert cancel_trans[0]["from_state"] == "*"


class TestHooks:
    def test_hook_extracted(self, pallet_result):
        funcs = {n["label"]: n for n in pallet_result.nodes if n["type"] == "function"}
        assert "on_initialize" in funcs
        meta = json.loads(funcs["on_initialize"]["metadata"])
        assert meta.get("is_hook") is True

    def test_hook_body_edges(self, pallet_result):
        """GAP #6: Hooks should have storage read/write edges extracted."""
        reads = [e for e in pallet_result.edges if e["relation"] == "reads_state"]
        hook_reads = [e for e in reads if "on_initialize" in e["source"]]
        assert len(hook_reads) > 0
        assert any("ProposalCount" in e["target"] for e in hook_reads)

    def test_on_finalize_hook_type(self, pallet_result):
        """H1: on_finalize should have hook_type metadata."""
        funcs = {n["label"]: n for n in pallet_result.nodes if n["type"] == "function"}
        assert "on_finalize" in funcs
        meta = json.loads(funcs["on_finalize"]["metadata"])
        assert meta.get("is_hook") is True
        assert meta.get("hook_type") == "on_finalize"

    def test_on_initialize_hook_type(self, pallet_result):
        """H1: on_initialize should have hook_type metadata."""
        funcs = {n["label"]: n for n in pallet_result.nodes if n["type"] == "function"}
        meta = json.loads(funcs["on_initialize"]["metadata"])
        assert meta.get("hook_type") == "on_initialize"

    def test_on_runtime_upgrade_is_migration(self, pallet_result):
        """C3: on_runtime_upgrade must be flagged as migration."""
        funcs = {n["label"]: n for n in pallet_result.nodes if n["type"] == "function"}
        assert "on_runtime_upgrade" in funcs
        meta = json.loads(funcs["on_runtime_upgrade"]["metadata"])
        assert meta.get("is_hook") is True
        assert meta.get("is_migration") is True
        assert meta.get("hook_type") == "on_runtime_upgrade"


class TestCallIndex:
    def test_call_index_extracted(self, pallet_result):
        """H2: call_index attribute should be parsed."""
        funcs = {n["label"]: n for n in pallet_result.nodes if n["type"] == "function"}
        meta = json.loads(funcs["create_proposal"]["metadata"])
        assert meta.get("call_index") == 0

    def test_call_index_value(self, pallet_result):
        """H2: call_index(1) should yield 1."""
        funcs = {n["label"]: n for n in pallet_result.nodes if n["type"] == "function"}
        meta = json.loads(funcs["activate_proposal"]["metadata"])
        assert meta.get("call_index") == 1

    def test_no_call_index_when_absent(self, pallet_result):
        """Functions without call_index should not have call_index in metadata."""
        funcs = {n["label"]: n for n in pallet_result.nodes if n["type"] == "function"}
        meta = json.loads(funcs["execute_proposal"]["metadata"])
        assert "call_index" not in meta


class TestWeightExtraction:
    def test_weight_value(self, pallet_result):
        funcs = {n["label"]: n for n in pallet_result.nodes if n["type"] == "function"}
        meta = json.loads(funcs["activate_proposal"]["metadata"])
        assert meta.get("weight") == "10_000"

    def test_weight_function_call(self, pallet_result):
        funcs = {n["label"]: n for n in pallet_result.nodes if n["type"] == "function"}
        meta = json.loads(funcs["create_proposal"]["metadata"])
        assert "WeightInfo" in meta.get("weight", "")
        assert "create_proposal" in meta.get("weight", "")


class TestTransactionalDetection:
    def test_transactional_true(self, pallet_result):
        funcs = {n["label"]: n for n in pallet_result.nodes if n["type"] == "function"}
        meta = json.loads(funcs["create_proposal"]["metadata"])
        assert meta.get("transactional") is True

    def test_transactional_false(self, pallet_result):
        funcs = {n["label"]: n for n in pallet_result.nodes if n["type"] == "function"}
        meta = json.loads(funcs["activate_proposal"]["metadata"])
        assert meta.get("transactional") is False


class TestCrossPalletCalls:
    def test_cross_pallet_edge(self, pallet_result):
        calls = [e for e in pallet_result.edges if e["relation"] == "calls"]
        cross = [e for e in calls if "cross_pallet" in e.get("attributes", "")]
        assert len(cross) > 0

    def test_currency_sink(self, pallet_result):
        cross_nodes = [n for n in pallet_result.nodes
                       if "cross_pallet" in n.get("metadata", "")]
        currency_sinks = [n for n in cross_nodes
                          if "is_sink" in n.get("metadata", "") and "Currency" in n["label"]]
        assert len(currency_sinks) > 0


class TestInherentCalls:
    def test_inherent_function_extracted(self, pallet_result):
        funcs = {n["label"]: n for n in pallet_result.nodes if n["type"] == "function"}
        assert "create_inherent" in funcs
        meta = json.loads(funcs["create_inherent"]["metadata"])
        assert meta.get("is_inherent") is True


class TestPalletMetadata:
    def test_pallet_in_metadata(self, pallet_result):
        funcs = [n for n in pallet_result.nodes if n["type"] == "function"]
        for f in funcs:
            meta = json.loads(f.get("metadata", "{}"))
            assert "pallet" in meta
            assert meta["pallet"] == "pallet"


class TestUnboundedStorageExpanded:
    """H4: Expanded unbounded type detection."""

    def test_string_is_unbounded(self, extractor):
        code = b"""
#[frame_support::pallet]
pub mod pallet {
    #[pallet::storage]
    pub type Names<T> = StorageValue<_, String, ValueQuery>;
}
"""
        result = extractor.extract_from_source(code, "test.rs")
        storage = {n["label"]: n for n in result.nodes if n["type"] == "state_var"}
        assert "Names" in storage
        meta = json.loads(storage["Names"]["metadata"])
        assert meta.get("unbounded") is True

    def test_hashmap_is_unbounded(self, extractor):
        code = b"""
#[frame_support::pallet]
pub mod pallet {
    #[pallet::storage]
    pub type Lookup<T> = StorageValue<_, HashMap<u32, u64>, ValueQuery>;
}
"""
        result = extractor.extract_from_source(code, "test.rs")
        storage = {n["label"]: n for n in result.nodes if n["type"] == "state_var"}
        meta = json.loads(storage["Lookup"]["metadata"])
        assert meta.get("unbounded") is True

    def test_hashset_is_unbounded(self, extractor):
        code = b"""
#[frame_support::pallet]
pub mod pallet {
    #[pallet::storage]
    pub type Members<T> = StorageValue<_, HashSet<u32>, ValueQuery>;
}
"""
        result = extractor.extract_from_source(code, "test.rs")
        storage = {n["label"]: n for n in result.nodes if n["type"] == "state_var"}
        meta = json.loads(storage["Members"]["metadata"])
        assert meta.get("unbounded") is True
