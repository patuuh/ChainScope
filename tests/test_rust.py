"""Tests for generic Rust knowledge graph extraction."""

import json
import pytest
from pathlib import Path
from core.web3.rust import RustExtractor


@pytest.fixture(scope="module")
def rust_result():
    ext = RustExtractor()
    src = Path("tests/fixtures/sample.rs").read_bytes()
    return ext.extract_from_source(src, "sample.rs")


@pytest.fixture(scope="module")
def nodes(rust_result):
    return {n["label"]: n for n in rust_result.nodes}


@pytest.fixture(scope="module")
def nodes_by_id(rust_result):
    return {n["id"]: n for n in rust_result.nodes}


@pytest.fixture(scope="module")
def edges(rust_result):
    return rust_result.edges


@pytest.fixture(scope="module")
def transitions(rust_result):
    return rust_result.transitions


def _meta(node):
    """Parse metadata JSON from a node."""
    return json.loads(node.get("metadata", "{}"))


# --- Node extraction ---

class TestStructExtraction:
    def test_config_struct(self, nodes):
        assert "Config" in nodes
        assert nodes["Config"]["type"] == "struct"
        assert nodes["Config"]["visibility"] == "pub"

    def test_session_manager_struct(self, nodes):
        assert "SessionManager" in nodes
        assert nodes["SessionManager"]["type"] == "struct"

    def test_session_struct(self, nodes):
        assert "Session" in nodes
        assert nodes["Session"]["type"] == "struct"


class TestEnumExtraction:
    def test_session_state_enum(self, nodes):
        assert "SessionState" in nodes
        assert nodes["SessionState"]["type"] == "enum"

    def test_enum_variants(self, nodes):
        for variant in ("Idle", "Authenticating", "Active", "Terminated"):
            assert variant in nodes
            assert nodes[variant]["type"] == "enum_variant"


class TestTraitExtraction:
    def test_authenticator_trait(self, nodes):
        assert "Authenticator" in nodes
        assert nodes["Authenticator"]["type"] == "trait"


class TestFieldExtraction:
    def test_struct_fields_exist(self, rust_result):
        fields = [n for n in rust_result.nodes if n["type"] == "state_var"]
        labels = {f["label"] for f in fields}
        assert "sessions" in labels
        assert "config" in labels
        assert "state" in labels
        assert "counter" in labels
        assert "max_sessions" in labels

    def test_private_fields(self, rust_result):
        fields = [n for n in rust_result.nodes
                  if n["type"] == "state_var" and n["label"] == "sessions"]
        assert len(fields) >= 1
        assert fields[0]["visibility"] == "private"

    def test_pub_fields(self, rust_result):
        fields = [n for n in rust_result.nodes
                  if n["type"] == "state_var" and n["label"] == "max_sessions"]
        assert len(fields) >= 1
        assert fields[0]["visibility"] == "pub"


class TestImplMethods:
    def test_public_methods(self, nodes):
        for name in ("new", "create_session", "terminate_session", "get_active_count"):
            assert name in nodes
            assert nodes[name]["type"] == "function"
            assert nodes[name]["visibility"] == "pub"

    def test_private_methods(self, nodes):
        for name in ("generate_id", "cleanup_session"):
            assert name in nodes
            assert nodes[name]["visibility"] == "private"


class TestTraitImpl:
    def test_trait_impl_methods(self, nodes):
        assert "verify" in nodes
        assert "revoke" in nodes

    def test_inherits_edge(self, edges):
        inherits = [e for e in edges if e["relation"] == "inherits"]
        assert any(
            "SessionManager" in e["source"] and "Authenticator" in e["target"]
            for e in inherits
        )


class TestFreeFunctions:
    def test_raw_copy(self, nodes):
        assert "raw_copy" in nodes
        assert nodes["raw_copy"]["type"] == "function"
        assert nodes["raw_copy"]["visibility"] == "pub"

    def test_unsafe_metadata(self, rust_result):
        raw_copy = [n for n in rust_result.nodes if n["label"] == "raw_copy"][0]
        meta = json.loads(raw_copy.get("metadata", "{}"))
        assert meta.get("unsafe") is True


# --- Edge extraction ---

class TestCallEdges:
    def test_create_session_calls_generate_id(self, edges):
        calls = [e for e in edges if e["relation"] == "calls"]
        assert any(
            "create_session" in e["source"] and "generate_id" in e["target"]
            for e in calls
        )

    def test_terminate_calls_cleanup(self, edges):
        calls = [e for e in edges if e["relation"] == "calls"]
        assert any(
            "terminate_session" in e["source"] and "cleanup_session" in e["target"]
            for e in calls
        )

    def test_revoke_calls_terminate(self, edges):
        calls = [e for e in edges if e["relation"] == "calls"]
        assert any(
            "revoke" in e["source"] and "terminate_session" in e["target"]
            for e in calls
        )


class TestStateEdges:
    def test_create_session_reads_sessions(self, edges):
        reads = [e for e in edges if e["relation"] == "reads_state"]
        assert any(
            "create_session" in e["source"] and "sessions" in e["target"]
            for e in reads
        )

    def test_create_session_writes_state(self, edges):
        writes = [e for e in edges if e["relation"] == "writes_state"]
        assert any(
            "create_session" in e["source"] and "state" in e["target"]
            for e in writes
        )

    def test_cleanup_reads_sessions(self, edges):
        reads = [e for e in edges if e["relation"] == "reads_state"]
        assert any(
            "cleanup_session" in e["source"] and "sessions" in e["target"]
            for e in reads
        )

    def test_cleanup_writes_state(self, edges):
        writes = [e for e in edges if e["relation"] == "writes_state"]
        assert any(
            "cleanup_session" in e["source"] and "state" in e["target"]
            for e in writes
        )

    def test_verify_reads_state(self, edges):
        reads = [e for e in edges if e["relation"] == "reads_state"]
        assert any(
            "verify" in e["source"] and "state" in e["target"]
            for e in reads
        )


class TestContainsEdges:
    def test_struct_contains_fields(self, edges):
        contains = [e for e in edges
                    if e["relation"] == "contains" and "SessionManager" in e["source"]
                    and "SessionManager::" not in e["source"]]
        targets = {e["target"] for e in contains}
        assert any("sessions" in t for t in targets)
        assert any("config" in t for t in targets)

    def test_enum_contains_variants(self, edges):
        contains = [e for e in edges
                    if e["relation"] == "contains" and "SessionState" in e["source"]
                    and "::" not in e["source"].split("SessionState")[0][-1:]]
        assert len(contains) == 4


# --- State transitions ---

class TestStateTransitions:
    def test_transitions_detected(self, transitions):
        assert len(transitions) >= 2

    def test_create_session_transition(self, transitions):
        assert any(
            t["entity"] == "SessionState" and t["to_state"] == "Active"
            and "create_session" in t["function_id"]
            for t in transitions
        )

    def test_cleanup_transition(self, transitions):
        assert any(
            t["entity"] == "SessionState" and t["to_state"] == "Idle"
            and "cleanup_session" in t["function_id"]
            for t in transitions
        )


# --- C1: Module recursion ---

class TestModuleRecursion:
    def test_module_node_exists(self, nodes):
        assert "helpers" in nodes
        assert nodes["helpers"]["type"] == "module"

    def test_struct_inside_module(self, nodes_by_id):
        """Structs inside mod blocks should have module-qualified IDs."""
        assert any(
            "helpers::Helper" in nid and n["type"] == "struct"
            for nid, n in nodes_by_id.items()
        )

    def test_function_inside_module(self, nodes_by_id):
        """Functions inside mod blocks should have module-qualified IDs."""
        assert any(
            "helpers::helper_init" in nid and n["type"] == "function"
            for nid, n in nodes_by_id.items()
        )

    def test_field_inside_module_struct(self, rust_result):
        """Fields inside module structs should exist."""
        fields = [n for n in rust_result.nodes
                  if n["type"] == "state_var" and "helpers" in n["id"]]
        labels = {f["label"] for f in fields}
        assert "name" in labels


# --- C2: Use declaration extraction ---

class TestUseExtraction:
    def test_use_nodes_exist(self, rust_result):
        use_nodes = [n for n in rust_result.nodes if n["type"] == "use"]
        assert len(use_nodes) >= 2

    def test_use_hashmap(self, rust_result):
        use_nodes = [n for n in rust_result.nodes if n["type"] == "use"]
        paths = [n["label"] for n in use_nodes]
        assert any("HashMap" in p for p in paths)

    def test_use_arc_mutex(self, rust_result):
        use_nodes = [n for n in rust_result.nodes if n["type"] == "use"]
        paths = [n["label"] for n in use_nodes]
        assert any("Arc" in p or "Mutex" in p for p in paths)

    def test_use_has_path_metadata(self, rust_result):
        use_nodes = [n for n in rust_result.nodes if n["type"] == "use"]
        for u in use_nodes:
            meta = _meta(u)
            assert "path" in meta


# --- C3: Trait impl vs inherent impl method ID collision ---

class TestTraitImplMethodIdCollision:
    def test_trait_impl_method_has_trait_in_id(self, nodes_by_id):
        """Methods from trait impl should include trait name in the ID."""
        verify_ids = [nid for nid in nodes_by_id
                      if "verify" in nid and "Authenticator" in nid]
        assert len(verify_ids) >= 1, "Trait impl methods should include trait name in ID"

    def test_trait_impl_method_has_trait_metadata(self, nodes):
        """Trait impl methods should have trait name in metadata."""
        verify = nodes["verify"]
        meta = _meta(verify)
        assert meta.get("trait") == "Authenticator"

    def test_inherent_impl_method_no_trait(self, nodes):
        """Inherent impl methods should NOT have trait in metadata."""
        new = nodes["new"]
        meta = _meta(new)
        assert "trait" not in meta


# --- H1: Generics and where clauses ---

class TestGenerics:
    def test_generic_struct(self, nodes):
        assert "Cache" in nodes
        meta = _meta(nodes["Cache"])
        assert "generics" in meta
        assert "T" in meta["generics"]

    def test_generic_struct_signature(self, nodes):
        assert "Cache" in nodes
        sig = nodes["Cache"]["signature"]
        assert "<" in sig and "T" in sig

    def test_generic_function_with_where(self, nodes):
        assert "process" in nodes
        meta = _meta(nodes["process"])
        assert "generics" in meta
        assert "where_clause" in meta


# --- H2: Lifetime annotations ---

class TestLifetimes:
    def test_lifetime_function(self, nodes):
        assert "longest" in nodes
        meta = _meta(nodes["longest"])
        assert "lifetimes" in meta
        assert "'a" in meta["lifetimes"]


# --- H3: Async functions ---

class TestAsyncFunctions:
    def test_async_function_detected(self, nodes):
        assert "fetch_data" in nodes
        meta = _meta(nodes["fetch_data"])
        assert meta.get("async") is True

    def test_async_in_signature(self, nodes):
        assert "fetch_data" in nodes
        sig = nodes["fetch_data"]["signature"]
        assert "async" in sig

    def test_non_async_function(self, nodes):
        meta = _meta(nodes["raw_copy"])
        assert "async" not in meta


# --- H4: Macro extraction ---

class TestMacroExtraction:
    def test_macro_node_exists(self, nodes):
        assert "log_event" in nodes
        assert nodes["log_event"]["type"] == "macro"

    def test_macro_signature(self, nodes):
        assert "macro_rules!" in nodes["log_event"]["signature"]


# --- H5: Receiver type ---

class TestReceiverType:
    def test_ref_self_receiver(self, nodes):
        meta = _meta(nodes["get_active_count"])
        assert meta.get("receiver") == "&self"

    def test_mut_self_receiver(self, nodes):
        meta = _meta(nodes["create_session"])
        assert meta.get("receiver") == "&mut self"

    def test_no_receiver_for_associated(self, nodes):
        """Associated functions (like new) should have no receiver or config as first param."""
        meta = _meta(nodes["new"])
        assert meta.get("receiver") is None

    def test_verify_ref_self(self, nodes):
        meta = _meta(nodes["verify"])
        assert meta.get("receiver") == "&self"


# --- H6: reads_state over-reporting ---

class TestReadsStateOverReporting:
    def test_write_only_field_no_read_edge(self, rust_result):
        """Counter.reset() writes self.value = 0 but never reads it.
        There should be a writes_state edge but no reads_state edge for value.
        """
        reset_writes = [e for e in rust_result.edges
                        if e["relation"] == "writes_state"
                        and "reset" in e["source"]
                        and "value" in e["target"]]
        assert len(reset_writes) >= 1, "reset should write self.value"

        reset_reads = [e for e in rust_result.edges
                       if e["relation"] == "reads_state"
                       and "reset" in e["source"]
                       and "value" in e["target"]]
        assert len(reset_reads) == 0, "reset should NOT read self.value (write-only)"

    def test_read_only_field_has_read_edge(self, rust_result):
        """Counter.get_read() reads self.read_field but doesn't write it."""
        get_reads = [e for e in rust_result.edges
                     if e["relation"] == "reads_state"
                     and "get_read" in e["source"]
                     and "read_field" in e["target"]]
        assert len(get_reads) >= 1, "get_read should read self.read_field"
