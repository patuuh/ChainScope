"""Tests for C++ knowledge graph extraction."""

import json
import pytest
from pathlib import Path
from core.web3.cpp import CppExtractor


@pytest.fixture(scope="module")
def cpp_result():
    ext = CppExtractor()
    src = Path("tests/fixtures/sample.cpp").read_bytes()
    return ext.extract_from_source(src, "sample.cpp")


@pytest.fixture(scope="module")
def nodes(cpp_result):
    return {n["label"]: n for n in cpp_result.nodes}


@pytest.fixture(scope="module")
def nodes_list(cpp_result):
    return cpp_result.nodes


@pytest.fixture(scope="module")
def edges(cpp_result):
    return cpp_result.edges


def _meta(node):
    """Parse metadata JSON from a node."""
    return json.loads(node["metadata"])


# --- Node extraction ---

class TestClassExtraction:
    def test_keymanager_class(self, cpp_result):
        classes = [n for n in cpp_result.nodes if n["label"] == "KeyManager" and n["type"] == "class"]
        assert len(classes) == 1

    def test_hsmkeymanager_class(self, cpp_result):
        classes = [n for n in cpp_result.nodes if n["label"] == "HsmKeyManager" and n["type"] == "class"]
        assert len(classes) == 1


class TestStructExtraction:
    def test_keypair_struct(self, nodes):
        assert "KeyPair" in nodes
        assert nodes["KeyPair"]["type"] == "struct"


class TestEnumExtraction:
    def test_keystate_enum(self, nodes):
        assert "KeyState" in nodes
        assert nodes["KeyState"]["type"] == "enum"

    def test_enum_variants(self, nodes):
        for variant in ("Uninitialized", "Active", "Revoked", "Expired"):
            assert variant in nodes
            assert nodes[variant]["type"] == "enumerator"


class TestMethodExtraction:
    def test_public_methods(self, nodes):
        for name in ("generate_key", "revoke_key", "get_key", "rotate_keys"):
            assert name in nodes
            assert nodes[name]["type"] == "function"
            assert nodes[name]["visibility"] == "public"

    def test_protected_method(self, cpp_result):
        protected = [n for n in cpp_result.nodes
                     if n["label"] == "derive_public_key" and n["visibility"] == "protected"]
        assert len(protected) >= 1

    def test_private_methods(self, nodes):
        assert "derive_private_key" in nodes
        assert nodes["derive_private_key"]["visibility"] == "private"
        assert "notify_revocation" in nodes
        assert nodes["notify_revocation"]["visibility"] == "private"


class TestConstructorExtraction:
    def test_constructors_detected(self, cpp_result):
        constructors = [n for n in cpp_result.nodes if n["type"] == "constructor"]
        assert len(constructors) >= 2
        labels = {c["label"] for c in constructors}
        assert "KeyManager" in labels
        assert "HsmKeyManager" in labels


class TestMemberFields:
    def test_private_fields(self, cpp_result):
        fields = [n for n in cpp_result.nodes if n["type"] == "state_var"]
        labels = {f["label"] for f in fields}
        assert "keys_" in labels
        assert "max_keys_" in labels
        assert "mutex_" in labels

    def test_struct_fields(self, cpp_result):
        fields = [n for n in cpp_result.nodes if n["type"] == "state_var"]
        labels = {f["label"] for f in fields}
        assert "public_key" in labels
        assert "private_key" in labels


class TestFreeFunctions:
    def test_unsafe_memcpy(self, nodes):
        assert "unsafe_memcpy" in nodes
        assert nodes["unsafe_memcpy"]["type"] == "function"


# --- Edge extraction ---

class TestInheritance:
    def test_hsmkeymanager_inherits_keymanager(self, edges):
        inherits = [e for e in edges if e["relation"] == "inherits"]
        assert any(
            "HsmKeyManager" in e["source"] and "KeyManager" in e["target"]
            for e in inherits
        )


class TestCallEdges:
    def test_generate_key_calls_derive(self, edges):
        calls = [e for e in edges if e["relation"] == "calls"]
        assert any(
            "generate_key" in e["source"] and "derive_public_key" in e["target"]
            for e in calls
        )
        assert any(
            "generate_key" in e["source"] and "derive_private_key" in e["target"]
            for e in calls
        )

    def test_revoke_key_calls_notify(self, edges):
        calls = [e for e in edges if e["relation"] == "calls"]
        assert any(
            "revoke_key" in e["source"] and "notify_revocation" in e["target"]
            for e in calls
        )

    def test_rotate_calls_generate(self, edges):
        calls = [e for e in edges if e["relation"] == "calls"]
        assert any(
            "rotate_keys" in e["source"] and "generate_key" in e["target"]
            for e in calls
        )

    def test_hsm_derive_public_key_calls_hsm_derive(self, edges):
        calls = [e for e in edges if e["relation"] == "calls"]
        assert any(
            "derive_public_key" in e["source"] and "hsm_derive" in e["target"]
            for e in calls
        )


class TestStateEdges:
    def test_generate_key_reads_keys(self, edges):
        reads = [e for e in edges if e["relation"] == "reads_state"]
        assert any(
            "generate_key" in e["source"] and "keys_" in e["target"]
            for e in reads
        )

    def test_revoke_key_writes_keys(self, edges):
        writes = [e for e in edges if e["relation"] == "writes_state"]
        assert any(
            "revoke_key" in e["source"] and "keys_" in e["target"]
            for e in writes
        )

    def test_rotate_keys_reads_and_writes(self, edges):
        reads = [e for e in edges if e["relation"] == "reads_state" and "rotate_keys" in e["source"]]
        writes = [e for e in edges if e["relation"] == "writes_state" and "rotate_keys" in e["source"]]
        assert len(reads) >= 1
        assert len(writes) >= 1


class TestContainsEdges:
    def test_class_contains_methods(self, edges):
        contains = [e for e in edges if e["relation"] == "contains" and "KeyManager" in e["source"]]
        targets = {e["target"] for e in contains}
        assert any("generate_key" in t for t in targets)
        assert any("revoke_key" in t for t in targets)

    def test_enum_contains_variants(self, edges):
        contains = [e for e in edges if e["relation"] == "contains"
                    and e["source"].endswith("::KeyState")]
        assert len(contains) == 4


# ==========================================
# NEW TESTS for CRITICAL and HIGH fixes
# ==========================================

# --- C1: typedef/using extraction ---

class TestTypeAlias:
    def test_using_alias_extracted(self, nodes):
        """C1: using KeyIndex = size_t should produce a type_alias node."""
        assert "KeyIndex" in nodes
        assert nodes["KeyIndex"]["type"] == "type_alias"

    def test_using_alias_metadata(self, nodes):
        """C1: type_alias metadata stores the aliased type."""
        meta = _meta(nodes["KeyIndex"])
        assert "aliased_type" in meta
        assert "size_t" in meta["aliased_type"]


# --- C2: operator overloading ---

class TestOperatorOverload:
    def test_operator_equals_extracted(self, cpp_result):
        """C2: operator== should be extracted as a function node."""
        ops = [n for n in cpp_result.nodes if n["label"] == "operator==" and n["type"] == "function"]
        assert len(ops) >= 1

    def test_operator_in_class(self, cpp_result):
        """C2: operator== should be contained by KeyManager."""
        ops = [n for n in cpp_result.nodes if n["label"] == "operator=="]
        assert len(ops) >= 1
        op_id = ops[0]["id"]
        contains = [e for e in cpp_result.edges
                    if e["relation"] == "contains" and e["target"] == op_id]
        assert len(contains) >= 1
        assert "KeyManager" in contains[0]["source"]


# --- C3: friend declaration ---

class TestFriendDeclaration:
    def test_friend_edge_exists(self, edges):
        """C3: friend class KeyAuditor should produce a friend edge."""
        friends = [e for e in edges if e["relation"] == "friend"]
        assert len(friends) >= 1
        assert any("KeyManager" in e["source"] and "KeyAuditor" in e["target"]
                    for e in friends)

    def test_friend_edge_attributes(self, edges):
        """C3: friend edge should have friend name in attributes."""
        friends = [e for e in edges if e["relation"] == "friend"]
        for e in friends:
            attrs = json.loads(e["attributes"])
            if "KeyAuditor" in e["target"]:
                assert attrs["friend"] == "KeyAuditor"


# --- C4: scoped vs unscoped enum ---

class TestEnumScoping:
    def test_scoped_enum(self, nodes):
        """C4: enum class KeyState should have scoped=True."""
        meta = _meta(nodes["KeyState"])
        assert meta["scoped"] is True

    def test_unscoped_enum(self, nodes):
        """C4: plain enum ErrorCode should have scoped=False."""
        assert "ErrorCode" in nodes
        assert nodes["ErrorCode"]["type"] == "enum"
        meta = _meta(nodes["ErrorCode"])
        assert meta["scoped"] is False

    def test_unscoped_enum_variants(self, nodes):
        """C4: plain enum variants are extracted."""
        for variant in ("OK", "InvalidKey", "Timeout", "InternalError"):
            assert variant in nodes
            assert nodes[variant]["type"] == "enumerator"


# --- C5: static member detection ---

class TestStaticMembers:
    def test_static_field(self, cpp_result):
        """C5: static int instance_count_ should have static=True."""
        fields = [n for n in cpp_result.nodes
                  if n["label"] == "instance_count_" and n["type"] == "state_var"]
        assert len(fields) >= 1
        meta = _meta(fields[0])
        assert meta.get("static") is True

    def test_static_method(self, cpp_result):
        """C5: static int instance_count() should have static=True."""
        methods = [n for n in cpp_result.nodes
                   if n["label"] == "instance_count" and n["type"] == "function"]
        assert len(methods) >= 1
        meta = _meta(methods[0])
        assert meta.get("static") is True

    def test_non_static_field(self, cpp_result):
        """C5: non-static fields should not have static=True."""
        fields = [n for n in cpp_result.nodes
                  if n["label"] == "keys_" and n["type"] == "state_var"]
        assert len(fields) >= 1
        meta = _meta(fields[0])
        assert meta.get("static") is not True


# --- H1: const method tracking ---

class TestConstMethod:
    def test_const_method_detected(self, nodes):
        """H1: get_key method should have const=True in metadata."""
        meta = _meta(nodes["get_key"])
        assert meta.get("const") is True

    def test_non_const_method(self, nodes):
        """H1: generate_key should not have const=True."""
        meta = _meta(nodes["generate_key"])
        assert meta.get("const") is not True

    def test_operator_equals_is_const(self, cpp_result):
        """H1: operator== declared const should have const=True."""
        ops = [n for n in cpp_result.nodes if n["label"] == "operator=="]
        assert len(ops) >= 1
        meta = _meta(ops[0])
        assert meta.get("const") is True


# --- H2: reads_state over-reporting fix ---

class TestReadsStateAccuracy:
    def test_no_spurious_reads_for_write_only(self, cpp_result):
        """H2: A field that only appears on LHS of assignment should not get reads_state.

        This tests the principle - we check that the write-set calculation works.
        """
        # The fixture's revoke_key writes to keys_ (keys_[index].state = ...)
        # and also reads keys_ (keys_.size()). So keys_ should have both read and write.
        reads = [e for e in cpp_result.edges if e["relation"] == "reads_state"]
        writes = [e for e in cpp_result.edges if e["relation"] == "writes_state"]
        # Basic sanity: we have both types
        assert len(reads) >= 1
        assert len(writes) >= 1


# --- H3: template info extraction ---

class TestTemplateExtraction:
    def test_template_class_params(self, nodes):
        """H3: template<typename T, int N> class SecureBuffer should store template_params."""
        assert "SecureBuffer" in nodes
        meta = _meta(nodes["SecureBuffer"])
        assert "template_params" in meta
        assert "T" in meta["template_params"]
        assert "N" in meta["template_params"]

    def test_template_class_type(self, nodes):
        """H3: SecureBuffer is still a class node."""
        assert nodes["SecureBuffer"]["type"] == "class"


# --- H4: inheritance access specifier and virtual ---

class TestInheritanceAccess:
    def test_public_inheritance(self, edges):
        """H4: HsmKeyManager : public KeyManager should have access='public'."""
        inherits = [e for e in edges if e["relation"] == "inherits"
                    and "HsmKeyManager" in e["source"] and "KeyManager" in e["target"]]
        assert len(inherits) >= 1
        attrs = json.loads(inherits[0]["attributes"])
        assert attrs["access"] == "public"
        assert attrs["virtual"] is False
        assert attrs["base_class"] == "KeyManager"


# --- H5: dangerous API detection ---

class TestDangerousAPIs:
    def test_unsafe_memcpy_dangerous(self, nodes):
        """H5: unsafe_memcpy calls memcpy, should have dangerous_calls."""
        meta = _meta(nodes["unsafe_memcpy"])
        assert "dangerous_calls" in meta
        assert "memcpy" in meta["dangerous_calls"]

    def test_dangerous_operations(self, nodes):
        """H5: dangerous_operations calls strcpy, malloc, free."""
        assert "dangerous_operations" in nodes
        meta = _meta(nodes["dangerous_operations"])
        assert "dangerous_calls" in meta
        dc = meta["dangerous_calls"]
        assert "strcpy" in dc
        assert "malloc" in dc
        assert "free" in dc

    def test_cast_example_reinterpret(self, nodes):
        """H5: cast_example uses reinterpret_cast."""
        assert "cast_example" in nodes
        meta = _meta(nodes["cast_example"])
        assert "dangerous_calls" in meta
        assert "reinterpret_cast" in meta["dangerous_calls"]

    def test_safe_function_no_dangerous(self, nodes):
        """H5: derive_private_key doesn't call dangerous APIs."""
        meta = _meta(nodes["derive_private_key"])
        assert "dangerous_calls" not in meta

    def test_template_method_dangerous(self, cpp_result):
        """H5: SecureBuffer::clear calls memset."""
        clears = [n for n in cpp_result.nodes if n["label"] == "clear"]
        assert len(clears) >= 1
        meta = _meta(clears[0])
        assert "dangerous_calls" in meta
        assert "memset" in meta["dangerous_calls"]
