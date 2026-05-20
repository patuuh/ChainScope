# tests/test_solidity_advanced.py
import json
import pytest
from pathlib import Path
from core.web3.solidity import SolidityExtractor

FIXTURES = Path(__file__).parent / "fixtures"

@pytest.fixture
def extractor():
    return SolidityExtractor()

@pytest.fixture
def advanced_result(extractor):
    code = (FIXTURES / "advanced_vault.sol").read_bytes()
    return extractor.extract_from_source(code, "advanced_vault.sol")


# ---------------------------------------------------------------------------
# Existing tests
# ---------------------------------------------------------------------------

class TestConstructor:
    def test_constructor_extracted(self, advanced_result):
        labels = {n["label"] for n in advanced_result.nodes if n["type"] == "function"}
        assert "constructor" in labels

    def test_constructor_writes_state(self, advanced_result):
        writes = [e for e in advanced_result.edges if e["relation"] == "writes_state"]
        constructor_writes = [e for e in writes if "constructor" in e["source"]]
        assert len(constructor_writes) > 0

class TestFallbackReceive:
    def test_receive_extracted(self, advanced_result):
        labels = {n["label"] for n in advanced_result.nodes if n["type"] == "function"}
        assert "receive" in labels

    def test_fallback_extracted(self, advanced_result):
        labels = {n["label"] for n in advanced_result.nodes if n["type"] == "function"}
        assert "fallback" in labels

    def test_receive_is_external(self, advanced_result):
        funcs = {n["label"]: n for n in advanced_result.nodes if n["type"] == "function"}
        assert funcs["receive"]["visibility"] == "external"

class TestOverloading:
    def test_both_withdraw_variants_extracted(self, advanced_result):
        withdraw_funcs = [n for n in advanced_result.nodes
                         if n["type"] == "function" and "withdraw" in n["label"]]
        assert len(withdraw_funcs) >= 2

class TestMultiContract:
    def test_no_node_id_collision(self, advanced_result):
        """All node IDs should be unique."""
        ids = [n["id"] for n in advanced_result.nodes]
        assert len(ids) == len(set(ids))


# ---------------------------------------------------------------------------
# C1: Statement-order tracking (reentrancy detection)
# ---------------------------------------------------------------------------

class TestStatementOrder:
    def test_calls_edges_have_order(self, advanced_result):
        """calls edges produced from function bodies should have an order attribute."""
        calls = [e for e in advanced_result.edges if e["relation"] == "calls"]
        body_calls = [e for e in calls if "withdraw" in e["source"]]
        orders_found = []
        for e in body_calls:
            attrs = json.loads(e["attributes"])
            if "order" in attrs:
                orders_found.append(attrs["order"])
        assert len(orders_found) > 0, "No order attributes found on call edges"

    def test_writes_state_edges_have_order(self, advanced_result):
        """writes_state edges should have an order attribute."""
        writes = [e for e in advanced_result.edges if e["relation"] == "writes_state"]
        withdraw_writes = [e for e in writes if "withdraw" in e["source"]]
        orders_found = []
        for e in withdraw_writes:
            attrs = json.loads(e["attributes"])
            if "order" in attrs:
                orders_found.append(attrs["order"])
        assert len(orders_found) > 0, "No order attributes found on writes_state edges"

    def test_reads_state_edges_have_order(self, advanced_result):
        """reads_state edges should have an order attribute."""
        reads = [e for e in advanced_result.edges if e["relation"] == "reads_state"]
        withdraw_reads = [e for e in reads if "withdraw" in e["source"]]
        orders_found = []
        for e in withdraw_reads:
            attrs = json.loads(e["attributes"])
            if "order" in attrs:
                orders_found.append(attrs["order"])
        assert len(orders_found) > 0, "No order attributes found on reads_state edges"


# ---------------------------------------------------------------------------
# C2: Low-level call detection
# ---------------------------------------------------------------------------

class TestLowLevelCallDetection:
    def _get_sinks(self, result):
        sinks = []
        for n in result.nodes:
            meta = json.loads(n.get("metadata", "{}"))
            if meta.get("is_sink"):
                sinks.append(meta)
        return sinks

    def test_bare_call_detected(self, advanced_result):
        """target.call(data) without {value:} should be detected as low_level_call sink."""
        sinks = self._get_sinks(advanced_result)
        types = {s.get("sink_type") for s in sinks}
        assert "low_level_call" in types, f"Expected low_level_call in sinks, got: {types}"

    def test_staticcall_detected(self, advanced_result):
        """target.staticcall(data) should be detected as static_call sink."""
        sinks = self._get_sinks(advanced_result)
        types = {s.get("sink_type") for s in sinks}
        assert "static_call" in types, f"Expected static_call in sinks, got: {types}"

    def test_call_with_value_still_fund_transfer(self, advanced_result):
        """msg.sender.call{value: amount} should still be fund_transfer."""
        sinks = self._get_sinks(advanced_result)
        types = {s.get("sink_type") for s in sinks}
        assert "fund_transfer" in types


# ---------------------------------------------------------------------------
# C3: tx.origin tracking
# ---------------------------------------------------------------------------

class TestTxOriginTracking:
    def test_tx_origin_metadata(self, advanced_result):
        """Function using tx.origin should have uses_tx_origin in metadata."""
        funcs = {n["label"]: n for n in advanced_result.nodes if n["type"] == "function"}
        assert "unsafeAuth" in funcs
        meta = json.loads(funcs["unsafeAuth"]["metadata"])
        assert meta.get("uses_tx_origin") is True

    def test_tx_origin_edge(self, advanced_result):
        """Function using tx.origin should emit a reads_state edge with tx_origin flag."""
        edges = [e for e in advanced_result.edges
                 if e["relation"] == "reads_state" and "unsafeAuth" in e["source"]]
        tx_edges = [e for e in edges
                    if json.loads(e["attributes"]).get("tx_origin") is True]
        assert len(tx_edges) > 0

    def test_functions_without_tx_origin(self, advanced_result):
        """Functions NOT using tx.origin should not have the flag."""
        funcs = {n["label"]: n for n in advanced_result.nodes if n["type"] == "function"}
        if "execute" in funcs:
            meta = json.loads(funcs["execute"]["metadata"])
            assert "uses_tx_origin" not in meta


# ---------------------------------------------------------------------------
# H1: Unchecked block detection
# ---------------------------------------------------------------------------

class TestUncheckedBlocks:
    def test_has_unchecked_metadata(self, advanced_result):
        """Function with unchecked block should have has_unchecked in metadata."""
        funcs = {n["label"]: n for n in advanced_result.nodes if n["type"] == "function"}
        assert "batchAdd" in funcs
        meta = json.loads(funcs["batchAdd"]["metadata"])
        assert meta.get("has_unchecked") is True

    def test_unchecked_edges(self, advanced_result):
        """Edges from operations inside unchecked blocks should have unchecked=true."""
        writes = [e for e in advanced_result.edges if e["relation"] == "writes_state"]
        batch_writes = [e for e in writes if "batchAdd" in e["source"]]
        unchecked_writes = [e for e in batch_writes
                           if json.loads(e["attributes"]).get("unchecked") is True]
        assert len(unchecked_writes) > 0

    def test_function_without_unchecked(self, advanced_result):
        """Functions without unchecked blocks should not have the flag."""
        funcs = {n["label"]: n for n in advanced_result.nodes if n["type"] == "function"}
        if "execute" in funcs:
            meta = json.loads(funcs["execute"]["metadata"])
            assert "has_unchecked" not in meta


# ---------------------------------------------------------------------------
# H2: Storage/memory/calldata data location
# ---------------------------------------------------------------------------

class TestDataLocations:
    def test_param_locations_captured(self, advanced_result):
        """Functions with data location qualifiers should have param_locations."""
        funcs = {n["label"]: n for n in advanced_result.nodes if n["type"] == "function"}
        # batchAdd has uint256[] memory values
        assert "batchAdd" in funcs
        meta = json.loads(funcs["batchAdd"]["metadata"])
        assert "param_locations" in meta
        locs = meta["param_locations"]
        assert any(pl["location"] == "memory" for pl in locs)

    def test_calldata_location(self, advanced_result):
        """execute() has bytes calldata data - should be captured."""
        funcs = {n["label"]: n for n in advanced_result.nodes if n["type"] == "function"}
        assert "execute" in funcs
        meta = json.loads(funcs["execute"]["metadata"])
        assert "param_locations" in meta
        locs = meta["param_locations"]
        assert any(pl["location"] == "calldata" for pl in locs)


# ---------------------------------------------------------------------------
# H3: Modifier body edge extraction
# ---------------------------------------------------------------------------

class TestModifierBodyEdges:
    def test_modifier_reads_state(self, advanced_result):
        """nonReentrant modifier reads _locked state var."""
        reads = [e for e in advanced_result.edges if e["relation"] == "reads_state"]
        mod_reads = [e for e in reads if "nonReentrant" in e["source"]]
        assert len(mod_reads) > 0, "nonReentrant modifier should have reads_state edges"

    def test_modifier_writes_state(self, advanced_result):
        """nonReentrant modifier writes _locked state var."""
        writes = [e for e in advanced_result.edges if e["relation"] == "writes_state"]
        mod_writes = [e for e in writes if "nonReentrant" in e["source"]]
        assert len(mod_writes) > 0, "nonReentrant modifier should have writes_state edges"


# ---------------------------------------------------------------------------
# MEDIUM: Interface type fix
# ---------------------------------------------------------------------------

class TestInterfaceType:
    def test_interface_has_interface_type(self, advanced_result):
        """interface_declaration nodes should have type='interface', not 'struct'."""
        ifaces = [n for n in advanced_result.nodes if n["type"] == "interface"]
        labels = {n["label"] for n in ifaces}
        assert "IVaultCallback" in labels


# ---------------------------------------------------------------------------
# MEDIUM: Struct declarations
# ---------------------------------------------------------------------------

class TestStructDeclarations:
    def test_global_struct_extracted(self, advanced_result):
        """Top-level struct GlobalPosition should be extracted."""
        structs = [n for n in advanced_result.nodes if n["type"] == "struct"]
        labels = {n["label"] for n in structs}
        assert "GlobalPosition" in labels

    def test_contract_struct_extracted(self, advanced_result):
        """Struct inside contract (VaultConfig) should be extracted."""
        structs = [n for n in advanced_result.nodes if n["type"] == "struct"]
        labels = {n["label"] for n in structs}
        assert "VaultConfig" in labels


class TestPrivilegeMetadata:
    def test_execute_is_marked_as_arbitrary_call_surface(self, advanced_result):
        funcs = {n["label"]: n for n in advanced_result.nodes if n["type"] == "function"}
        meta = json.loads(funcs["execute"]["metadata"])
        assert "privileged_operations" in meta
        assert "arbitrary_call" in meta["privileged_operations"]
        assert meta.get("unguarded_privileged_operation") is True

    def test_withdraw_has_role_guard_from_modifier(self, advanced_result):
        funcs = {n["label"]: n for n in advanced_result.nodes if n["type"] == "function"}
        meta = json.loads(funcs["withdraw"]["metadata"])
        # two overloads share the same label; at least one should show modifier-based protection
        assert "modifiers" in meta or meta.get("role_guards")


# ---------------------------------------------------------------------------
# MEDIUM: Library declarations
# ---------------------------------------------------------------------------

class TestLibraryDeclarations:
    def test_library_extracted(self, advanced_result):
        """library SafeMath should be extracted."""
        libs = [n for n in advanced_result.nodes if n["type"] == "library"]
        labels = {n["label"] for n in libs}
        assert "SafeMath" in labels

    def test_library_functions_extracted(self, advanced_result):
        """Functions inside library should be extracted."""
        funcs = {n["label"]: n for n in advanced_result.nodes if n["type"] == "function"}
        assert "add" in funcs


# ---------------------------------------------------------------------------
# MEDIUM: Assembly block detection
# ---------------------------------------------------------------------------

class TestAssemblyDetection:
    def test_has_assembly_metadata(self, advanced_result):
        """Function with assembly block should have has_assembly in metadata."""
        funcs = {n["label"]: n for n in advanced_result.nodes if n["type"] == "function"}
        assert "getSlot" in funcs
        meta = json.loads(funcs["getSlot"]["metadata"])
        assert meta.get("has_assembly") is True

    def test_function_without_assembly(self, advanced_result):
        """Functions without assembly should not have the flag."""
        funcs = {n["label"]: n for n in advanced_result.nodes if n["type"] == "function"}
        if "execute" in funcs:
            meta = json.loads(funcs["execute"]["metadata"])
            assert "has_assembly" not in meta
