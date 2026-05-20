import json
import pytest
from core.schema import GraphDB
from core.graph import Graph


@pytest.fixture
def graph_with_chain(tmp_db):
    """Creates a graph: f1 -> f2 -> f3 -> f4, with f3 -> state_var (writes_state)."""
    db = GraphDB(tmp_db)
    for i in range(1, 5):
        db.insert_node(id=f"a::f{i}", label=f"f{i}", type="function",
                       visibility="public" if i == 1 else "internal", file="a.sol")
    db.insert_node(id="a::balance", label="balance", type="state_var", file="a.sol")
    db.insert_edge("a::f1", "a::f2", "calls")
    db.insert_edge("a::f2", "a::f3", "calls")
    db.insert_edge("a::f3", "a::f4", "calls")
    db.insert_edge("a::f3", "a::balance", "writes_state")
    db.insert_edge("a::f1", "a::balance", "reads_state")
    return Graph(tmp_db)


class TestBFS:
    def test_reachable_from_f1(self, graph_with_chain):
        reachable = graph_with_chain.get_reachable_nodes(["a::f1"])
        assert "a::f2" in reachable
        assert "a::f3" in reachable
        assert "a::f4" in reachable
        # BFS only follows calls/flows_to/inherits, NOT reads_state/writes_state
        assert "a::balance" not in reachable

    def test_reachable_from_f3(self, graph_with_chain):
        reachable = graph_with_chain.get_reachable_nodes(["a::f3"])
        assert "a::f4" in reachable
        assert "a::f1" not in reachable

    def test_empty_start(self, graph_with_chain):
        assert graph_with_chain.get_reachable_nodes([]) == set()


class TestPathFinding:
    def test_find_path_f1_to_f4(self, graph_with_chain):
        path = graph_with_chain.find_path("a::f1", "a::f4")
        assert path == ["f1", "f2", "f3", "f4"]

    def test_no_path_f4_to_f1(self, graph_with_chain):
        path = graph_with_chain.find_path("a::f4", "a::f1")
        assert path == []

    def test_find_all_paths(self, graph_with_chain):
        paths = graph_with_chain.find_all_paths("a::f1", "a::f4", max_paths=10)
        assert len(paths) >= 1
        assert ["f1", "f2", "f3", "f4"] in paths

    def test_max_depth_limits_search(self, graph_with_chain):
        path = graph_with_chain.find_path("a::f1", "a::f4", max_depth=2)
        assert path == []


class TestStateTracing:
    def test_find_writers(self, graph_with_chain):
        writers = graph_with_chain.get_state_accessors("a::balance", "writes_state")
        assert len(writers) == 1
        assert writers[0]["id"] == "a::f3"

    def test_find_readers(self, graph_with_chain):
        readers = graph_with_chain.get_state_accessors("a::balance", "reads_state")
        assert len(readers) == 1
        assert readers[0]["id"] == "a::f1"


class TestSinkPropagation:
    def test_propagate_from_f4(self, graph_with_chain):
        wrappers = graph_with_chain.propagate_sinks(["f4"])
        labels = [w["wrapper_label"] for w in wrappers]
        assert "f3" in labels
        assert "f2" in labels
        assert "f1" in labels


class TestSinksByType:
    def test_get_sinks_by_type(self, tmp_db):
        db = GraphDB(tmp_db)
        db.insert_node(id="a::transfer", label="transfer", type="function", file="a.sol",
                       metadata=json.dumps({"is_sink": True, "sink_type": "fund_transfer"}))
        db.insert_node(id="a::selfdestruct", label="selfdestruct", type="function", file="a.sol",
                       metadata=json.dumps({"is_sink": True, "sink_type": "self_destruct"}))
        db.insert_node(id="a::foo", label="foo", type="function", file="a.sol")
        g = Graph(tmp_db)
        all_sinks = g.get_sinks_by_type()
        assert len(all_sinks) == 2
        fund_sinks = g.get_sinks_by_type("fund_transfer")
        assert len(fund_sinks) == 1
        assert fund_sinks[0]["label"] == "transfer"


class TestGuards:
    def test_guards_along_path(self, tmp_db):
        db = GraphDB(tmp_db)
        db.insert_node(id="a::deposit", label="deposit", type="function", file="a.sol")
        db.insert_node(id="a::_transfer", label="_transfer", type="function", file="a.sol")
        db.insert_node(id="a::onlyOwner", label="onlyOwner", type="modifier", file="a.sol")
        db.insert_edge("a::deposit", "a::_transfer", "calls")
        db.insert_edge("a::onlyOwner", "a::deposit", "guards")
        g = Graph(tmp_db)
        guards = g.get_guards_for("a::deposit")
        assert len(guards) == 1
        assert guards[0]["label"] == "onlyOwner"
