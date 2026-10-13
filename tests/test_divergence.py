"""Tests for core.divergence (deployed vs repo graph diff)."""
import json

from core.schema import GraphDB
from core.divergence import diff_graphs, format_report
from core.web3.solidity import SolidityExtractor


def _seed(db_path, funcs, edges, state_vars=()):
    db = GraphDB(db_path)
    for f in funcs:
        db.insert_node(
            id=f["id"], label=f["label"], type="function",
            visibility=f.get("visibility", "public"), file=f.get("file", "A.sol"),
            metadata=json.dumps(f.get("metadata", {})),
        )
    for s in state_vars:
        db.insert_node(id=s["id"], label=s["label"], type="state_var", file=s.get("file", "A.sol"))
    for e in edges:
        db.insert_edge(e[0], e[1], e[2], attributes=e[3] if len(e) > 3 else "{}")


def _func(contract, name, params="", mods=None):
    key = f"{contract}.{name}({params})" if params else f"{contract}.{name}"
    return {"id": f"A.sol::{key}", "label": name, "file": "A.sol",
            "metadata": {"contract": contract, "modifiers": mods or []}}


def test_detects_removed_guard_and_added_function(tmp_path):
    dep = str(tmp_path / "dep.db")
    rep = str(tmp_path / "rep.db")
    _seed(dep, [_func("A", "set", "uint256")], [
        ("A.sol::A.set(uint256)", "A.sol::A.x", "writes_state"),
    ], state_vars=[{"id": "A.sol::A.x", "label": "x"}])
    _seed(rep, [_func("A", "set", "uint256", ["onlyOwner"]), _func("A", "newFn")], [
        ("A.sol::A.set(uint256)", "A.sol::A.x", "writes_state"),
    ], state_vars=[{"id": "A.sol::A.x", "label": "x"}])

    report = diff_graphs(dep, rep)
    assert report["has_divergence"]
    assert "A.newFn" in report["functions_only_in_repo"]
    assert any(c["function"] == "A.set(uint256)" for c in report["changed_modifiers"])
    mod = next(c for c in report["changed_modifiers"] if c["function"] == "A.set(uint256)")
    assert mod["repo_only"] == ["onlyOwner"]


def test_detects_sink_and_write_changes(tmp_path):
    dep = str(tmp_path / "dep2.db")
    rep = str(tmp_path / "rep2.db")
    _seed(dep, [_func("A", "withdraw")], [
        ("A.sol::A.withdraw", "A.sol::A.x", "writes_state"),
    ], state_vars=[{"id": "A.sol::A.x", "label": "x"}])
    # repo adds a sink call to a synthetic sink node
    db = GraphDB(rep)
    db.insert_node(id="A.sol::A.withdraw", label="withdraw", type="function",
                   metadata=json.dumps({"contract": "A", "modifiers": []}))
    db.insert_node(id="A.sol::A._sink_call_9", label="call", type="function",
                   metadata=json.dumps({"contract": "A", "is_sink": True, "sink_type": "low_level_call"}))
    db.insert_node(id="A.sol::A.x", label="x", type="state_var")
    db.insert_edge("A.sol::A.withdraw", "A.sol::A.x", "writes_state")
    db.insert_edge("A.sol::A.withdraw", "A.sol::A._sink_call_9", "calls", attributes=json.dumps({"sink": True}))

    report = diff_graphs(dep, rep)
    assert any("call:low_level_call" in c["repo"] for c in report["changed_sinks"])


def test_contract_filter(tmp_path):
    dep = str(tmp_path / "dep3.db")
    rep = str(tmp_path / "rep3.db")
    _seed(dep, [_func("A", "f"), _func("B", "g")], [])
    _seed(rep, [_func("A", "f"), _func("B", "g"), _func("B", "h")], [])
    report = diff_graphs(dep, rep, contract="B")
    assert report["functions_only_in_repo"] == ["B.h"]
    assert report["summary"]["deployed_functions"] == 1


def test_no_divergence(tmp_path):
    dep = str(tmp_path / "dep4.db")
    rep = str(tmp_path / "rep4.db")
    _seed(dep, [_func("A", "f")], [])
    _seed(rep, [_func("A", "f")], [])
    report = diff_graphs(dep, rep)
    assert not report["has_divergence"]
    assert "No security-relevant divergence" not in format_report(report)  # formatter still renders


def test_struct_storage_fields_indexed():
    """ERC-7201 namespaced storage fields become state vars with read/write edges."""
    ex = SolidityExtractor()
    src = b"""
contract C {
    struct S { uint256 nonce; address owner; }
    bytes32 private constant SLocation = 0x00;
    function _getS() internal pure returns (S storage $) { assembly { $.slot := SLocation } }
    function f() external { S storage $ = _getS(); $.nonce = 1; uint256 x = $.owner; }
}
"""
    r = ex.extract_from_source(src, "C.sol")
    labels = {n["label"] for n in r.nodes if n["type"] == "state_var"}
    assert "S.nonce" in labels and "S.owner" in labels
    writes = {(e["source"].split("::")[-1], e["target"].split("::")[-1])
              for e in r.edges if e["relation"] == "writes_state"}
    assert any("S.nonce" in t for _, t in writes)


def test_inline_sender_guard_detected():
    """Inline `if (msg.sender != X) revert` is recognised as access control."""
    ex = SolidityExtractor()
    src = b"""
contract C {
    address dm;
    uint256 x;
    function preLiquidate(address safe) external {
        if (msg.sender != address(dm)) revert OnlyDebtManager();
        x = 1;
    }
    function open(uint256 v) external { x = v; }
}
"""
    r = ex.extract_from_source(src, "C.sol")
    by_label = {}
    for n in r.nodes:
        if n["type"] == "function":
            by_label[n["label"]] = json.loads(n["metadata"])
    guarded = by_label["preLiquidate"]
    assert guarded.get("sender_guards"), "inline sender guard not detected"
    assert "sender_check" in guarded.get("role_guards", [])
    assert "sender_guards" not in by_label["open"]


def test_local_sender_alias_guard_detected():
    """A guard comparing a local alias of _msgSender() is still access control."""
    ex = SolidityExtractor()
    src = b"""
contract C {
    address admin;
    address pauseGuardian;
    uint256 x;
    function _msgSender() internal view returns (address) { return msg.sender; }
    function pause() external {
        address sender = _msgSender();
        require(sender == admin || sender == pauseGuardian, CallerNotOwnerOrPauseGuardian());
        x = 1;
    }
    function open(uint256 v) external { x = v; }
}
"""
    r = ex.extract_from_source(src, "C.sol")
    by_label = {n["label"]: json.loads(n["metadata"]) for n in r.nodes if n["type"] == "function"}
    guarded = by_label["pause"]
    assert guarded.get("sender_guards"), "local-alias sender guard not detected"
    assert "sender_check" in guarded.get("role_guards", [])
    assert "sender_guards" not in by_label["open"]


def test_call_guard_detected():
    """Reverting access-control calls (onlyPauser/checkAccess) count as guards."""
    ex = SolidityExtractor()
    src = b"""
contract C {
    IRoleRegistry rr;
    uint256 x;
    function pause() external { rr.onlyPauser(msg.sender); x = 1; }
    function open(uint256 v) external { x = v; }
}
"""
    r = ex.extract_from_source(src, "C.sol")
    by_label = {n["label"]: json.loads(n["metadata"]) for n in r.nodes if n["type"] == "function"}
    assert by_label["pause"].get("call_guards"), "call-based guard not detected"
    assert "guard_call" in by_label["pause"].get("role_guards", [])
    assert "call_guards" not in by_label["open"]


def test_signature_guard_detected():
    """Owner-quorum signature checks count as authorization, not 'unguarded'."""
    ex = SolidityExtractor()
    src = b"""
contract C {
    uint256 x;
    function setT(uint8 t, address[] calldata signers, bytes[] calldata sigs) external {
        _currentOwner();
        bytes32 d = keccak256("x");
        if (!checkSignatures(d, signers, sigs)) revert InvalidSignatures();
        x = t;
    }
    function open(uint256 v) external { x = v; }
}
"""
    r = ex.extract_from_source(src, "C.sol")
    by_label = {n["label"]: json.loads(n["metadata"]) for n in r.nodes if n["type"] == "function"}
    assert by_label["setT"].get("signature_guards"), "signature guard not detected"
    assert "signature_guard" in by_label["setT"].get("role_guards", [])
    assert "signature_guards" not in by_label["open"]
