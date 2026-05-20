import json

from core.codeql_bridge import CodeQLBridge
from core.schema import GraphDB


def test_codeql_bridge_resolves_sarif_locations_to_graph_nodes(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    db_path = str(tmp_path / "graph.db")
    db = GraphDB(db_path)
    db.insert_node(
        id="src/main.go::Handle",
        label="Handle",
        type="function",
        visibility="public",
        file="src/main.go",
        line_start=10,
        line_end=20,
        signature="func Handle()",
        metadata=json.dumps({}),
    )
    db.insert_node(
        id="src/store.go::Sink",
        label="Sink",
        type="function",
        visibility="public",
        file="src/store.go",
        line_start=30,
        line_end=40,
        signature="func Sink()",
        metadata=json.dumps({}),
    )

    monkeypatch.setattr("core.codeql_bridge.shutil.which", lambda _: "codeql")
    bridge = CodeQLBridge(str(repo), db_path)
    resolved = bridge._resolve_flows([
        {
            "source_file": "src/main.go",
            "source_line": 12,
            "target_file": "src/store.go",
            "target_line": 35,
            "query": "go/sql-injection",
        },
        {
            "source_file": "src/missing.go",
            "source_line": 1,
            "target_file": "src/store.go",
            "target_line": 35,
            "query": "go/sql-injection",
        },
    ])

    assert len(resolved["flows"]) == 1
    assert resolved["flows"][0]["source"] == "src/main.go::Handle"
    assert resolved["flows"][0]["target"] == "src/store.go::Sink"
    assert resolved["unresolved_flows"] == 1
    assert resolved["unresolved_examples"][0]["source_file"] == "src/missing.go"
