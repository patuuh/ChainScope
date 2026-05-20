"""Tests for C-specific security pattern detection in C++ parser."""

import json
import pytest
from pathlib import Path
from core.web3.cpp import CppExtractor


@pytest.fixture(scope="module")
def c_result():
    ext = CppExtractor()
    src = Path("tests/fixtures/vuln_sample.c").read_bytes()
    return ext.extract_from_source(src, "vuln_sample.c")


@pytest.fixture(scope="module")
def func_meta(c_result):
    """Map function label -> parsed metadata dict."""
    out = {}
    for n in c_result.nodes:
        if n["type"] == "function":
            out[n["label"]] = json.loads(n["metadata"] or "{}")
    return out


class TestBufferOverflow:
    def test_strcpy_detected(self, func_meta):
        meta = func_meta["copy_name"]
        assert "buffer_overflow_risk" in meta
        assert any("strcpy" in e["detail"] for e in meta["buffer_overflow_risk"])

    def test_sprintf_detected(self, func_meta):
        meta = func_meta["format_message"]
        assert "buffer_overflow_risk" in meta
        assert any("sprintf" in e["detail"] for e in meta["buffer_overflow_risk"])

    def test_clean_function_no_overflow(self, func_meta):
        meta = func_meta["add"]
        assert "buffer_overflow_risk" not in meta


class TestFormatString:
    def test_printf_variable_format(self, func_meta):
        meta = func_meta["log_input"]
        assert "format_string_risk" in meta
        assert any("printf" in e["detail"] for e in meta["format_string_risk"])

    def test_fprintf_variable_format(self, func_meta):
        meta = func_meta["log_to_file"]
        assert "format_string_risk" in meta

    def test_sprintf_with_literal_no_fmtstr(self, func_meta):
        # format_message uses sprintf with a literal format "Hello, %s!"
        meta = func_meta["format_message"]
        assert "format_string_risk" not in meta


class TestCommandInjection:
    def test_system_variable(self, func_meta):
        meta = func_meta["run_command"]
        assert "command_injection_risk" in meta
        assert any("system" in e["detail"] for e in meta["command_injection_risk"])

    def test_popen_variable(self, func_meta):
        meta = func_meta["run_pipe"]
        assert "command_injection_risk" in meta
        assert any("popen" in e["detail"] for e in meta["command_injection_risk"])


class TestUseAfterFree:
    def test_free_then_use(self, func_meta):
        meta = func_meta["process_data"]
        assert "use_after_free_risk" in meta

    def test_free_reassign_use_safe(self, func_meta):
        meta = func_meta["safe_realloc"]
        assert "use_after_free_risk" not in meta


class TestDoubleFree:
    def test_double_free(self, func_meta):
        meta = func_meta["cleanup_twice"]
        assert "double_free_risk" in meta


class TestNullDeref:
    def test_malloc_no_check(self, func_meta):
        meta = func_meta["alloc_no_check"]
        assert "null_deref_risk" in meta

    def test_calloc_no_check(self, func_meta):
        meta = func_meta["alloc_calloc"]
        assert "null_deref_risk" in meta

    def test_malloc_with_check_safe(self, func_meta):
        meta = func_meta["alloc_safe"]
        assert "null_deref_risk" not in meta


class TestToctou:
    def test_access_then_open(self, func_meta):
        meta = func_meta["check_and_open"]
        assert "toctou_risk" in meta


class TestPathTraversal:
    def test_fopen_with_param(self, func_meta):
        meta = func_meta["open_user_file"]
        assert "path_traversal_risk" in meta


class TestIntegerOverflow:
    def test_arithmetic_in_malloc(self, func_meta):
        meta = func_meta["alloc_computed"]
        assert "integer_overflow_risk" in meta


class TestUninitializedUse:
    def test_uninit_var(self, func_meta):
        meta = func_meta["use_uninit"]
        assert "uninitialized_use" in meta


class TestNegativeCases:
    def test_system_literal_no_injection(self, func_meta):
        meta = func_meta["run_literal"]
        assert "command_injection_risk" not in meta

    def test_fopen_literal_no_traversal(self, func_meta):
        meta = func_meta["open_config"]
        assert "path_traversal_risk" not in meta


class TestMultipleRisks:
    def test_combo_function(self, func_meta):
        meta = func_meta["dangerous_combo"]
        assert "buffer_overflow_risk" in meta
        assert "format_string_risk" in meta


class TestCleanFunction:
    def test_no_risks(self, func_meta):
        meta = func_meta["add"]
        risk_fields = [
            "buffer_overflow_risk", "format_string_risk", "command_injection_risk",
            "use_after_free_risk", "double_free_risk", "null_deref_risk",
            "integer_overflow_risk", "toctou_risk", "path_traversal_risk",
            "uninitialized_use",
        ]
        for field in risk_fields:
            assert field not in meta


class TestCScoring:
    """Test that C functions get differentiated scores via cs_hotspots."""

    @pytest.fixture(scope="class")
    def hotspot_results(self, tmp_path_factory):
        """Build a graph from vuln_sample.c and run cs_hotspots."""
        from core.schema import GraphDB
        from core.web3.cpp import CppExtractor

        db_path = str(tmp_path_factory.mktemp("scoring") / "test.db")
        graph_db = GraphDB(db_path)
        conn = graph_db.get_connection()

        ext = CppExtractor()
        src = Path("tests/fixtures/vuln_sample.c").read_bytes()
        result = ext.extract_from_source(src, "vuln_sample.c")

        for node in result.nodes:
            conn.execute(
                "INSERT INTO nodes (id, label, type, file, visibility, line_start, line_end, signature, metadata) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (node["id"], node["label"], node["type"], node["file"],
                 node["visibility"], node["line_start"], node["line_end"],
                 node["signature"], node["metadata"])
            )
        for edge in result.edges:
            conn.execute(
                "INSERT OR IGNORE INTO edges (source, target, relation, attributes) VALUES (?, ?, ?, ?)",
                (edge["source"], edge["target"], edge["relation"], edge["attributes"])
            )
        conn.commit()
        conn.close()

        import mcp_server
        results = json.loads(mcp_server.cs_hotspots(db=db_path, top=50))
        return {h["function"]: h for h in results["hotspots"]}

    def test_command_injection_scores_high(self, hotspot_results):
        assert "run_command" in hotspot_results
        assert hotspot_results["run_command"]["score"] >= 5

    def test_clean_function_not_in_hotspots(self, hotspot_results):
        assert "add" not in hotspot_results

    def test_multi_risk_scores_higher(self, hotspot_results):
        if "dangerous_combo" in hotspot_results and "run_command" in hotspot_results:
            assert hotspot_results["dangerous_combo"]["score"] >= 6

    def test_scores_are_differentiated(self, hotspot_results):
        scores = [h["score"] for h in hotspot_results.values()]
        assert len(set(scores)) > 1, f"All scores identical: {scores}"
