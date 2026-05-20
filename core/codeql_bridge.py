"""CodeQL integration bridge — optional taint analysis via CodeQL CLI."""

import json
import os
import shutil
import subprocess
import tempfile
from collections import Counter
from pathlib import Path
from urllib.parse import unquote, urlparse
from core.schema import GraphDB


class CodeQLBridge:
    """Runs CodeQL analysis and injects flows_to edges into the knowledge graph."""

    def __init__(self, repo_path: str, db_path: str):
        self.repo_path = repo_path
        self.db_path = db_path
        self.codeql_bin = shutil.which("codeql")
        if not self.codeql_bin:
            raise RuntimeError(
                "CodeQL CLI not found in PATH. "
                "Install from https://github.com/github/codeql-cli-binaries"
            )

    def run(self, build_cmd: str | None = None) -> dict:
        """Run CodeQL analysis and inject taint edges.

        Returns: {"edges_added": int}
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            codeql_db = os.path.join(tmpdir, "codeql-db")
            language = self._detect_language()

            self._create_database(codeql_db, language, build_cmd)
            sarif_path = os.path.join(tmpdir, "results.sarif")
            self._run_queries(codeql_db, language, sarif_path)
            flows = self._parse_sarif(sarif_path)
            resolved = self._resolve_flows(flows)

            graph_db = GraphDB(self.db_path)
            edges_added = 0
            for flow in resolved["flows"]:
                graph_db.insert_edge(
                    source=flow["source"],
                    target=flow["target"],
                    relation="flows_to",
                    attributes=json.dumps({"codeql": True, "query": flow.get("query", "")}),
                )
                edges_added += 1

            return {
                "language": language,
                "raw_flows": len(flows),
                "resolved_flows": len(resolved["flows"]),
                "unresolved_flows": resolved["unresolved_flows"],
                "unresolved_examples": resolved["unresolved_examples"],
                "edges_added": edges_added,
            }

    def _detect_language(self) -> str:
        """Detect CodeQL language from repo contents."""
        repo = Path(self.repo_path)
        ext_to_lang = {
            ".go": "go",
            ".java": "java",
            ".py": "python",
            ".rs": "rust",
            ".js": "javascript",
            ".jsx": "javascript",
            ".ts": "javascript",
            ".tsx": "javascript",
            ".c": "cpp",
            ".cc": "cpp",
            ".cpp": "cpp",
            ".cxx": "cpp",
            ".h": "cpp",
            ".hpp": "cpp",
            ".hxx": "cpp",
        }
        counts: Counter[str] = Counter()
        for path in repo.rglob("*"):
            if not path.is_file():
                continue
            lang = ext_to_lang.get(path.suffix.lower())
            if lang:
                counts[lang] += 1
        if counts:
            return counts.most_common(1)[0][0]
        raise RuntimeError(
            "No CodeQL-supported source language detected. "
            "Supported here: go, java, python, rust, javascript/typescript, cpp."
        )

    def _create_database(self, db_path: str, language: str, build_cmd: str | None):
        """Create a CodeQL database from the repo."""
        cmd = [
            self.codeql_bin, "database", "create", db_path,
            "--language", language,
            "--source-root", self.repo_path,
            "--overwrite",
        ]
        if build_cmd:
            cmd.extend(["--command", build_cmd])
        subprocess.run(cmd, check=True, capture_output=True, text=True)

    def _run_queries(self, codeql_db: str, language: str, sarif_path: str):
        """Run CodeQL security queries and output SARIF."""
        cmd = [
            self.codeql_bin, "database", "analyze", codeql_db,
            f"codeql/{language}-queries:codeql-suites/{language}-security-extended.qls",
            "--format", "sarifv2.1.0",
            "--output", sarif_path,
        ]
        subprocess.run(cmd, check=True, capture_output=True, text=True)

    def _parse_sarif(self, sarif_path: str) -> list[dict]:
        """Parse SARIF results into raw location-to-location flows."""
        if not os.path.exists(sarif_path):
            return []

        with open(sarif_path) as f:
            sarif = json.load(f)

        flows = []
        for run in sarif.get("runs", []):
            for result in run.get("results", []):
                code_flows = result.get("codeFlows", [])
                query_id = result.get("ruleId", "")
                for cf in code_flows:
                    for thread_flow in cf.get("threadFlows", []):
                        locations = thread_flow.get("locations", [])
                        if len(locations) >= 2:
                            source_loc = locations[0].get("location", {})
                            sink_loc = locations[-1].get("location", {})
                            source_file = self._extract_file(source_loc)
                            sink_file = self._extract_file(sink_loc)
                            source_line = self._extract_line(source_loc)
                            sink_line = self._extract_line(sink_loc)
                            if source_file and sink_file:
                                flows.append({
                                    "source_file": source_file,
                                    "source_line": source_line,
                                    "target_file": sink_file,
                                    "target_line": sink_line,
                                    "query": query_id,
                                })
        return flows

    def _resolve_flows(self, flows: list[dict]) -> dict:
        """Resolve SARIF locations back to graph nodes so traversal composes."""
        graph_db = GraphDB(self.db_path)
        conn = graph_db.get_connection()
        try:
            resolved = []
            unresolved = 0
            unresolved_examples = []
            for flow in flows:
                source_id = self._resolve_node_id(conn, flow["source_file"], flow["source_line"])
                target_id = self._resolve_node_id(conn, flow["target_file"], flow["target_line"])
                if source_id and target_id and source_id != target_id:
                    resolved.append({
                        "source": source_id,
                        "target": target_id,
                        "query": flow.get("query", ""),
                    })
                    continue

                unresolved += 1
                if len(unresolved_examples) < 10:
                    unresolved_examples.append({
                        "source_file": self._normalize_repo_file(flow["source_file"]) or flow["source_file"],
                        "source_line": flow["source_line"],
                        "target_file": self._normalize_repo_file(flow["target_file"]) or flow["target_file"],
                        "target_line": flow["target_line"],
                        "query": flow.get("query", ""),
                    })
            return {
                "flows": resolved,
                "unresolved_flows": unresolved,
                "unresolved_examples": unresolved_examples,
            }
        finally:
            conn.close()

    def _normalize_repo_file(self, file_path: str) -> str | None:
        """Normalize SARIF file references to the relative paths used in the graph."""
        if not file_path:
            return None
        parsed = urlparse(file_path)
        if parsed.scheme == "file":
            file_path = unquote(parsed.path)
        file_path = file_path.replace("\\", "/")
        repo_root = str(Path(self.repo_path).resolve()).replace("\\", "/")
        if os.path.isabs(file_path):
            abs_path = str(Path(file_path).resolve()).replace("\\", "/")
            if abs_path == repo_root:
                return "."
            if not abs_path.startswith(repo_root.rstrip("/") + "/"):
                return None
            rel_path = os.path.relpath(abs_path, self.repo_path)
        else:
            rel_path = file_path
        rel_path = rel_path.replace("\\", "/")
        while rel_path.startswith("./"):
            rel_path = rel_path[2:]
        return rel_path

    def _resolve_node_id(self, conn, file_path: str, line: int) -> str | None:
        repo_file = self._normalize_repo_file(file_path)
        if not repo_file:
            return None

        row = conn.execute(
            """
            SELECT id, type, line_start, line_end
            FROM nodes
            WHERE REPLACE(file, '\\', '/') = ?
              AND line_start <= ?
              AND line_end >= ?
            ORDER BY
              CASE WHEN type = 'function' THEN 0 WHEN type = 'modifier' THEN 1 ELSE 2 END,
              (line_end - line_start) ASC
            LIMIT 1
            """,
            (repo_file, line, line),
        ).fetchone()
        if row:
            return row["id"]

        nearest = conn.execute(
            """
            SELECT id, type, ABS(line_start - ?) AS distance
            FROM nodes
            WHERE REPLACE(file, '\\', '/') = ?
            ORDER BY
              CASE WHEN type = 'function' THEN 0 WHEN type = 'modifier' THEN 1 ELSE 2 END,
              distance ASC
            LIMIT 1
            """,
            (line, repo_file),
        ).fetchone()
        if nearest and nearest["distance"] <= 3:
            return nearest["id"]
        return None

    def _extract_file(self, location: dict) -> str | None:
        """Extract file path from SARIF location."""
        physical = location.get("physicalLocation", {})
        artifact = physical.get("artifactLocation", {})
        return artifact.get("uri")

    def _extract_line(self, location: dict) -> int:
        """Extract line number from SARIF location."""
        physical = location.get("physicalLocation", {})
        region = physical.get("region", {})
        return region.get("startLine", 0)
