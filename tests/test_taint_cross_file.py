from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "skills" / "audit-production-readiness" / "scripts"))

from impact_graph import (  # noqa: E402
    ImpactGraph,
    render_impact_markdown,
)


class CrossFileTaintTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp_dir.name)

    def tearDown(self) -> None:
        self.tmp_dir.cleanup()

    def test_cross_file_sql_injection_is_traced(self) -> None:
        """Test that user input in routes/user.py flows through services/user_service.py to repos/user_repo.py sink."""
        routes_dir = self.root / "routes"
        routes_dir.mkdir(parents=True)
        services_dir = self.root / "services"
        services_dir.mkdir(parents=True)
        repos_dir = self.root / "repos"
        repos_dir.mkdir(parents=True)

        (routes_dir / "user.py").write_text(
            """
from services.user_service import get_user_by_id

@app.get('/users/{user_id}')
def get_user(user_id: str):
    return get_user_by_id(user_id)
""",
            encoding="utf-8",
        )

        (services_dir / "user_service.py").write_text(
            """
from repos.user_repo import query_user

def get_user_by_id(uid: str):
    return query_user(uid)
""",
            encoding="utf-8",
        )

        (repos_dir / "user_repo.py").write_text(
            """
import sqlite3

def query_user(raw_id: str):
    conn = sqlite3.connect("db.sqlite")
    cursor = conn.cursor()
    cursor.execute(raw_id)
    return cursor.fetchall()
""",
            encoding="utf-8",
        )

        graph = ImpactGraph(self.root)
        graph.build()

        flows = graph.taint_flows
        self.assertTrue(len(flows) >= 1)

        sql_flow = next((f for f in flows if f.sink_rule_id == "SP103"), None)
        self.assertIsNotNone(sql_flow)
        self.assertEqual(sql_flow.source_entrypoint, "get_user")
        self.assertEqual(sql_flow.sink_function, "query_user")
        self.assertFalse(sql_flow.is_sanitized)

        # Check report
        report = graph.analyze_impact("repos/user_repo.py")
        self.assertTrue(len(report.cross_file_taint_flows) >= 1)
        self.assertIn("REACHABLE", report.reachability_status)
        md = render_impact_markdown(report)
        self.assertIn("Cross-File Data-Flow Taint Traces", md)
        self.assertIn("SP103", md)

    def test_sanitized_cross_file_taint_is_marked_safe(self) -> None:
        """Test that applying a sanitizer (e.g. int() or uuid.UUID()) clears taint across files."""
        routes_dir = self.root / "routes"
        routes_dir.mkdir(parents=True)
        services_dir = self.root / "services"
        services_dir.mkdir(parents=True)
        repos_dir = self.root / "repos"
        repos_dir.mkdir(parents=True)

        (routes_dir / "user.py").write_text(
            """
from services.user_service import get_user_by_id

@app.get('/users/{user_id}')
def get_user(user_id: str):
    clean_id = int(user_id)
    return get_user_by_id(clean_id)
""",
            encoding="utf-8",
        )

        (services_dir / "user_service.py").write_text(
            """
from repos.user_repo import query_user

def get_user_by_id(uid: int):
    return query_user(uid)
""",
            encoding="utf-8",
        )

        (repos_dir / "user_repo.py").write_text(
            """
def query_user(clean_id: int):
    cursor.execute(clean_id)
""",
            encoding="utf-8",
        )

        graph = ImpactGraph(self.root)
        graph.build()

        flows = graph.taint_flows
        # If flow exists, it should be marked is_sanitized=True
        for flow in flows:
            if flow.sink_rule_id == "SP103":
                self.assertTrue(flow.is_sanitized)

    def test_standalone_unreachable_function_is_tagged_dead_code(self) -> None:
        """Test that a function not called by any route is classified as UNREACHABLE / STANDALONE."""
        utils_dir = self.root / "utils"
        utils_dir.mkdir(parents=True)

        (utils_dir / "helper.py").write_text(
            """
def orphan_function(data: str):
    return data.strip()
""",
            encoding="utf-8",
        )

        graph = ImpactGraph(self.root)
        graph.build()

        report = graph.analyze_impact("utils/helper.py")
        self.assertIn("UNREACHABLE", report.reachability_status)


if __name__ == "__main__":
    unittest.main()
