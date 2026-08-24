from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).parents[1]
SCRIPTS = ROOT / "skills" / "audit-production-readiness" / "scripts"
sys.path.insert(0, str(SCRIPTS))

from impact_graph import ImpactGraph, build_ir_program  # noqa: E402
from ir import IRProgram, aggregate_effects, propagate_taint  # noqa: E402


class IRPipelineTests(unittest.TestCase):
    """End-to-end tests for the unified IR pipeline."""

    def setUp(self) -> None:
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp_dir.name)

    def tearDown(self) -> None:
        self.tmp_dir.cleanup()

    def _write(self, rel: str, content: str) -> None:
        target = self.root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")

    def _build(self) -> tuple:
        graph = ImpactGraph(self.root)
        graph.build()
        program = build_ir_program(graph)
        return graph, program

    def test_ir_functions_created_for_all_files(self) -> None:
        self._write("a.py", "def fa(x):\n    pass\n")
        self._write("b.js", "function fb(y) { return y; }")
        _, prog = self._build()
        self.assertGreaterEqual(len(prog.functions), 2)
        files = {fn.file for fn in prog.functions}
        self.assertIn("a.py", files)
        self.assertIn("b.js", files)

    def test_cross_language_call_graph_connected(self) -> None:
        self._write(
            "main.py",
            """
from helper import process
def run(data):
    return process(data)
""",
        )
        self._write(
            "helper.py",
            """
def process(value):
    return value.strip()
""",
        )
        _, prog = self._build()
        names = {f.name for f in prog.functions}
        self.assertIn("run", names)
        self.assertIn("process", names)

    def test_ir_preserves_function_lines_and_sink_effects(self) -> None:
        self._write(
            "app.py",
            """
@app.get('/items/{value}')
def handler(value):
    cursor.execute(value)
""",
        )
        _, prog = self._build()
        handler = next(fn for fn in prog.functions if fn.name == "handler")
        self.assertGreater(handler.line_start, 0)
        self.assertGreaterEqual(handler.line_end, handler.line_start)
        self.assertEqual([effect.kind for effect in handler.effects], ["db_read"])

    def test_propagate_taint_produces_flows(self) -> None:
        self._write(
            "routes.py",
            """
from svc import handle

@app.post("/items")
def create_item(item_name):
    return handle(item_name)
""",
        )
        self._write(
            "svc.py",
            """
from db import execute

def handle(name):
    return execute("INSERT INTO items VALUES ('" + name + "')")
""",
        )
        self._write(
            "db.py",
            """
def execute(query):
    cursor.execute(query)
""",
        )
        _, prog = self._build()
        flows = propagate_taint(prog)
        sql_flows = [f for f in flows if f["sink_rule_id"] == "SP103"]
        self.assertEqual(len(sql_flows), 1)
        self.assertEqual(sql_flows[0]["source_file"], "routes.py")
        # Sink fires where execute() lives (svc.py), not at the entrypoint
        self.assertEqual(sql_flows[0]["sink_file"], "svc.py")
        self.assertFalse(sql_flows[0]["is_sanitized"])

    def test_sanitized_chain_produces_no_unsanitized_flow(self) -> None:
        self._write(
            "routes.py",
            """
from svc import safe_handle

@app.get("/items/:id")
def get_item(item_id):
    return safe_handle(item_id)
""",
        )
        self._write(
            "svc.py",
            """
from db import query

def safe_handle(raw_id):
    clean_id = int(raw_id)
    return query(clean_id)
""",
        )
        self._write(
            "db.py",
            """
def query(pk):
    cursor.execute("SELECT * FROM items WHERE id = ?", [pk])
""",
        )
        _, prog = self._build()
        flows = propagate_taint(prog)
        unsanitized = [f for f in flows if not f["is_sanitized"]]
        self.assertEqual(unsanitized, [])

    def test_aggregate_effects_counts_per_file(self) -> None:
        from ir import IREffect, IRFunction

        fn = IRFunction(
            name="handler",
            file="app.py",
            params=[],
            line_start=1,
            line_end=5,
            is_entrypoint=False,
            entry_taint_vars=[],
            sinks=[],
            callees=[],
            sanitized_params=set(),
            aliases={},
            effects=[
                IREffect(kind="db_read", target="users", line=2),
                IREffect(kind="http_call", target="/api/x", line=3),
                IREffect(kind="db_read", target="orders", line=4),
            ],
            guards=[],
        )
        prog = IRProgram(functions=[fn])
        agg = aggregate_effects(prog)
        self.assertEqual(agg["app.py"]["db_read"], 2)
        self.assertEqual(agg["app.py"]["http_call"], 1)


if __name__ == "__main__":
    unittest.main()
