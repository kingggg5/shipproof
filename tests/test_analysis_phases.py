from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).parents[1]
SCRIPTS = ROOT / "skills" / "audit-production-readiness" / "scripts"
sys.path.insert(0, str(SCRIPTS))

from analysis import (  # noqa: E402
    analyze_program,
    group_by_root_cause,
    run_invariants,
)
from impact_graph import ImpactGraph, build_ir_program  # noqa: E402
from ir import IREffect, IRFunction, IRGuard, IRProgram  # noqa: E402


class RootCauseGroupingTests(unittest.TestCase):
    def test_same_sink_groups_together(self) -> None:
        flows = [
            {
                "sink_rule_id": "SP103",
                "sink_function": "execute",
                "source_entrypoint": "a",
                "source_file": "a.py",
                "sink_file": "db.py",
                "sink_line": 5,
                "sink_type": "sql_injection",
                "is_sanitized": False,
            },
            {
                "sink_rule_id": "SP103",
                "sink_function": "execute",
                "source_entrypoint": "b",
                "source_file": "b.py",
                "sink_file": "db.py",
                "sink_line": 5,
                "sink_type": "sql_injection",
                "is_sanitized": False,
            },
        ]
        groups = group_by_root_cause(flows)
        self.assertEqual(len(groups), 1)
        self.assertEqual(len(groups[0].finding_ids), 2)

    def test_sanitized_flows_excluded_from_grouping(self) -> None:
        flows = [
            {
                "sink_rule_id": "SP103",
                "sink_function": "e",
                "source_entrypoint": "a",
                "source_file": "a.py",
                "sink_file": "db.py",
                "sink_line": 1,
                "is_sanitized": True,
            },
        ]
        self.assertEqual(group_by_root_cause(flows), [])


class AuthDominanceTests(unittest.TestCase):
    def test_privileged_effect_without_guard_flagged(self) -> None:
        fn = IRFunction(
            name="delete_all",
            file="admin.py",
            params=[],
            line_start=1,
            line_end=3,
            is_entrypoint=True,
            entry_taint_vars=[],
            sinks=[],
            callees=[],
            sanitized_params=set(),
            aliases={},
            effects=[IREffect(kind="db_write", target="users", line=2)],
            guards=[],
        )
        prog = IRProgram(functions=[fn])
        violations = run_invariants(prog)
        auth_v = [v for v in violations if v.invariant_id == "auth-dominance"]
        self.assertEqual(len(auth_v), 1)

    def test_with_auth_guard_no_violation(self) -> None:
        fn = IRFunction(
            name="delete_all",
            file="admin.py",
            params=[],
            line_start=1,
            line_end=3,
            is_entrypoint=True,
            entry_taint_vars=[],
            sinks=[],
            callees=[],
            sanitized_params=set(),
            aliases={},
            effects=[IREffect(kind="db_write", target="users", line=2)],
            guards=[IRGuard(kind="authorization", expression="requireAdmin(user)", line=1)],
        )
        prog = IRProgram(functions=[fn])
        violations = run_invariants(prog)
        auth_v = [v for v in violations if v.invariant_id == "auth-dominance"]
        self.assertEqual(auth_v, [])

    def test_auth_guard_after_effect_does_not_dominate(self) -> None:
        fn = IRFunction(
            name="delete_all",
            file="admin.py",
            params=[],
            line_start=1,
            line_end=10,
            is_entrypoint=True,
            entry_taint_vars=[],
            sinks=[],
            callees=[],
            sanitized_params=set(),
            aliases={},
            effects=[IREffect(kind="db_write", target="users", line=2)],
            guards=[IRGuard(kind="authorization", expression="requireAdmin(user)", line=9)],
        )
        violations = run_invariants(IRProgram(functions=[fn]))
        self.assertEqual(
            len([item for item in violations if item.invariant_id == "auth-dominance"]),
            1,
        )


class TenantIsolationTests(unittest.TestCase):
    def test_tenant_context_without_scope_flagged(self) -> None:
        fn = IRFunction(
            name="update_invoice",
            file="billing.py",
            params=["tenant_id", "invoice_id"],
            line_start=1,
            line_end=5,
            is_entrypoint=True,
            entry_taint_vars=["tenant_id"],
            sinks=[],
            callees=[],
            sanitized_params=set(),
            aliases={},
            effects=[IREffect(kind="db_write", target="invoices", line=3)],
            guards=[],
        )
        prog = IRProgram(functions=[fn])
        violations = run_invariants(prog)
        tenant_v = [v for v in violations if v.invariant_id == "tenant-isolation"]
        self.assertEqual(len(tenant_v), 1)
        self.assertEqual(tenant_v[0].severity, "critical")

    def test_non_entrypoint_skipped(self) -> None:
        fn = IRFunction(
            name="helper",
            file="util.py",
            params=["tenant_id"],
            line_start=1,
            line_end=2,
            is_entrypoint=False,
            entry_taint_vars=["tenant_id"],
            sinks=[],
            callees=[],
            sanitized_params=set(),
            aliases={},
            effects=[IREffect(kind="db_write", target="data", line=2)],
            guards=[],
        )
        prog = IRProgram(functions=[fn])
        self.assertEqual(run_invariants(prog), [])


class FullPipelineTests(unittest.TestCase):
    """End-to-end through ImpactGraph → IR → unified analysis."""

    def setUp(self) -> None:
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp_dir.name)

    def tearDown(self) -> None:
        self.tmp_dir.cleanup()

    def test_full_analysis_pipeline(self) -> None:
        routes = self.root / "routes.py"
        routes.parent.mkdir(parents=True, exist_ok=True)
        routes.write_text("""
from svc import handle

@app.post("/items")
def create_item(item_name):
    return handle(item_name)
""")
        svc = self.root / "svc.py"
        svc.write_text("""
def handle(name):
    cursor.execute("INSERT INTO items VALUES ('" + name + "')")
""")
        graph = ImpactGraph(self.root)
        graph.build()
        program = build_ir_program(graph)
        result = analyze_program(program)

        self.assertGreater(result.total_functions, 0)
        sql_flows = [f for f in result.taint_flows if f["sink_rule_id"] == "SP103"]
        self.assertEqual(len(sql_flows), 1)
        self.assertGreater(len(result.root_cause_groups), 0)
        self.assertIn("svc.py", result.effect_summary)


if __name__ == "__main__":
    unittest.main()
