from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).parents[1]
SCRIPTS = ROOT / "skills" / "audit-production-readiness" / "scripts"
sys.path.insert(0, str(SCRIPTS))

from impact_graph import (  # noqa: E402
    ImpactGraph,
    extract_js_ts_symbols,
    render_impact_markdown,
)


class ImpactGraphTests(unittest.TestCase):
    def test_python_symbol_and_call_extraction(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "service.py").write_text(
                "def helper():\n    return 42\n\n"
                "class UserService:\n"
                "    def get_user(self, user_id):\n"
                "        val = helper()\n"
                '        return f"user_{val}"\n',
                encoding="utf-8",
            )
            (root / "api.py").write_text(
                "from service import UserService\n"
                "def handler():\n"
                "    svc = UserService()\n"
                "    return svc.get_user(1)\n",
                encoding="utf-8",
            )

            graph = ImpactGraph(root)
            graph.build()

            report = graph.analyze_impact("service.py")
            self.assertEqual(report.target_file, "service.py")
            self.assertIn("helper", report.target_symbols)
            self.assertIn("UserService.get_user", report.target_symbols)
            self.assertTrue(any("api.py:handler" in c for c in report.transitive_callers))

    def test_sql_table_touch_extraction(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "repo.py").write_text(
                "def find_orders():\n    query = \"SELECT * FROM orders WHERE status = 'active'\"\n    return query\n",
                encoding="utf-8",
            )

            graph = ImpactGraph(root)
            graph.build()

            report = graph.analyze_impact("repo.py")
            self.assertIn("orders", report.tables_touched)

    def test_js_ts_symbol_extraction(self):
        js_code = (
            "export async function processPayment(amount) {\n"
            "  const res = await stripeCharge(amount);\n"
            "  const query = 'UPDATE accounts SET balance = balance - 10';\n"
            "  return res;\n"
            "}\n"
        )
        symbols = extract_js_ts_symbols("payment.ts", js_code)
        self.assertIn("processPayment", symbols)
        sym = symbols["processPayment"]
        self.assertIn("stripeCharge", sym.calls)
        self.assertIn("accounts", sym.tables_touched)

    def test_relevant_test_linking(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "auth.py").write_text(
                "def authenticate_token(token):\n    return token == 'valid'\n",
                encoding="utf-8",
            )
            (root / "tests").mkdir()
            (root / "tests" / "test_auth.py").write_text(
                "from auth import authenticate_token\ndef test_auth():\n    assert authenticate_token('valid')\n",
                encoding="utf-8",
            )

            graph = ImpactGraph(root)
            graph.build()

            report = graph.analyze_impact("auth.py")
            self.assertIn("tests/test_auth.py", report.relevant_tests)
            md = render_impact_markdown(report)
            self.assertIn("ShipProof Change Impact Analysis", md)
            self.assertIn("tests/test_auth.py", md)


if __name__ == "__main__":
    unittest.main()
