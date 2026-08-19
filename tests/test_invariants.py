from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).parents[1]
SCRIPTS = ROOT / "skills" / "audit-production-readiness" / "scripts"
sys.path.insert(0, str(SCRIPTS))

from invariants import (  # noqa: E402
    check_auth_boundary,
    check_tenant_boundary,
    check_transaction_hygiene,
    evaluate_invariants,
    render_invariants_markdown,
)


class InvariantsTests(unittest.TestCase):
    def test_admin_route_missing_auth_is_flagged(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            file_path = root / "admin_routes.py"
            file_path.write_text(
                "@app.get('/admin/users')\ndef list_all_users():\n    return {'users': []}\n",
                encoding="utf-8",
            )

            violations = check_auth_boundary(root, file_path, file_path.read_text(encoding="utf-8"))
            self.assertEqual(len(violations), 1)
            self.assertEqual(violations[0].invariant_id, "INV-AUTH-01")

    def test_admin_route_with_auth_is_not_flagged(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            file_path = root / "admin_routes.py"
            file_path.write_text(
                "@app.get('/admin/users', dependencies=[Depends(require_admin)])\n"
                "def list_all_users():\n"
                "    return {'users': []}\n",
                encoding="utf-8",
            )

            violations = check_auth_boundary(root, file_path, file_path.read_text(encoding="utf-8"))
            self.assertEqual(len(violations), 0)

    def test_tenant_repo_missing_scope_is_flagged(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            repo_dir = root / "repositories"
            repo_dir.mkdir()
            file_path = repo_dir / "user_repo.py"
            file_path.write_text(
                "class UserRepo:\n"
                "    def find_by_user_id(self, user_id):\n"
                "        return db.query(User).filter_by(id=user_id).first()\n",
                encoding="utf-8",
            )

            violations = check_tenant_boundary(
                root, file_path, file_path.read_text(encoding="utf-8")
            )
            self.assertEqual(len(violations), 1)
            self.assertEqual(violations[0].invariant_id, "INV-TENANT-01")

    def test_network_call_in_transaction_is_flagged(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            file_path = root / "order_service.py"
            file_path.write_text(
                "def checkout():\n"
                "    with db.transaction():\n"
                "        order = create_order()\n"
                "        res = requests.post('https://api.stripe.com/v1/charges', json={'order_id': order.id})\n"
                "        commit_order(order)\n",
                encoding="utf-8",
            )

            violations = check_transaction_hygiene(
                root, file_path, file_path.read_text(encoding="utf-8")
            )
            self.assertEqual(len(violations), 1)
            self.assertEqual(violations[0].invariant_id, "INV-TX-01")

    def test_full_repository_invariant_evaluation(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "safe.py").write_text("def ping(): return 'pong'\n", encoding="utf-8")
            violations = evaluate_invariants(root)
            self.assertEqual(len(violations), 0)
            md = render_invariants_markdown(violations)
            self.assertIn("PASS", md)

    def test_cli_invariants_markdown_and_json(self):
        from invariants import main

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "safe.py").write_text("def ping(): return 'pong'\n", encoding="utf-8")
            self.assertEqual(main([str(root), "--format", "markdown"]), 0)
            self.assertEqual(main([str(root), "--format", "json"]), 0)

            # Violations return exit 1
            bad_file = root / "admin.py"
            bad_file.write_text("@app.get('/admin/test')\ndef f(): pass\n", encoding="utf-8")
            self.assertEqual(main([str(root), "--format", "json"]), 1)
            self.assertEqual(main([str(root), "--format", "markdown"]), 1)


if __name__ == "__main__":
    unittest.main()
