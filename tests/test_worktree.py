import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "skills" / "audit-production-readiness" / "scripts"))

from worktree_manager import VALID_TASK_NAME, create_worktree, list_worktrees, main  # noqa: E402


class WorktreeTests(unittest.TestCase):
    def test_valid_task_name_regex(self):
        self.assertTrue(VALID_TASK_NAME.match("fix-sp591"))
        self.assertTrue(VALID_TASK_NAME.match("task_123"))
        self.assertTrue(VALID_TASK_NAME.match("featureA"))

        # Rejects path traversal and dangerous characters
        self.assertFalse(VALID_TASK_NAME.match("../escape"))
        self.assertFalse(VALID_TASK_NAME.match("foo/bar"))
        self.assertFalse(VALID_TASK_NAME.match("foo;rm -rf"))
        self.assertFalse(VALID_TASK_NAME.match(""))

    def test_invalid_task_name_returns_exit_code_2(self):
        code = create_worktree(ROOT, "../unsafe-path")
        self.assertEqual(code, 2)

    def test_list_worktrees_empty_returns_0(self):
        code = list_worktrees(ROOT, as_json=True)
        self.assertEqual(code, 0)

    def test_cli_missing_action_returns_2(self):
        code = main([])
        self.assertEqual(code, 2)


if __name__ == "__main__":
    unittest.main()
