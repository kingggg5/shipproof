import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "skills" / "audit-production-readiness" / "scripts"))

from worktree_manager import (  # noqa: E402
    VALID_TASK_NAME,
    check_worktree,
    create_worktree,
    get_repo_root,
    list_worktrees,
    main,
    merge_worktree,
    remove_worktree,
)


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
        self.assertEqual(check_worktree(ROOT, "../unsafe-path"), 2)
        self.assertEqual(merge_worktree(ROOT, "../unsafe-path"), 2)
        self.assertEqual(remove_worktree(ROOT, "../unsafe-path"), 2)

    def test_list_worktrees_empty_returns_0(self):
        code = list_worktrees(ROOT, as_json=True)
        self.assertEqual(code, 0)
        code_text = list_worktrees(ROOT, as_json=False)
        self.assertEqual(code_text, 0)

    def test_list_worktrees_with_mock_entry(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            work_task = root / ".work" / "mock-task"
            work_task.mkdir(parents=True)
            (work_task / ".git").write_text("gitdir: /fake/path\n", encoding="utf-8")
            self.assertEqual(list_worktrees(root, as_json=True), 0)
            self.assertEqual(list_worktrees(root, as_json=False), 0)

    def test_check_and_merge_missing_worktree(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            self.assertEqual(check_worktree(root, "non-existent"), 2)
            self.assertEqual(merge_worktree(root, "non-existent"), 2)

    def test_get_repo_root_returns_path(self):
        root = get_repo_root()
        self.assertTrue(root.exists())

    def test_cli_missing_action_returns_2(self):
        code = main([])
        self.assertEqual(code, 2)

    def test_cli_dispatch_actions(self):
        self.assertEqual(main(["list", "--json"]), 0)
        self.assertEqual(main(["check", "../invalid"]), 2)
        self.assertEqual(main(["merge", "../invalid"]), 2)
        self.assertEqual(main(["remove", "../invalid"]), 2)

    def test_create_and_remove_in_real_temp_repo(self):
        import shutil
        import subprocess

        git_bin = shutil.which("git")
        if not git_bin:
            return

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            subprocess.run([git_bin, "init", str(root)], check=True, capture_output=True)
            subprocess.run(
                [git_bin, "config", "user.email", "test@example.com"],
                cwd=str(root),
                check=True,
                capture_output=True,
            )
            subprocess.run(
                [git_bin, "config", "user.name", "Test User"],
                cwd=str(root),
                check=True,
                capture_output=True,
            )
            (root / "README.md").write_text("# Test\n", encoding="utf-8")
            subprocess.run([git_bin, "add", "."], cwd=str(root), check=True, capture_output=True)
            subprocess.run(
                [git_bin, "commit", "-m", "init"],
                cwd=str(root),
                check=True,
                capture_output=True,
            )

            # Test create worktree
            self.assertEqual(create_worktree(root, "test-task"), 0)
            # Re-creating should return 2
            self.assertEqual(create_worktree(root, "test-task"), 2)
            # List worktrees
            self.assertEqual(list_worktrees(root, as_json=False), 0)
            # Remove worktree
            self.assertEqual(remove_worktree(root, "test-task", force=True), 0)


if __name__ == "__main__":
    unittest.main()
