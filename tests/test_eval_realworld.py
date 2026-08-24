from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).parents[1]
SCRIPT = ROOT / "scripts" / "eval-realworld.py"
SPEC = importlib.util.spec_from_file_location("eval_realworld", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load real-world evaluation harness")
eval_realworld = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = eval_realworld
SPEC.loader.exec_module(eval_realworld)


class RealWorldManifestTests(unittest.TestCase):
    def test_git_runner_is_noninteractive_isolated_and_bounded(self):
        completed = eval_realworld.subprocess.CompletedProcess(["git", "version"], 0, "ok", "")
        injected = {
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": "filter.evil.smudge",
            "GIT_CONFIG_VALUE_0": "dangerous-helper",
            "GIT_TEMPLATE_DIR": "unsafe-template",
            "git_config_key_1": "core.hooksPath",
            "git_template_dir": "unsafe-lowercase-template",
        }
        with (
            patch.object(eval_realworld.os, "environ", injected),
            patch.object(eval_realworld.subprocess, "run", return_value=completed) as run,
        ):
            self.assertIs(eval_realworld.run_git("version"), completed)
        environment = run.call_args.kwargs["env"]
        self.assertEqual(environment["GIT_TERMINAL_PROMPT"], "0")
        self.assertEqual(environment["GIT_CONFIG_NOSYSTEM"], "1")
        self.assertEqual(environment["GIT_CONFIG_GLOBAL"], eval_realworld.os.devnull)
        self.assertFalse(
            any(
                key.upper().startswith("GIT_CONFIG_")
                and key.upper()
                not in {"GIT_CONFIG_NOSYSTEM", "GIT_CONFIG_SYSTEM", "GIT_CONFIG_GLOBAL"}
                for key in environment
            )
        )
        self.assertFalse(any(key.lower() == "git_template_dir" for key in environment))
        self.assertEqual(run.call_args.kwargs["timeout"], eval_realworld.GIT_TIMEOUT_SECONDS)

    def test_prepare_uses_a_fresh_empty_git_template(self):
        revision = "a" * 40
        specification = {
            "name": "sample",
            "url": "https://github.com/example/sample.git",
            "revision": revision,
            "license_path": "LICENSE",
        }
        observed_template = None

        def fake_run_git(*arguments, cwd=None):
            nonlocal observed_template
            if arguments[0] == "init":
                template_argument = next(
                    value for value in arguments if value.startswith("--template=")
                )
                observed_template = Path(template_argument.removeprefix("--template="))
                self.assertTrue(observed_template.is_dir())
                self.assertEqual(list(observed_template.iterdir()), [])
                target = Path(arguments[-1])
                target.mkdir(parents=True)
                (target / "LICENSE").write_text("fixture license\n", encoding="utf-8")
            stdout = f"{revision}\n" if "rev-parse" in arguments else ""
            return eval_realworld.subprocess.CompletedProcess(arguments, 0, stdout, "")

        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            with patch.object(eval_realworld, "run_git", side_effect=fake_run_git):
                target = eval_realworld.prepare(specification, workspace)
            self.assertEqual(target.resolve(), (workspace / "sample").resolve())
            self.assertIsNotNone(observed_template)
            self.assertFalse(observed_template.exists())

    def test_git_timeout_becomes_bounded_unavailable_evidence(self):
        with patch.object(
            eval_realworld.subprocess,
            "run",
            side_effect=eval_realworld.subprocess.TimeoutExpired(["git", "fetch"], 180),
        ):
            completed = eval_realworld.run_git("fetch")
        self.assertEqual(completed.returncode, 124)
        self.assertIn("timed out", completed.stderr)

    def test_checked_in_manifest_is_revision_and_license_pinned(self):
        path = ROOT / "benchmarks" / "realworld-repositories.json"
        manifest = eval_realworld.load_manifest(path)
        self.assertEqual(len(manifest["repositories"]), 6)
        self.assertEqual(
            {item["classification"] for item in manifest["repositories"]},
            {"clean_baseline", "intentionally_vulnerable"},
        )

    def test_manifest_rejects_moving_revisions_and_path_escape(self):
        payload = {
            "schema_version": 1,
            "repositories": [
                {
                    "name": "sample",
                    "url": "https://github.com/example/sample.git",
                    "revision": "main",
                    "classification": "clean_baseline",
                    "license_spdx": "MIT",
                    "license_path": "../LICENSE",
                    "license_url": "https://github.com/example/sample/blob/main/LICENSE",
                }
            ],
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "manifest.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "full lowercase commit"):
                eval_realworld.load_manifest(path)

    def test_manifest_rejects_license_permalink_for_another_repository(self):
        revision = "a" * 40
        payload = {
            "schema_version": 1,
            "repositories": [
                {
                    "name": "sample",
                    "url": "https://github.com/example/sample.git",
                    "revision": revision,
                    "classification": "clean_baseline",
                    "license_spdx": "MIT",
                    "license_path": "LICENSE",
                    "license_url": (f"https://github.com/attacker/other/blob/{revision}/LICENSE"),
                }
            ],
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "manifest.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "same repository"):
                eval_realworld.load_manifest(path)

    def test_empty_only_selection_is_invalid_evidence(self):
        original_argv = sys.argv
        sys.argv = [str(SCRIPT), "--only", ","]
        try:
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(eval_realworld.main(), 2)
        finally:
            sys.argv = original_argv

    def test_tree_digest_ignores_git_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "src").mkdir()
            (root / "src" / "app.py").write_text("value = 1\n", encoding="utf-8")
            first = eval_realworld.sha256_tree(root)
            (root / ".git").mkdir()
            (root / ".git" / "HEAD").write_text("moving", encoding="utf-8")
            self.assertEqual(first, eval_realworld.sha256_tree(root))


if __name__ == "__main__":
    unittest.main()
