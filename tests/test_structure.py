import json
import re
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "skills" / "audit-production-readiness" / "scripts"))

from install import SKILL_NAMES, install, skill_root  # noqa: E402
from scan_repo import VERSION as SCAN_VERSION  # noqa: E402


class StructureTests(unittest.TestCase):
    def test_plugin_manifest_points_to_skill(self):
        manifest = json.loads((ROOT / ".codex-plugin" / "plugin.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["name"], "shipproof")
        self.assertEqual(manifest["skills"], "./skills/")
        self.assertEqual(manifest["license"], "MIT")
        for name in SKILL_NAMES:
            self.assertTrue((ROOT / manifest["skills"] / name / "SKILL.md").is_file())

    def test_claude_manifest_uses_same_skills(self):
        codex = json.loads((ROOT / ".codex-plugin" / "plugin.json").read_text(encoding="utf-8"))
        claude = json.loads((ROOT / ".claude-plugin" / "plugin.json").read_text(encoding="utf-8"))
        package = json.loads((ROOT / "package.json").read_text(encoding="utf-8"))
        self.assertEqual(claude["name"], "shipproof")
        self.assertEqual(claude["version"], codex["version"])
        self.assertEqual(package["version"], codex["version"])
        self.assertEqual(claude["skills"], "./skills/")

    def test_scanner_version_matches_manifests(self):
        codex = json.loads((ROOT / ".codex-plugin" / "plugin.json").read_text(encoding="utf-8"))
        self.assertEqual(SCAN_VERSION, codex["version"])

    def test_npm_package_is_dependency_free_and_has_no_install_hook(self):
        package = json.loads((ROOT / "package.json").read_text(encoding="utf-8"))
        self.assertEqual(package["bin"], {"shipproof": "bin/shipproof.mjs"})
        self.assertNotIn("dependencies", package)
        for risky_hook in ("preinstall", "install", "postinstall", "prepare"):
            self.assertNotIn(risky_hook, package["scripts"])

    def test_skill_frontmatter_has_no_placeholders(self):
        for name in SKILL_NAMES:
            content = (ROOT / "skills" / name / "SKILL.md").read_text(encoding="utf-8")
            self.assertTrue(content.startswith(f"---\nname: {name}\n"))
            self.assertNotIn("TODO", content)
            self.assertEqual(content.count("\n---\n"), 1)
            self.assertLess(len(content.splitlines()), 500)
            for target in re.findall(r"\]\(([^)]+\.md)\)", content):
                if "://" not in target:
                    self.assertTrue((ROOT / "skills" / name / target).resolve().is_file(), target)

    def test_openai_metadata_invokes_skill(self):
        for name in SKILL_NAMES:
            content = (ROOT / "skills" / name / "agents" / "openai.yaml").read_text(encoding="utf-8")
            self.assertIn(f"${name}", content)

    def test_installer_routes_to_each_host(self):
        base = ROOT / "test-home"
        self.assertEqual(skill_root("codex", codex_home=base), base.resolve() / "skills")
        self.assertEqual(skill_root("claude", claude_home=base), base.resolve() / "skills")
        with self.assertRaises(ValueError):
            skill_root("unknown")

    def test_installer_routes_copy_operations(self):
        temp_path = ROOT / "test-install-root"
        codex_home = temp_path / "codex_home"
        claude_home = temp_path / "claude_home"
        with patch("install.Path.mkdir") as mkdir, patch("install.shutil.copytree") as copytree:
            results = install(target="both", codex_home=codex_home, claude_home=claude_home)
            self.assertEqual(len(results), 4)
            self.assertEqual(mkdir.call_count, 2)
            self.assertEqual(copytree.call_count, 4)
            self.assertTrue(all(call.kwargs == {"dirs_exist_ok": True} for call in copytree.call_args_list))

        single_codex = temp_path / "single_codex"
        with patch("install.Path.mkdir"), patch("install.shutil.copytree"):
            codex_results = install(target="codex", codex_home=single_codex)
        self.assertEqual(len(codex_results), 2)
        self.assertEqual([result[0] for result in codex_results], ["codex", "codex"])


if __name__ == "__main__":
    unittest.main()
