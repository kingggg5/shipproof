import json
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "skills" / "audit-production-readiness" / "scripts"))

from scan_repo import VERSION as SCAN_VERSION  # noqa: E402

SKILL_NAMES = ("engineer-production-systems", "audit-production-readiness")


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
            content = (ROOT / "skills" / name / "agents" / "openai.yaml").read_text(
                encoding="utf-8"
            )
            self.assertIn(f"${name}", content)


if __name__ == "__main__":
    unittest.main()
