from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT))

from install import SKILL_NAMES, skill_root  # noqa: E402


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
        self.assertEqual(claude["name"], "shipproof")
        self.assertEqual(claude["version"], codex["version"])
        self.assertEqual(claude["skills"], "./skills/")

    def test_skill_frontmatter_has_no_placeholders(self):
        for name in SKILL_NAMES:
            content = (ROOT / "skills" / name / "SKILL.md").read_text(encoding="utf-8")
            self.assertTrue(content.startswith(f"---\nname: {name}\n"))
            self.assertNotIn("TODO", content)
            self.assertEqual(content.count("\n---\n"), 1)

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


if __name__ == "__main__":
    unittest.main()
