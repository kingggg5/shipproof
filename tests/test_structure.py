from __future__ import annotations

import json
import unittest
from pathlib import Path

ROOT = Path(__file__).parents[1]


class StructureTests(unittest.TestCase):
    def test_plugin_manifest_points_to_skill(self):
        manifest = json.loads((ROOT / ".codex-plugin" / "plugin.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["name"], "shipproof")
        self.assertEqual(manifest["skills"], "./skills/")
        self.assertEqual(manifest["license"], "MIT")
        self.assertTrue((ROOT / manifest["skills"] / "audit-production-readiness" / "SKILL.md").is_file())

    def test_skill_frontmatter_has_no_placeholders(self):
        content = (ROOT / "skills" / "audit-production-readiness" / "SKILL.md").read_text(encoding="utf-8")
        self.assertTrue(content.startswith("---\nname: audit-production-readiness\n"))
        self.assertNotIn("TODO", content)
        self.assertEqual(content.count("\n---\n"), 1)

    def test_openai_metadata_invokes_skill(self):
        content = (ROOT / "skills" / "audit-production-readiness" / "agents" / "openai.yaml").read_text(encoding="utf-8")
        self.assertIn("$audit-production-readiness", content)


if __name__ == "__main__":
    unittest.main()
