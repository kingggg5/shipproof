import json
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "skills" / "audit-production-readiness" / "scripts"))

from capacity_model import VERSION as CAPACITY_VERSION  # noqa: E402
from scan_repo import VERSION as SCAN_VERSION  # noqa: E402

sys.path.insert(0, str(ROOT / "skills" / "engineer-production-systems" / "scripts"))
from check_budget import VERSION as BUDGET_VERSION  # noqa: E402

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
        self.assertEqual(CAPACITY_VERSION, codex["version"])
        self.assertEqual(BUDGET_VERSION, codex["version"])

    def test_npm_package_keeps_core_dependency_free_and_has_no_install_hook(self):
        package = json.loads((ROOT / "package.json").read_text(encoding="utf-8"))
        self.assertEqual(package["bin"], {"shipproof": "bin/shipproof.mjs"})
        self.assertIn("docs", package["files"])
        self.assertNotIn("dependencies", package)
        self.assertEqual(
            set(package["peerDependencies"]),
            {"@modelcontextprotocol/sdk", "zod"},
        )
        self.assertTrue(
            all(value["optional"] for value in package["peerDependenciesMeta"].values())
        )
        for risky_hook in ("preinstall", "install", "postinstall", "prepare"):
            self.assertNotIn(risky_hook, package["scripts"])

    def test_machine_contracts_and_distribution_entrypoints_exist(self):
        for path in (
            ROOT / "action.yml",
            ROOT / ".pre-commit-hooks.yaml",
            ROOT / "schemas" / "evidence-envelope.schema.json",
            ROOT / "schemas" / "shipproof-config.schema.json",
            ROOT / "schemas" / "shipproof-policy.schema.json",
            ROOT / ".shipproof.yml",
        ):
            self.assertTrue(path.is_file(), str(path))
        for schema in (ROOT / "schemas").glob("*.json"):
            payload = json.loads(schema.read_text(encoding="utf-8"))
            self.assertEqual(payload["$schema"], "https://json-schema.org/draft/2020-12/schema")

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

    def test_public_markdown_links_resolve_locally(self):
        markdown_files = [ROOT / "README.md", *sorted((ROOT / "docs").glob("*.md"))]
        for markdown_file in markdown_files:
            content = markdown_file.read_text(encoding="utf-8")
            for target in re.findall(r"\]\(([^)]+)\)", content):
                target_path = target.split("#", 1)[0]
                if not target_path or "://" in target_path or target_path.startswith("mailto:"):
                    continue
                resolved = (markdown_file.parent / target_path).resolve()
                self.assertTrue(resolved.exists(), f"{markdown_file}: {target}")

    def test_skill_guidance_keeps_external_sources_in_research_notebook(self):
        for markdown_file in sorted((ROOT / "skills").glob("**/*.md")):
            content = markdown_file.read_text(encoding="utf-8")
            self.assertNotRegex(content, r"https?://", str(markdown_file))


if __name__ == "__main__":
    unittest.main()
