import json
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "skills" / "audit-production-readiness" / "scripts"))

from capacity_model import VERSION as CAPACITY_VERSION  # noqa: E402
from scan_repo import RULES  # noqa: E402
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

    def test_public_runtime_and_capability_claims_match_implementation(self):
        ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        agents = (ROOT / "AGENTS.md").read_text(encoding="utf-8")
        llms = (ROOT / "llms.txt").read_text(encoding="utf-8")
        commands = (ROOT / "docs" / "commands.md").read_text(encoding="utf-8")
        mcp_source = (ROOT / "lib" / "mcp-server.mjs").read_text(encoding="utf-8")

        self.assertIn('python-version: ["3.10", "3.11", "3.12", "3.13", "3.14"]', ci)
        self.assertIn('node-version: ["20", "22", "24"]', ci)
        for document in (readme, agents):
            self.assertRegex(document, r"Node(?:\.js)? 20/22/24")
            self.assertRegex(document, r"Python 3\.10/3\.11/3\.12/3\.13/3\.14")

        count_match = re.search(r"- (\d+) deterministic rules", llms)
        self.assertIsNotNone(count_match)
        self.assertEqual(int(count_match.group(1)), len(RULES))
        self.assertIn("L2 interprocedural taint flows", llms)
        self.assertIn("--cross-file", llms)

        registered_tools = set(re.findall(r'server\.registerTool\(\s*"([^"]+)"', mcp_source))
        self.assertEqual(
            registered_tools,
            {
                "shipproof_scan",
                "shipproof_budget",
                "shipproof_capacity",
                "shipproof_explain",
                "shipproof_lint_snippet",
            },
        )
        self.assertIn("The server registers five tools", commands)
        for tool_name in registered_tools:
            self.assertIn(f"`{tool_name}`", commands)

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
        markdown_files = [
            ROOT / "README.md",
            ROOT / "README.th.md",
            *sorted((ROOT / "docs").glob("*.md")),
        ]
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

    def test_readme_rule_tables_match_scanner_rules(self):
        code_severities = {rule.rule_id: rule.severity.upper() for rule in RULES}
        english_row = re.compile(
            r"^\|\s*\*\*`(SP\d+)`\*\*\s*\|\s*(CRITICAL|HIGH|MEDIUM|LOW)\s*\|",
            re.MULTILINE,
        )
        sources = (("docs/rules.md", english_row),)
        for readme_name, row_pattern in sources:
            content = (ROOT / readme_name).read_text(encoding="utf-8")
            documented = {match.group(1): match.group(2) for match in row_pattern.finditer(content)}
            self.assertEqual(
                sorted(documented),
                sorted(code_severities),
                f"{readme_name} rule table must list exactly the scanner rules",
            )
            for rule_id, code_severity in code_severities.items():
                self.assertEqual(
                    documented[rule_id],
                    code_severity,
                    f"{readme_name} severity drift for {rule_id}",
                )

    def test_framework_table_rules_exist_in_scanner(self):
        scanner_rule_ids = {rule.rule_id for rule in RULES}
        for doc_name in ("docs/rules.md",):
            content = (ROOT / doc_name).read_text(encoding="utf-8")
            supported_headings = (
                "## Ecosystem-aware detection",
                "## Framework-Aware Detection",
                "## การตรวจจับตาม ecosystem",
                "## การตรวจจับที่ปรับตาม Framework อัตโนมัติ",
            )
            heading = next(
                (candidate for candidate in supported_headings if candidate in content),
                None,
            )
            self.assertIsNotNone(heading, f"Missing ecosystem table heading in {doc_name}")
            framework_section = content.split(heading, 1)[1]
            framework_table = framework_section.split("## ", 1)[0]
            mentioned_rules = set(re.findall(r"\b(SP\d{3})\b", framework_table))
            self.assertTrue(
                mentioned_rules.issubset(scanner_rule_ids),
                f"Rules in {doc_name} framework table not in scanner: {mentioned_rules - scanner_rule_ids}",
            )

    def test_catalog_shipped_claims_exist_in_scanner(self):
        """Dogfood the evidence-first contract: every rule the failure catalog
        marks SHIPPED must exist in the scanner (reserved IDs never count)."""
        catalog_path = ROOT / "docs" / "knowledge" / "failure-catalog.md"
        if not catalog_path.is_file():
            self.skipTest("failure catalog not present")
        scanner_rule_ids = {rule.rule_id for rule in RULES}
        reserved_ids = {"SP111", "SP308", "SP309", "SP310", "SP311", "SP312"}
        content = catalog_path.read_text(encoding="utf-8")
        shipped_claims = set()
        for claim in re.findall(r"SHIPPED\s+((?:SP\d{3})(?:\s*/\s*SP\d{3})*)", content):
            shipped_claims.update(re.findall(r"SP\d{3}", claim))
        self.assertTrue(
            shipped_claims,
            "failure catalog no longer marks any rule as SHIPPED; drop this test",
        )
        ghost_claims = shipped_claims - scanner_rule_ids - reserved_ids
        self.assertEqual(
            ghost_claims,
            set(),
            f"Catalog claims these rules are shipped but they do not exist: {sorted(ghost_claims)}",
        )


if __name__ == "__main__":
    unittest.main()
