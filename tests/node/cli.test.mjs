import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { installSkills, internals, run } from "../../lib/cli.mjs";

test("package exposes two complete skills", () => {
  assert.deepEqual(internals.skillNames(), ["audit-production-readiness", "engineer-production-systems"]);
});

test("project install is explicit and non-destructive by default", () => {
  const root = mkdtempSync(join(tmpdir(), "shipproof-"));
  try {
    const first = installSkills({ target: "codex", scope: "project", projectRoot: root });
    const second = installSkills({ target: "codex", scope: "project", projectRoot: root });
    assert.ok(first.every((item) => item.status === "installed"));
    assert.ok(second.every((item) => item.status === "skipped"));
    assert.match(readFileSync(join(first[0].path, "SKILL.md"), "utf8"), /^---\nname:/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("force replaces only the named skill directories", () => {
  const root = mkdtempSync(join(tmpdir(), "shipproof-"));
  try {
    installSkills({ target: "claude", scope: "project", projectRoot: root });
    const replaced = installSkills({ target: "claude", scope: "project", projectRoot: root, force: true });
    assert.ok(replaced.every((item) => item.status === "installed"));
    assert.ok(replaced.every((item) => item.path.startsWith(join(root, ".claude", "skills"))));
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("prompt catalog is allowlisted", async () => {
  assert.equal(await run(["prompt", "missing"]), 2);
  assert.ok(internals.PROMPTS.has("database"));
  assert.ok(internals.PROMPTS.has("ai-agent"));
});

test("unknown commands fail closed", async () => {
  assert.equal(await run(["definitely-not-a-command"]), 2);
});

test("management commands reject unknown options and ignored paths", async () => {
  assert.equal(await run(["doctor", ".", "--surprise"]), 2);
  assert.equal(await run(["install", "ignored-path"]), 2);
});
