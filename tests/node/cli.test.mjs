import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { installSkills, internals, runCli } from "../../lib/cli.mjs";

function createGitRepository() {
  const root = mkdtempSync(join(tmpdir(), "shipproof-hook-"));
  mkdirSync(join(root, ".git"), { recursive: true });
  return root;
}

test("package exposes two complete skills", () => {
  assert.deepEqual(internals.listSkillNames(), ["audit-production-readiness", "engineer-production-systems"]);
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

test("prompt catalog is allowlisted", () => {
  assert.equal(runCli(["prompt", "missing"]), 2);
  assert.equal(runCli(["prompt", "database", "ignored"]), 2);
  assert.ok(internals.PROMPT_FILES.has("database"));
  assert.ok(internals.PROMPT_FILES.has("ai-agent"));
  assert.ok(internals.PROMPT_FILES.has("loop"));
});

test("unknown commands fail closed", () => {
  assert.equal(runCli(["definitely-not-a-command"]), 2);
});

test("management commands reject unknown options and ignored paths", () => {
  assert.equal(runCli(["doctor", ".", "--surprise"]), 2);
  assert.equal(runCli(["install", "ignored-path"]), 2);
});

test("Python runtime policy requires version 3.10 or newer", () => {
  assert.equal(internals.isSupportedPythonVersion("Python 3.9.19"), false);
  assert.equal(internals.isSupportedPythonVersion("Python 3.10.0"), true);
  assert.equal(internals.isSupportedPythonVersion("Python 4.0.0"), true);
  assert.equal(internals.isSupportedPythonVersion("not Python"), false);
});

test("hook install writes a managed pre-commit hook and is idempotent", () => {
  const root = createGitRepository();
  try {
    assert.equal(internals.runHookCommand(["install"], { repositoryRoot: root }), 0);
    const hookPath = join(root, ".git", "hooks", "pre-commit");
    const hookContent = readFileSync(hookPath, "utf8");
    assert.match(hookContent, /shipproof-managed-pre-commit-hook/);
    assert.match(hookContent, /shipproof check \./);
    assert.equal(internals.runHookCommand(["install"], { repositoryRoot: root }), 0);
    assert.match(readFileSync(hookPath, "utf8"), /shipproof-managed-pre-commit-hook/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("hook install refuses to overwrite a foreign pre-commit hook", () => {
  const root = createGitRepository();
  try {
    const hookPath = join(root, ".git", "hooks", "pre-commit");
    mkdirSync(join(root, ".git", "hooks"), { recursive: true });
    writeFileSync(hookPath, "#!/bin/sh\nnpm test\n", "utf8");
    assert.throws(() => internals.runHookCommand(["install"], { repositoryRoot: root }), /not installed by shipproof/);
    assert.equal(readFileSync(hookPath, "utf8"), "#!/bin/sh\nnpm test\n");
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("hook remove deletes only shipproof-managed hooks", () => {
  const root = createGitRepository();
  try {
    internals.runHookCommand(["install"], { repositoryRoot: root });
    const hookPath = join(root, ".git", "hooks", "pre-commit");
    assert.equal(internals.runHookCommand(["remove"], { repositoryRoot: root }), 0);
    assert.equal(existsSync(hookPath), false);
    writeFileSync(hookPath, "#!/bin/sh\nnpm test\n", "utf8");
    assert.equal(internals.runHookCommand(["remove"], { repositoryRoot: root }), 0);
    assert.equal(readFileSync(hookPath, "utf8"), "#!/bin/sh\nnpm test\n");
    assert.equal(internals.runHookCommand(["remove"], { repositoryRoot: root }), 0);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("hook command rejects invalid actions and non-repositories", () => {
  assert.equal(runCli(["hook", "explode"]), 2);
  const root = mkdtempSync(join(tmpdir(), "shipproof-nogit-"));
  try {
    assert.throws(() => internals.runHookCommand(["install"], { repositoryRoot: root }), /not a git repository/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("in-process dispatch covers help, prompt, doctor, and the Python bridge", () => {
  assert.equal(runCli(["help"]), 0);
  assert.equal(runCli(["--version"]), 0);
  assert.equal(runCli(["prompt", "list"]), 0);
  const root = mkdtempSync(join(tmpdir(), "shipproof-dispatch-"));
  try {
    assert.ok([0, 1].includes(runCli(["doctor", root, "--json"])));
    assert.equal(runCli(["explain", "SP402"]), 0);
    assert.equal(runCli(["scan", root, "--fail-on", "none"]), 0);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("policy check passes on the repository's own reviewed policy", () => {
  assert.equal(runCli(["check", internals.PACKAGE_ROOT]), 0);
});

test("bare shipproof invocation scans the current directory", () => {
  assert.equal(runCli([]), 0);
});
