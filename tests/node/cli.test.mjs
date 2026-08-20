import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { installSkills, internals, runCli } from "../../lib/cli.mjs";

function createGitRepository() {
  const root = mkdtempSync(join(tmpdir(), "shipproof-hook-"));
  const result = spawnSync("git", ["-C", root, "init", "-q"], { windowsHide: true });
  assert.equal(result.status, 0);
  return root;
}

function runGit(root, ...argumentsList) {
  const result = spawnSync("git", ["-C", root, ...argumentsList], {
    encoding: "utf8",
    windowsHide: true,
  });
  assert.equal(result.status, 0, result.stderr);
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

test("legacy prompt catalog remains allowlisted during migration", () => {
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
  assert.equal(runCli(["init", "ignored-path", "--scope", "global"]), 2);
  assert.equal(runCli(["labs", "missing"]), 2);
  assert.equal(runCli(["gate", "missing"]), 2);
  assert.equal(runCli(["config", "missing"]), 2);
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

test("hook helper follows core.hooksPath and ignores marker text inside foreign hooks", () => {
  const root = createGitRepository();
  try {
    runGit(root, "config", "core.hooksPath", ".githooks");
    const hooksDirectory = join(root, ".githooks");
    assert.equal(internals.resolveGitHooksDirectory(root), hooksDirectory);
    assert.equal(internals.runHookCommand(["install"], { repositoryRoot: root }), 0);
    const hookPath = join(hooksDirectory, "pre-commit");
    assert.equal(internals.isShipProofManagedHook(readFileSync(hookPath, "utf8")), true);
    assert.equal(internals.runHookCommand(["remove"], { repositoryRoot: root }), 0);
    assert.equal(existsSync(hookPath), false);

    writeFileSync(hookPath, "#!/bin/sh\necho safe\n# shipproof-managed-pre-commit-hook\n");
    assert.equal(internals.isShipProofManagedHook(readFileSync(hookPath, "utf8")), false);
    assert.throws(
      () => internals.runHookCommand(["install"], { repositoryRoot: root }),
      /was not installed by shipproof/,
    );
    assert.equal(internals.runHookCommand(["remove"], { repositoryRoot: root }), 0);
    assert.equal(existsSync(hookPath), true);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("hook helper installs from a linked Git worktree", () => {
  const parent = mkdtempSync(join(tmpdir(), "shipproof-worktree-hook-"));
  const mainRoot = join(parent, "main");
  const linkedRoot = join(parent, "linked");
  try {
    mkdirSync(mainRoot);
    runGit(mainRoot, "init", "-q");
    runGit(mainRoot, "config", "user.email", "shipproof@example.test");
    runGit(mainRoot, "config", "user.name", "ShipProof Test");
    writeFileSync(join(mainRoot, "README.md"), "fixture\n");
    runGit(mainRoot, "add", "README.md");
    runGit(mainRoot, "commit", "-q", "-m", "fixture");
    runGit(mainRoot, "worktree", "add", "-q", "-b", "hook-test", linkedRoot);

    const hooksDirectory = internals.resolveGitHooksDirectory(linkedRoot);
    assert.equal(hooksDirectory, join(realpathSync.native(mainRoot), ".git", "hooks"));
    assert.equal(internals.runHookCommand(["install"], { repositoryRoot: linkedRoot }), 0);
    assert.equal(existsSync(join(hooksDirectory, "pre-commit")), true);
  } finally {
    rmSync(parent, { recursive: true, force: true });
  }
});

test("hook command rejects invalid actions and non-repositories", () => {
  assert.equal(runCli(["hook", "explode"]), 2);
  const root = mkdtempSync(join(tmpdir(), "shipproof-nogit-"));
  try {
    assert.throws(() => internals.runHookCommand(["install"], { repositoryRoot: root }), /not a git/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("in-process dispatch covers stable, grouped, retired, and legacy commands", () => {
  assert.equal(runCli(["help"]), 0);
  assert.equal(runCli(["--version"]), 0);
  assert.equal(runCli(["prompt", "list"]), 0);
  assert.equal(runCli(["badge"]), 2);
  assert.equal(runCli(["badge", "--format", "json"]), 2);
  const root = mkdtempSync(join(tmpdir(), "shipproof-dispatch-"));
  try {
    assert.ok([0, 1].includes(runCli(["doctor", root, "--json"])));
    assert.equal(runCli(["explain", "SP402"]), 0);
    assert.equal(runCli(["explain", "SP402", "--context-level", "summary", "--format", "json"]), 0);
    assert.equal(runCli(["explain", "SP402", "extra"]), 2);
    assert.equal(runCli(["explain", "SP402", "--context-level", "invalid"]), 2);
    assert.equal(runCli(["scan", root, "--fail-on", "none"]), 0);
    assert.equal(runCli(["labs", "cost", "--context-tokens", "1000", "--budget-usd", "10.0"]), 0);
    assert.equal(runCli(["cost", "--context-tokens", "1000", "--budget-usd", "10.0"]), 0);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("cost command supports latest 2026 AI models and budget gates", () => {
  const prefix = ["labs", "cost"];
  assert.equal(runCli([...prefix, "--context-tokens", "5000", "--model", "claude-sonnet-5", "--budget-usd", "1.0"]), 0);
  assert.equal(runCli([...prefix, "--context-tokens", "5000", "--model", "claude-3-7-sonnet", "--budget-usd", "1.0"]), 0);
  assert.equal(runCli([...prefix, "--context-tokens", "5000", "--model", "gpt-4.5", "--format", "json"]), 0);
  assert.equal(runCli([...prefix, "--context-tokens", "5000", "--model", "o4-mini", "--iterations", "2"]), 0);
  assert.equal(runCli([...prefix, "--context-tokens", "5000", "--model", "gemini-3-7-flash"]), 0);
  assert.equal(runCli([...prefix, "--context-tokens", "5000", "--model", "deepseek-v4-pro", "--budget-usd", "0.5"]), 0);
  assert.equal(runCli([...prefix, "--context-tokens", "5000", "--model", "deepseek-r1", "--budget-usd", "0.5"]), 0);
  assert.equal(runCli([...prefix, "--context-tokens", "5000", "--model", "gemini-2-0-flash"]), 0);
  assert.equal(runCli([...prefix, "--context-tokens", "500000", "--model", "gpt-4.5", "--budget-usd", "0.0001"]), 1);
});

test("policy check passes on the repository's own reviewed policy", () => {
  assert.equal(runCli(["check", internals.PACKAGE_ROOT]), 0);
});

test("bare shipproof invocation scans the current directory", () => {
  assert.equal(runCli([]), 0);
});
