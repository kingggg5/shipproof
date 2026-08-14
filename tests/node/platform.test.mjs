import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { buildPythonInvocation, resolveRepositoryPath } from "../../lib/mcp-server.mjs";
import { discoverEvidenceAdapters, runEvidenceAdapter } from "../../lib/evidence.mjs";
import { buildScannerArguments, validateActionInputs } from "../../scripts/run-action.mjs";

test("composite action validates values and repository path boundaries", () => {
  const root = mkdtempSync(join(tmpdir(), "shipproof-action-"));
  try {
    mkdirSync(join(root, "src"));
    mkdirSync(join(root, "reports"));
    const inputs = validateActionInputs({
      GITHUB_WORKSPACE: root,
      SHIPPROOF_INPUT_PATH: "src",
      SHIPPROOF_INPUT_OUTPUT: "reports/shipproof.sarif",
      SHIPPROOF_INPUT_FORMAT: "sarif",
      SHIPPROOF_INPUT_FAIL_ON: "high",
      SHIPPROOF_INPUT_MAX_FILE_BYTES: "1000000",
    });
    assert.equal(inputs.format, "sarif");
    assert.ok(buildScannerArguments(inputs).includes("--max-file-bytes"));
    assert.throws(() => validateActionInputs({
      GITHUB_WORKSPACE: root,
      SHIPPROOF_INPUT_PATH: "..",
    }), /escapes/);
    assert.throws(() => validateActionInputs({
      GITHUB_WORKSPACE: root,
      SHIPPROOF_INPUT_OUTPUT: "report.sarif\nforged=value",
    }), /invalid characters/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("MCP repository paths reject traversal and symlink-independent outside paths", () => {
  const root = mkdtempSync(join(tmpdir(), "shipproof-mcp-"));
  try {
    writeFileSync(join(root, "budget.json"), "{}", "utf8");
    assert.equal(
      resolveRepositoryPath(root, "budget.json", "file"),
      realpathSync.native(join(root, "budget.json")),
    );
    assert.throws(() => resolveRepositoryPath(root, "..", "directory"), /escapes/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("MCP command construction is allowlisted", () => {
  assert.match(buildPythonInvocation("scan", [".", "--format", "json"])[0], /scan_repo\.py$/);
  assert.throws(() => buildPythonInvocation("shell", ["whoami"]), /unsupported/);
});

test("evidence adapters are marker-driven and fixed", () => {
  const root = mkdtempSync(join(tmpdir(), "shipproof-evidence-"));
  try {
    mkdirSync(join(root, "node_modules", "typescript", "bin"), { recursive: true });
    writeFileSync(join(root, "tsconfig.json"), "{}", "utf8");
    writeFileSync(join(root, "node_modules", "typescript", "bin", "tsc"), "", "utf8");
    writeFileSync(join(root, "Cargo.toml"), "[package]\nname='safe'\nversion='0.1.0'\n", "utf8");
    const adapters = discoverEvidenceAdapters(root);
    assert.equal(adapters.find((adapter) => adapter.name === "typescript").available, true);
    assert.throws(() => runEvidenceAdapter(root, "rust"), /allow-project-code/);
    assert.throws(() => runEvidenceAdapter(root, "shell"), /unsupported/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
