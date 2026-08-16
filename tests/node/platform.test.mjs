import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { buildPythonInvocation, internals as mcpInternals, resolveRepositoryPath } from "../../lib/mcp-server.mjs";
import { discoverEvidenceAdapters, internals as evidenceInternals, runEvidenceAdapter } from "../../lib/evidence.mjs";
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
      SHIPPROOF_INPUT_CHANGED_SINCE: "origin/main",
    });
    assert.equal(inputs.format, "sarif");
    assert.equal(inputs.changedSince, "origin/main");
    assert.ok(buildScannerArguments(inputs).includes("--changed-since"));
    assert.throws(() => validateActionInputs({
      GITHUB_WORKSPACE: root,
      SHIPPROOF_INPUT_PATH: "src",
      SHIPPROOF_INPUT_CHANGED_SINCE: "--upload-pack=malicious",
    }), /plain git ref/);
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
  assert.throws(() => buildPythonInvocation("scan", [42]), /must be strings/);
});

test("MCP python bridge returns evidence envelopes and rejects cancelled calls", async () => {
  const report = await mcpInternals.runPythonJson("capacity", ["--users", "100", "--format", "json"]);
  assert.equal(report.schema_version, "1.0");
  assert.equal(report.tool.name, "ShipProof");
  assert.ok(Array.isArray(report.limitations));
  const controller = new AbortController();
  controller.abort();
  await assert.rejects(
    mcpInternals.runPythonJson("capacity", ["--users", "100", "--format", "json"], controller.signal),
    /cancelled/,
  );
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
    assert.throws(() => runEvidenceAdapter(root, "go"), /did not find go\.mod/);
    assert.deepEqual(evidenceInternals.ADAPTERS.go.environment, { GOPROXY: "off", GOTOOLCHAIN: "local" });
    assert.deepEqual(evidenceInternals.ADAPTERS.go.build(".").argumentsList, ["vet", "./..."]);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("evidence adapters report nothing detected without markers", () => {
  const root = mkdtempSync(join(tmpdir(), "shipproof-empty-"));
  try {
    const adapters = discoverEvidenceAdapters(root);
    assert.equal(adapters.length, 3);
    assert.ok(adapters.every((adapter) => adapter.detected === false));
    assert.ok(adapters.every((adapter) => adapter.available === false));
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("formatActionSummary formats markdown, json, and sarif reports", async () => {
  const { formatActionSummary } = await import("../../scripts/run-action.mjs");
  const root = mkdtempSync(join(tmpdir(), "shipproof-summary-"));
  try {
    const mdPath = join(root, "report.md");
    writeFileSync(mdPath, "# Report Markdown Content", "utf8");
    assert.equal(formatActionSummary(mdPath, "markdown"), "# Report Markdown Content");

    const jsonPath = join(root, "report.json");
    writeFileSync(jsonPath, JSON.stringify({
      verdict: "PASS_WITH_EVIDENCE",
      summary: { files_scanned: 10 },
      findings: [
        { severity: "high", rule_id: "SP108", path: "app.py", line: 12, title: "Auth Missing" },
        { severity: "medium", rule_id: "SP305", path: "app.py", line: 20, title: "Page Size" },
        { severity: "low", rule_id: "SP406", path: "app.py", line: 30, title: "Error" },
      ],
    }), "utf8");
    const jsonSummary = formatActionSummary(jsonPath, "json");
    assert.match(jsonSummary, /PASS_WITH_EVIDENCE/);
    assert.match(jsonSummary, /SP108/);

    const sarifPath = join(root, "report.sarif");
    writeFileSync(sarifPath, JSON.stringify({
      runs: [{
        results: [
          {
            ruleId: "SP101",
            level: "error",
            message: { text: "eval used" },
            locations: [{ physicalLocation: { artifactLocation: { uri: "app.py" }, region: { startLine: 5 } } }],
          },
          {
            ruleId: "SP305",
            level: "warning",
            message: { text: "unbounded" },
            locations: [{ physicalLocation: { artifactLocation: { uri: "app.py" }, region: { startLine: 15 } } }],
          },
        ],
      }],
    }), "utf8");
    const sarifSummary = formatActionSummary(sarifPath, "sarif");
    assert.match(sarifSummary, /SP101/);
    assert.match(sarifSummary, /BLOCKED/);

    assert.equal(formatActionSummary(join(root, "nonexistent.json"), "json"), "");
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
