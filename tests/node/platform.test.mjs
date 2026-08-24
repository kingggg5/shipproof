import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  existsSync,
  mkdtempSync,
  mkdirSync,
  readFileSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { buildPythonInvocation, internals as mcpInternals, resolveRepositoryPath } from "../../lib/mcp-server.mjs";
import { discoverEvidenceAdapters, internals as evidenceInternals, runEvidenceAdapter } from "../../lib/evidence.mjs";
import { VERSION } from "../../lib/package-info.mjs";
import { buildScannerArguments, validateActionInputs } from "../../scripts/run-action.mjs";

const evidenceEnvelopeSchema = JSON.parse(
  readFileSync(join(process.cwd(), "schemas", "evidence-envelope.schema.json"), "utf8"),
);
const evidenceReportSchema = JSON.parse(
  readFileSync(join(process.cwd(), "schemas", "evidence-report.schema.json"), "utf8"),
);

function assertEvidenceReportTopLevel(report) {
  const commandShape = evidenceReportSchema.allOf[1];
  const allowed = new Set([
    ...Object.keys(evidenceEnvelopeSchema.properties),
    ...Object.keys(commandShape.properties),
  ]);
  assert.deepEqual(Object.keys(report).sort(), [...allowed].sort());
  assert.equal(report.tool.command, commandShape.properties.tool.properties.command.const);
}

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
  await assert.rejects(
    mcpInternals.runPythonJson("capacity", ["--users", "0", "--format", "json"]),
    (error) => /users must be a positive integer/.test(error.message) && !/could not parse/.test(error.message),
  );

  const snippet = "const value = 1; // safe fixture\n".repeat(1_250);
  const snippetReport = await mcpInternals.runPythonJson(
    "scan",
    [process.cwd(), "--snippet-stdin", "--snippet-file", "snippet.js", "--format", "json"],
    undefined,
    { stdin: snippet },
  );
  assert.equal(snippetReport.summary.files_scanned, 1);
  assert.equal(snippetReport.root, realpathSync.native(process.cwd()));
});

test("evidence adapters are marker-driven and fixed", () => {
  const root = mkdtempSync(join(tmpdir(), "shipproof-evidence-"));
  try {
    mkdirSync(join(root, "node_modules", "typescript", "bin"), { recursive: true });
    writeFileSync(join(root, "tsconfig.json"), "{}", "utf8");
    const probeMarker = join(root, "probe-ran");
    writeFileSync(
      join(root, "node_modules", "typescript", "bin", "tsc"),
      `if (process.argv.includes("--version")) { require("node:fs").writeFileSync(${JSON.stringify(probeMarker)}, "yes"); console.log("Version 5.9.2"); }\n`,
      "utf8",
    );
    writeFileSync(join(root, "Cargo.toml"), "[package]\nname='safe'\nversion='0.1.0'\n", "utf8");
    const adapters = discoverEvidenceAdapters(root);
    const unapprovedTypescript = adapters.find((adapter) => adapter.name === "typescript");
    assert.equal(unapprovedTypescript.available, false);
    assert.equal(unapprovedTypescript.approval_required, true);
    assert.equal(unapprovedTypescript.analyzer_version, null);
    assert.equal(existsSync(probeMarker), false);
    const approvedTypescript = discoverEvidenceAdapters(root, { allowProjectCode: true })
      .find((adapter) => adapter.name === "typescript");
    assert.equal(approvedTypescript.available, true);
    assert.equal(approvedTypescript.approval_required, false);
    assert.equal(approvedTypescript.analyzer_version, "Version 5.9.2");
    assert.equal(existsSync(probeMarker), true);
    assert.equal(adapters.find((adapter) => adapter.name === "typescript").requires_project_code_approval, true);
    assert.throws(() => runEvidenceAdapter(root, "typescript"), /allow-project-code/);
    const evidenceReport = runEvidenceAdapter(root, "typescript", { allowProjectCode: true });
    assert.equal(evidenceReport.verdict, "PASS_WITH_EVIDENCE");
    assert.equal(evidenceReport.analyzer_version, "Version 5.9.2");
    assert.equal(evidenceReport.diagnostics_truncated, false);
    assertEvidenceReportTopLevel(evidenceReport);
    writeFileSync(
      join(root, "node_modules", "typescript", "bin", "tsc"),
      'if (process.argv.includes("--version")) console.log("Version 5.9.2"); else process.exit(1);\n',
      "utf8",
    );
    assert.throws(
      () => runEvidenceAdapter(root, "typescript", { allowProjectCode: true }),
      /without diagnostics/,
    );
    assert.throws(() => runEvidenceAdapter(root, "rust"), /allow-project-code/);
    assert.throws(() => runEvidenceAdapter(root, "shell"), /unsupported/);
    assert.throws(() => runEvidenceAdapter(root, "go"), /did not find go\.mod/);
    assert.deepEqual(evidenceInternals.ADAPTERS.go.environment, { GOPROXY: "off", GOTOOLCHAIN: "local" });
    assert.deepEqual(evidenceInternals.ADAPTERS.go.build(".").versionArguments, ["version"]);
    assert.deepEqual(evidenceInternals.ADAPTERS.go.build(".").argumentsList, ["vet", "./..."]);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("evidence adapters classify findings, timeout, crash, output cap, and unavailable separately", () => {
  const root = mkdtempSync(join(tmpdir(), "shipproof-evidence-states-"));
  const compilerDirectory = join(root, "node_modules", "typescript", "bin");
  const compiler = join(compilerDirectory, "tsc");
  const versionBranch = 'if (process.argv.includes("--version")) { console.log("Version 5.9.2"); } else ';
  try {
    mkdirSync(compilerDirectory, { recursive: true });
    writeFileSync(join(root, "tsconfig.json"), "{}", "utf8");

    const sensitiveName = "api_" + "key";
    const sensitiveValue = "fixture-value-that-must-not-escape";
    writeFileSync(
      compiler,
      `${versionBranch}{ console.error(${JSON.stringify(`src/app.ts:1: error: ${sensitiveName}=${sensitiveValue}`)}); process.exit(1); }`,
      "utf8",
    );
    const blocked = runEvidenceAdapter(root, "typescript", { allowProjectCode: true });
    assert.equal(blocked.verdict, "BLOCK");
    assert.equal(blocked.process_exit_code, 1);
    assert.equal(blocked.severity_counts.error, 1);
    assert.match(blocked.diagnostics[0], /\[REDACTED\]/);
    assert.equal(blocked.diagnostics[0].includes(sensitiveValue), false);

    writeFileSync(compiler, `${versionBranch}{ setTimeout(() => {}, 5_000); }`, "utf8");
    assert.throws(
      () => runEvidenceAdapter(root, "typescript", { allowProjectCode: true, timeoutMs: 50 }),
      /timed out without usable evidence/,
    );

    writeFileSync(compiler, `${versionBranch}{ process.exit(3); }`, "utf8");
    assert.throws(
      () => runEvidenceAdapter(root, "typescript", { allowProjectCode: true }),
      /failed with exit code 3/,
    );

    writeFileSync(
      compiler,
      `${versionBranch}{ process.stdout.write("x".repeat(100_000)); }`,
      "utf8",
    );
    assert.throws(
      () => runEvidenceAdapter(root, "typescript", {
        allowProjectCode: true,
        maxBufferBytes: 1_024,
      }),
      /exceeded the output cap without usable evidence/,
    );

    writeFileSync(compiler, "process.exit(1);", "utf8");
    assert.equal(
      discoverEvidenceAdapters(root, { allowProjectCode: true })
        .find((adapter) => adapter.name === "typescript").available,
      false,
    );
    assert.throws(
      () => runEvidenceAdapter(root, "typescript", { allowProjectCode: true }),
      /not installed or not available offline/,
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("evidence diagnostics enforce line-count and per-line bounds", () => {
  const root = mkdtempSync(join(tmpdir(), "shipproof-evidence-bounds-"));
  const compilerDirectory = join(root, "node_modules", "typescript", "bin");
  const compiler = join(compilerDirectory, "tsc");
  try {
    mkdirSync(compilerDirectory, { recursive: true });
    writeFileSync(join(root, "tsconfig.json"), "{}", "utf8");
    writeFileSync(
      compiler,
      `if (process.argv.includes("--version")) console.log("Version 5.9.2"); else {
        const { writeSync } = require("node:fs");
        const line = "x".repeat(5000) + "\\n";
        for (let index = 0; index < 205; index += 1) writeSync(2, line);
        process.exitCode = 1;
      }`,
      "utf8",
    );
    const report = runEvidenceAdapter(root, "typescript", { allowProjectCode: true });
    assert.equal(report.diagnostics.length, evidenceInternals.bounds.max_diagnostic_lines);
    assert.equal(report.diagnostics_truncated, true);
    assert.ok(report.diagnostics.every((line) => line.length <= 4_110));
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
    assert.match(
      formatActionSummary(mdPath, "markdown", { exitCode: 0, failOn: "high" }),
      /PASSED[\s\S]*Report Markdown Content/,
    );

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
    const jsonSummary = formatActionSummary(jsonPath, "json", { exitCode: 1, failOn: "high" });
    assert.match(jsonSummary, /BLOCKED/);
    assert.match(jsonSummary, /PASS_WITH_EVIDENCE/);
    assert.match(jsonSummary, /SP108/);

    const sarifPath = join(root, "report.sarif");
    writeFileSync(sarifPath, JSON.stringify({
      runs: [{
        results: [
          {
            ruleId: "SP101",
            level: "warning",
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
    const sarifSummary = formatActionSummary(
      sarifPath,
      "sarif",
      { exitCode: 0, failOn: "high" },
    );
    assert.match(sarifSummary, /SP101/);
    assert.match(sarifSummary, /PASSED/);

    assert.equal(formatActionSummary(join(root, "nonexistent.json"), "json"), "");
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("action discards stale reports when the current scan is unavailable", async () => {
  const { main: runActionMain } = await import("../../scripts/run-action.mjs");
  const root = mkdtempSync(join(tmpdir(), "shipproof-action-stale-"));
  try {
    const reportPath = join(root, "report.json");
    const outputPath = join(root, "github-output.txt");
    const summaryPath = join(root, "github-summary.md");
    writeFileSync(reportPath, '{"verdict":"PASS_WITH_EVIDENCE"}', "utf8");
    writeFileSync(outputPath, "", "utf8");
    writeFileSync(summaryPath, "", "utf8");

    const exitCode = runActionMain({
      GITHUB_WORKSPACE: root,
      GITHUB_OUTPUT: outputPath,
      GITHUB_STEP_SUMMARY: summaryPath,
      SHIPPROOF_INPUT_PATH: ".",
      SHIPPROOF_INPUT_OUTPUT: "report.json",
      SHIPPROOF_INPUT_FORMAT: "json",
      SHIPPROOF_INPUT_FAIL_ON: "high",
      SHIPPROOF_INPUT_CHANGED_SINCE: "HEAD",
      SHIPPROOF_INPUT_MAX_FILE_BYTES: "1000000",
    });

    assert.equal(exitCode, 2);
    assert.equal(existsSync(reportPath), false);
    assert.equal(readFileSync(outputPath, "utf8"), "");
    assert.equal(readFileSync(summaryPath, "utf8"), "");
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("release metadata rejects branches and accepts only the exact package tag", () => {
  const root = mkdtempSync(join(tmpdir(), "shipproof-release-info-"));
  try {
    const outputPath = join(root, "github-output.txt");
    writeFileSync(outputPath, "", "utf8");
    const script = join(process.cwd(), "scripts", "release-info.mjs");
    const branch = spawnSync(process.execPath, [script], {
      encoding: "utf8",
      env: {
        ...process.env,
        GITHUB_REF_NAME: "main",
        GITHUB_REF_TYPE: "branch",
        GITHUB_OUTPUT: outputPath,
      },
      shell: false,
      windowsHide: true,
    });
    assert.notEqual(branch.status, 0);
    assert.match(branch.stderr, /exact tag/);
    assert.equal(readFileSync(outputPath, "utf8"), "");

    const tag = spawnSync(process.execPath, [script], {
      encoding: "utf8",
      env: {
        ...process.env,
        GITHUB_REF_NAME: `v${VERSION}`,
        GITHUB_REF_TYPE: "tag",
        GITHUB_OUTPUT: outputPath,
      },
      shell: false,
      windowsHide: true,
    });
    assert.equal(tag.status, 0, tag.stderr);
    assert.ok(readFileSync(outputPath, "utf8").includes(`version=${VERSION}\n`));
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("security and release workflows preserve failure evidence and fail closed", () => {
  const security = readFileSync(join(process.cwd(), ".github", "workflows", "security.yml"), "utf8");
  assert.match(security, /if: always\(\) && hashFiles\('shipproof\.sarif'\) != ''/);

  const release = readFileSync(join(process.cwd(), ".github", "workflows", "release.yml"), "utf8");
  assert.doesNotMatch(release, /workflow_dispatch/);
  assert.doesNotMatch(release, /npm publish/);
  assert.doesNotMatch(release, /\|\| echo/);
  assert.match(release, /gh release create/);
});
