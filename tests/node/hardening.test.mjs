import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { internals as cliInternals } from "../../lib/cli.mjs";
import { internals as evidenceInternals } from "../../lib/evidence.mjs";
import { buildScanArguments, internals as mcpInternals } from "../../lib/mcp-server.mjs";
import { parsePolicyText, validatePolicy } from "../../lib/policy.mjs";
import { detectPythonRuntime, isSupportedPythonVersion } from "../../lib/runtime.mjs";
import { formatActionSummary } from "../../scripts/run-action.mjs";

const { runPythonJsonCommand } = cliInternals;

function fakeSpawn(overrides = {}) {
  return (_command, _args, _options) => ({
    status: 0,
    stdout: JSON.stringify({ verdict: "PASS_WITH_EVIDENCE" }),
    stderr: "",
    ...overrides,
  });
}

test("runtime detection is shared, cached, and version-gated", () => {
  assert.equal(isSupportedPythonVersion("Python 3.10.0"), true);
  assert.equal(isSupportedPythonVersion("Python 3.9.7"), false);
  assert.equal(isSupportedPythonVersion(""), false);
  const runtime = detectPythonRuntime({ refresh: true });
  if (runtime) {
    assert.match(runtime.version, /Python 3\.(?:[1-9]\d|\d{2,})/);
    const cached = detectPythonRuntime();
    assert.equal(cached.command, runtime.command);
  }
});

test("runPythonJsonCommand maps timeout kills to an actionable error", () => {
  assert.throws(
    () => runPythonJsonCommand("skills/x/y.py", [], () => ({ status: null, signal: "SIGTERM", stdout: "", stderr: "" })),
    /terminated.*timeout/i,
  );
});

test("runPythonJsonCommand maps maxBuffer failures to an actionable error", () => {
  const error = new Error("stdout maxBuffer length exceeded");
  assert.throws(
    () => runPythonJsonCommand("skills/x/y.py", [], () => ({ error, status: null, stdout: "", stderr: "" })),
    /output limit.*SHIPPROOF_MAX_BUFFER_BYTES/,
  );
});

test("runPythonJsonCommand surfaces scanner stderr for invalid evidence", () => {
  assert.throws(
    () => runPythonJsonCommand("skills/x/y.py", [], () => ({ status: 3, stdout: "", stderr: "boom" })),
    /boom/,
  );
});

test("runPythonJsonCommand names the gate when JSON is invalid", () => {
  assert.throws(
    () => runPythonJsonCommand("skills/x/y.py", [], fakeSpawn({ stdout: "not-json" })),
    /skills\/x\/y\.py.*invalid JSON/,
  );
});

test("buildScanArguments supports exclude, confidence, and cross-file modes", () => {
  assert.deepEqual(
    buildScanArguments({ path: ".", fail_on: "high", max_file_bytes: 1000 }),
    [".", "--format", "json", "--fail-on", "high", "--max-file-bytes", "1000"],
  );
  assert.deepEqual(
    buildScanArguments({ path: ".", exclude: ["dist/**", "build/**"], cross_file: true, min_confidence: "medium" }),
    [
      ".", "--format", "json", "--fail-on", "high", "--max-file-bytes", "1000000",
      "--exclude", "dist/**", "--exclude", "build/**",
      "--min-confidence", "medium",
      "--cross-file",
    ],
  );
});

test("buildScanArguments rejects malformed exclude patterns", () => {
  assert.throws(() => buildScanArguments({ path: ".", exclude: [""] }), /repository-relative/);
  assert.throws(() => buildScanArguments({ path: ".", exclude: ["a\nb"] }), /repository-relative/);
  assert.throws(() => buildScanArguments({ path: ".", exclude: ["x".repeat(600)] }), /repository-relative/);
  assert.throws(() => buildScanArguments({ path: ".", min_confidence: "certain" }), /min_confidence/);
});

test("mcp internals stay exported for parity tooling", () => {
  assert.equal(typeof mcpInternals.runPythonJson, "function");
  assert.equal(typeof mcpInternals.runPythonProcess, "function");
});

test("policy parser rejects mapping-shaped sequence items", () => {
  assert.throws(
    () => parsePolicyText("version: 1\nscan:\n  exclude:\n    - path: dist\n"),
    /plain scalars.*mappings/,
  );
});

test("policy parser explains leading-zero numbers", () => {
  assert.throws(
    () => parsePolicyText("version: 1\nscan:\n  max_file_bytes: 007\n"),
    /leading zeros/,
  );
});

test("policy parser reports JSON syntax errors with context", () => {
  assert.throws(() => parsePolicyText('{"version": 1,'), /invalid JSON policy/);
});

test("policy parser unifies max_file_bytes floor with the action and MCP", () => {
  assert.throws(
    () => validatePolicy(parsePolicyText("version: 1\nscan:\n  max_file_bytes: 512\n")),
    /1024/,
  );
  const policy = validatePolicy(parsePolicyText("version: 1\nscan:\n  max_file_bytes: 1024\n"));
  assert.equal(policy.scan.max_file_bytes, 1024);
});

test("evidence diagnostics are classified by severity", () => {
  const { classifyDiagnostics } = evidenceInternals;
  assert.deepEqual(
    classifyDiagnostics([
      "src/main.rs:12:5: error: unresolved import",
      "src/lib.rs:3:1: warning: unused variable",
      "src/lib.rs:9:8: warning: value assigned is never read",
      "vet: suspicious Printf call",
    ]),
    { error: 1, warning: 2, other: 1 },
  );
});

test("policy parser still accepts quoted strings containing colons in sequences", () => {
  const policy = parsePolicyText('version: 1\nscan:\n  exclude:\n    - "01-intro:/**"\n');
  assert.deepEqual(policy.scan.exclude, ["01-intro:/**"]);
});

test("action summary escapes table cells and caps rendered rows", () => {
  const directory = mkdtempSync(join(tmpdir(), "shipproof-summary-"));
  const reportPath = join(directory, "report.json");
  const findings = Array.from({ length: 230 }, (_, index) => ({
    severity: "high",
    rule_id: `SP9${String(index).padStart(2, "0")}`,
    path: `src/file|${index}.ts`,
    line: index + 1,
    title: `Title with | pipe and\nnewline ${index}`,
  }));
  writeFileSync(reportPath, JSON.stringify({ verdict: "BLOCK", findings, summary: { files_scanned: 1 } }));
  const summary = formatActionSummary(reportPath, "json", { exitCode: 1, failOn: "high" });
  assert.match(summary, /Title with \\\| pipe and newline/);
  assert.match(summary, /…and 30 more findings/);
  assert.equal((summary.match(/\n/g) || []).length < 260, true);
  rmSync(directory, { recursive: true, force: true });
});
