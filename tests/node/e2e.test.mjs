import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";

import { internals } from "../../lib/cli.mjs";

const CLI = join(internals.PACKAGE_ROOT, "bin", "shipproof.mjs");
const EVIDENCE_SCHEMA = JSON.parse(
  readFileSync(join(internals.PACKAGE_ROOT, "schemas", "evidence-envelope.schema.json"), "utf8"),
);
const CHECK_SCHEMA = JSON.parse(
  readFileSync(join(internals.PACKAGE_ROOT, "schemas", "check-report.schema.json"), "utf8"),
);

function assertTopLevelSchemaContract(report, schema) {
  const commandShape = schema.allOf[1];
  const allowed = [...Object.keys(EVIDENCE_SCHEMA.properties), ...Object.keys(commandShape.properties)].sort();
  assert.deepEqual(Object.keys(report).sort(), [...new Set(allowed)].sort());
  for (const key of [...EVIDENCE_SCHEMA.required, ...commandShape.required]) {
    assert.ok(Object.hasOwn(report, key), `missing ${key}`);
  }
  assert.equal(report.tool.command, commandShape.properties.tool.properties.command.const);
}

function runCli(argumentsList) {
  return spawnSync(process.execPath, [CLI, ...argumentsList], {
    encoding: "utf8",
    maxBuffer: 4_000_000,
    shell: false,
    windowsHide: true,
  });
}

test("CLI workflow preserves documented exit codes and artifacts", (context) => {
  const probe = runCli(["version"]);
  if (probe.error?.code === "EPERM") {
    context.skip("subprocess creation is blocked by the host sandbox");
    return;
  }
  assert.equal(probe.status, 0, probe.stderr);

  const repository = mkdtempSync(join(tmpdir(), "shipproof-e2e-"));
  try {
    const initialized = runCli(["init", repository, "--target", "codex"]);
    assert.equal(initialized.status, 0, initialized.stderr);
    assert.equal(existsSync(join(repository, ".agents", "skills", "audit-production-readiness", "SKILL.md")), true);
    assert.match(readFileSync(join(repository, ".shipproof.yml"), "utf8"), /^version: 1$/m);

    const policyValidation = runCli(["config", "validate", repository, "--format", "json"]);
    assert.equal(policyValidation.status, 0, policyValidation.stderr);
    assert.equal(JSON.parse(policyValidation.stdout).valid, true);

    const initializedCheck = runCli(["check", repository, "--format", "json"]);
    assert.equal(initializedCheck.status, 0, initializedCheck.stderr);
    const checkReport = JSON.parse(initializedCheck.stdout);
    assert.equal(checkReport.verdict, "PASS_WITH_EVIDENCE");
    assertTopLevelSchemaContract(checkReport, CHECK_SCHEMA);

    const help = runCli(["help"]);
    assert.equal(help.status, 0, help.stderr);
    assert.match(help.stdout, /labs impact/);
    assert.doesNotMatch(help.stdout, /^\s+badge\b/m);

    const vulnerable = join(internals.PACKAGE_ROOT, "examples", "demo-api", "fixtures", "before");
    const scanned = runCli(["scan", vulnerable, "--format", "json", "--fail-on", "high"]);
    assert.equal(scanned.status, 1, scanned.stderr);
    assert.equal(JSON.parse(scanned.stdout).summary.findings, 6);

    const retiredBadge = runCli(["badge", vulnerable]);
    assert.equal(retiredBadge.status, 2);
    assert.doesNotMatch(retiredBadge.stdout, /PASS/);

    const baseline = join(repository, "baseline.json");
    const current = join(repository, "current.json");
    const budget = join(repository, "budget.json");
    writeFileSync(baseline, JSON.stringify({ metrics: { p95_latency_ms: 100 } }), "utf8");
    writeFileSync(current, JSON.stringify({ metrics: { p95_latency_ms: 250 } }), "utf8");
    writeFileSync(
      budget,
      JSON.stringify({ metrics: { p95_latency_ms: { direction: "lower", max: 150 } } }),
      "utf8",
    );
    const budgetResult = runCli([
      "gate", "budget", "--baseline", baseline, "--current", current, "--budget", budget, "--format", "json",
    ]);
    assert.equal(budgetResult.status, 1, budgetResult.stderr);
    assert.equal(JSON.parse(budgetResult.stdout).verdict, "BLOCK");

    const invalidEvidence = runCli(["gate", "evidence", repository, "--adapter", "shell", "--format", "json"]);
    assert.equal(invalidEvidence.status, 2);
  } finally {
    rmSync(repository, { recursive: true, force: true });
  }
});
