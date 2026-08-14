import assert from "node:assert/strict";
import { existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";

import { internals } from "../../lib/cli.mjs";

const CLI = join(internals.PACKAGE_ROOT, "bin", "shipproof.mjs");

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

    const vulnerable = join(internals.PACKAGE_ROOT, "examples", "demo-api", "fixtures", "before");
    const scanned = runCli(["scan", vulnerable, "--format", "json", "--fail-on", "high"]);
    assert.equal(scanned.status, 1, scanned.stderr);
    assert.equal(JSON.parse(scanned.stdout).summary.findings, 5);

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
      "budget", "--baseline", baseline, "--current", current, "--budget", budget, "--format", "json",
    ]);
    assert.equal(budgetResult.status, 1, budgetResult.stderr);
    assert.equal(JSON.parse(budgetResult.stdout).verdict, "BLOCK");

    const invalidEvidence = runCli(["evidence", repository, "--adapter", "shell", "--format", "json"]);
    assert.equal(invalidEvidence.status, 2);
  } finally {
    rmSync(repository, { recursive: true, force: true });
  }
});
