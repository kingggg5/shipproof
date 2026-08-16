import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";

import { internals } from "../../lib/cli.mjs";

const CLI = join(internals.PACKAGE_ROOT, "bin", "shipproof.mjs");
const EXPECTATION = JSON.parse(
  readFileSync(join(internals.PACKAGE_ROOT, "fixtures", "expected-golden-scan.json"), "utf8"),
);

test("Node CLI scan produces the same findings and fingerprints as direct Python", (context) => {
  const probe = spawnSync(process.execPath, [CLI, "version"], {
    encoding: "utf8",
    shell: false,
    windowsHide: true,
  });
  if (probe.error?.code === "EPERM") {
    context.skip("subprocess creation is blocked by the host sandbox");
    return;
  }
  const scanned = spawnSync(
    process.execPath,
    [CLI, "scan", join(internals.PACKAGE_ROOT, "fixtures", "golden-contract"), "--format", "json", "--fail-on", "none"],
    { encoding: "utf8", maxBuffer: 4_000_000, shell: false, windowsHide: true },
  );
  assert.equal(scanned.status, 0, scanned.stderr);
  const report = JSON.parse(scanned.stdout);
  assert.equal(report.verdict, EXPECTATION.verdict);
  assert.equal(report.summary.files_scanned, EXPECTATION.summary.files_scanned);
  const stableFields = (finding) => {
    const {
      rule_id, path, line, severity, confidence, detection, proof_level, evidence, fingerprint: print,
    } = finding;
    return { rule_id, path, line, severity, confidence, detection, proof_level, evidence, fingerprint: print };
  };
  assert.deepEqual(report.findings.map(stableFields), EXPECTATION.findings);
});
