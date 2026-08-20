import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { buildPolicyGates, loadPolicy, parsePolicyText, validatePolicy } from "../../lib/policy.mjs";
import { internals } from "../../lib/cli.mjs";

test("parses and validates the repository policy without a YAML runtime", () => {
  const { path, policy } = loadPolicy(internals.PACKAGE_ROOT);
  assert.equal(path, join(internals.PACKAGE_ROOT, ".shipproof.yml"));
  assert.equal(policy.version, 1);
  assert.equal(policy.security.fail_on, "high");
  assert.deepEqual(policy.scan.exclude, ["examples/demo-api/fixtures/**"]);
});

test("builds only fixed allowlisted gate commands", () => {
  const { policy } = loadPolicy(internals.PACKAGE_ROOT);
  const gates = buildPolicyGates(internals.PACKAGE_ROOT, policy);
  assert.deepEqual(gates.map((gate) => gate.command), ["scan", "budget", "capacity"]);
  assert.ok(gates[0].argumentsList.includes("--exclude"));
  assert.ok(gates.every((gate) => !gate.argumentsList.some((value) => value.includes(";"))));
});

test("rejects unsupported YAML features, duplicate keys, and unknown policy keys", () => {
  assert.throws(() => parsePolicyText("version: 1\nscan: &defaults\n  path: .\n"), /unsupported YAML/);
  assert.throws(() => parsePolicyText("version: 1\nversion: 1\n"), /duplicate key/);
  assert.throws(() => validatePolicy({ version: 1, command: "curl example.test" }), /unknown policy keys/);
});

test("rejects paths outside the repository", () => {
  assert.throws(() => loadPolicy(internals.PACKAGE_ROOT, "../.shipproof.yml"), /invalid policy file/);
  const policy = validatePolicy({ version: 1, scan: { path: ".." } });
  assert.throws(() => buildPolicyGates(internals.PACKAGE_ROOT, policy), /requested path/);
});

test("allowMissing permits only an absent policy, not a wrong path type", () => {
  const root = mkdtempSync(join(tmpdir(), "shipproof-policy-"));
  try {
    assert.equal(loadPolicy(root, ".shipproof.yml", { allowMissing: true }), null);
    mkdirSync(join(root, ".shipproof.yml"));
    assert.throws(
      () => loadPolicy(root, ".shipproof.yml", { allowMissing: true }),
      /requested path is not a file/,
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("capacity accepts reviewed numeric inputs and rejects unknown fields", () => {
  const policy = validatePolicy({
    version: 1,
    capacity: { target_users: 10_000, inputs: { headroom: 1.5 } },
  });
  assert.equal(policy.capacity.target_users, 10_000);
  assert.throws(
    () => validatePolicy({ version: 1, capacity: { target_users: 1, inputs: { shell: "rm" } } }),
    /unknown capacity.inputs keys/,
  );
});
