import assert from "node:assert/strict";
import { cpSync, existsSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

import { VERSION } from "../lib/package-info.mjs";

const PACKAGE_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");

function runProcess(command, argumentsList, options = {}) {
  const result = spawnSync(command, argumentsList, {
    encoding: "utf8",
    maxBuffer: 8_000_000,
    shell: false,
    windowsHide: true,
    ...options,
  });
  return result;
}

function npmCliPath() {
  const base = dirname(process.execPath);
  const candidates = [
    join(base, "node_modules", "npm", "bin", "npm-cli.js"),
    join(base, "..", "lib", "node_modules", "npm", "bin", "npm-cli.js"),
    join(base, "lib", "node_modules", "npm", "bin", "npm-cli.js"),
    join(base, "..", "node_modules", "npm", "bin", "npm-cli.js"),
  ];
  for (const candidate of candidates) {
    if (existsSync(candidate)) return candidate;
  }
  throw new Error(`npm CLI not found next to Node at ${candidates.join(" or ")}`);
}

function main() {
  const workDirectory = mkdtempSync(join(tmpdir(), "shipproof-package-smoke-"));
  const localNodeModules = join(PACKAGE_ROOT, "node_modules");
  mkdirSync(localNodeModules, { recursive: true });
  const consumerDirectory = mkdtempSync(join(localNodeModules, ".shipproof-consumer-"));
  try {
    const artifactsDirectory = join(workDirectory, "artifacts");
    mkdirSync(artifactsDirectory);
    const packed = runProcess(process.execPath, [npmCliPath(), "pack", "--pack-destination", artifactsDirectory], {
      cwd: PACKAGE_ROOT,
    });
    assert.equal(packed.status, 0, packed.stderr);
    const tarballName = `kingggg5-shipproof-${VERSION}.tgz`;
    const tarballPath = join(artifactsDirectory, tarballName);
    assert.ok(existsSync(tarballPath), `expected packed tarball ${tarballPath}`);

    writeFileSync(join(consumerDirectory, "package.json"), JSON.stringify({ name: "consumer", private: true }), "utf8");
    const installed = runProcess(
      process.execPath,
      [npmCliPath(), "install", tarballPath, "--ignore-scripts", "--no-audit", "--no-fund", "--no-save"],
      { cwd: consumerDirectory },
    );
    assert.equal(installed.status, 0, installed.stderr);

    const installedPackageRoot = join(consumerDirectory, "node_modules", "@kingggg5", "shipproof");
    assert.ok(existsSync(join(installedPackageRoot, "bin", "shipproof.mjs")), "installed package must expose the CLI");
    const installedCli = join(installedPackageRoot, "bin", "shipproof.mjs");

    const versionProbe = runProcess(process.execPath, [installedCli, "--version"]);
    assert.equal(versionProbe.status, 0, versionProbe.stderr);
    assert.equal(versionProbe.stdout.trim(), VERSION);

    const helpProbe = runProcess(process.execPath, [installedCli, "help"]);
    assert.equal(helpProbe.status, 0, helpProbe.stderr);
    assert.match(helpProbe.stdout, /labs impact/);
    assert.doesNotMatch(helpProbe.stdout, /^\s+badge\b/m);

    const policyProbe = runProcess(
      process.execPath,
      [installedCli, "config", "validate", installedPackageRoot, "--format", "json"],
    );
    assert.equal(policyProbe.status, 0, policyProbe.stderr);
    assert.equal(JSON.parse(policyProbe.stdout).valid, true);

    const demoFixture = join(installedPackageRoot, "examples", "demo-api", "fixtures", "before");
    assert.ok(existsSync(demoFixture), "installed package must ship the demo fixtures");
    const scanned = runProcess(process.execPath, [installedCli, "scan", demoFixture, "--format", "json", "--fail-on", "high"]);
    assert.equal(scanned.status, 1, scanned.stderr);
    assert.equal(JSON.parse(scanned.stdout).summary.findings, 6, "demo before-fixture must report six findings");

    const explained = runProcess(process.execPath, [installedCli, "explain", "SP402"]);
    assert.equal(explained.status, 0, explained.stderr);
    assert.match(explained.stdout, /rate.?limit/i);

    const retiredBadge = runProcess(process.execPath, [installedCli, "badge", demoFixture]);
    assert.equal(retiredBadge.status, 2);
    assert.doesNotMatch(retiredBadge.stdout, /PASS/);

    for (const skillName of ["audit-production-readiness", "engineer-production-systems"]) {
      assert.ok(
        existsSync(join(installedPackageRoot, "skills", skillName, "SKILL.md")),
        `installed package must ship the ${skillName} skill`,
      );
    }

    const actionReportPath = join(installedPackageRoot, "package-smoke-action.json");
    const actionOutputPath = join(workDirectory, "github-output.txt");
    const actionSummaryPath = join(workDirectory, "github-summary.md");
    const action = runProcess(
      process.execPath,
      [join(installedPackageRoot, "scripts", "run-action.mjs")],
      {
        cwd: installedPackageRoot,
        env: {
          ...process.env,
          GITHUB_WORKSPACE: installedPackageRoot,
          GITHUB_OUTPUT: actionOutputPath,
          GITHUB_STEP_SUMMARY: actionSummaryPath,
          SHIPPROOF_INPUT_PATH: "examples/demo-api/fixtures/before",
          SHIPPROOF_INPUT_FORMAT: "json",
          SHIPPROOF_INPUT_OUTPUT: "package-smoke-action.json",
          SHIPPROOF_INPUT_FAIL_ON: "high",
          SHIPPROOF_INPUT_BASELINE: "",
          SHIPPROOF_INPUT_CHANGED_SINCE: "",
          SHIPPROOF_INPUT_MAX_FILE_BYTES: "1000000",
        },
      },
    );
    assert.equal(action.status, 1, action.stderr);
    assert.equal(JSON.parse(readFileSync(actionReportPath, "utf8")).summary.findings, 6);
    assert.match(readFileSync(actionOutputPath, "utf8"), /report-path=/);
    assert.match(readFileSync(actionSummaryPath, "utf8"), /BLOCKED/);

    const mcpHandshake = runProcess(
      process.execPath,
      [join(PACKAGE_ROOT, "tests", "node", "mcp-handshake.test.mjs")],
      {
        cwd: PACKAGE_ROOT,
        env: {
          ...process.env,
          SHIPPROOF_MCP_SERVER_ENTRY: join(installedPackageRoot, "lib", "mcp-server.mjs"),
        },
      },
    );
    assert.equal(mcpHandshake.status, 0, `${mcpHandshake.stdout}\n${mcpHandshake.stderr}`);
    assert.match(mcpHandshake.stdout, /pass 1/);

    console.log(
      `package smoke: PASS (tarball ${tarballName}, CLI, Action, MCP, 2 skills, ${VERSION})`,
    );
  } finally {
    rmSync(consumerDirectory, { recursive: true, force: true });
    rmSync(workDirectory, { recursive: true, force: true });
  }
}

try {
  main();
} catch (error) {
  console.error(`package smoke: FAIL — ${error.message}`);
  process.exitCode = 1;
}
