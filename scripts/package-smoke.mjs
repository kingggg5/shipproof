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
  const candidate = join(dirname(process.execPath), "node_modules", "npm", "bin", "npm-cli.js");
  if (!existsSync(candidate)) throw new Error(`npm CLI not found next to Node at ${candidate}`);
  return candidate;
}

function main() {
  const workDirectory = mkdtempSync(join(tmpdir(), "shipproof-package-smoke-"));
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

    const consumerDirectory = join(workDirectory, "consumer");
    mkdirSync(consumerDirectory);
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

    const demoFixture = join(installedPackageRoot, "examples", "demo-api", "fixtures", "before");
    assert.ok(existsSync(demoFixture), "installed package must ship the demo fixtures");
    const scanned = runProcess(process.execPath, [installedCli, "scan", demoFixture, "--format", "json", "--fail-on", "high"]);
    assert.equal(scanned.status, 1, scanned.stderr);
    assert.equal(JSON.parse(scanned.stdout).summary.findings, 5, "demo before-fixture must report five findings");

    const explained = runProcess(process.execPath, [installedCli, "explain", "SP402"]);
    assert.equal(explained.status, 0, explained.stderr);
    assert.match(explained.stdout, /rate.?limit/i);

    const skillsShipped = existsSync(join(installedPackageRoot, "skills", "audit-production-readiness", "SKILL.md"));
    assert.ok(skillsShipped, "installed package must ship the audit skill");
    console.log(`package smoke: PASS (tarball ${tarballName}, version ${VERSION}, 5 demo findings, explain SP402)`);
  } finally {
    rmSync(workDirectory, { recursive: true, force: true });
  }
}

try {
  main();
} catch (error) {
  console.error(`package smoke: FAIL — ${error.message}`);
  process.exitCode = 1;
}
