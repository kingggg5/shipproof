import assert from "node:assert/strict";
import { copyFileSync, existsSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

import { VERSION } from "../lib/package-info.mjs";
import { detectPythonRuntime } from "../lib/runtime.mjs";

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

function requestedMcpPeer(argumentsList) {
  if (argumentsList.length === 0) return null;
  if (
    argumentsList.length !== 2 || argumentsList[0] !== "--mcp-peer"
    || !["3.25.76", "4.6.7"].includes(argumentsList[1])
  ) {
    throw new Error("expected --mcp-peer with a tested version: 3.25.76 or 4.6.7");
  }
  return argumentsList[1];
}

function main(peerVersion) {
  const workDirectory = mkdtempSync(join(tmpdir(), "shipproof-package-smoke-"));
  const consumerDirectory = join(workDirectory, "consumer");
  mkdirSync(consumerDirectory);
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
      [
        npmCliPath(),
        "install",
        tarballPath,
        "--ignore-scripts",
        "--no-audit",
        "--no-fund",
        "--no-save",
        "--omit=optional",
      ],
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

    const packetSource = join(workDirectory, "packet-source");
    const packetOutput = join(workDirectory, "packet-output");
    mkdirSync(packetSource);
    mkdirSync(packetOutput);
    writeFileSync(join(packetSource, "entry.ts"), "export const value = 1;\n");
    const packetScan = runProcess(process.execPath, [installedCli, "scan", packetSource, "--format", "json", "--packet-discover", "--packet-out", packetOutput]);
    assert.equal(packetScan.status, 0, packetScan.stderr);
    const packetLedger = JSON.parse(readFileSync(join(packetOutput, "ledger.json"), "utf8"));
    assert.equal(packetLedger.packet_version, "review-packet/1.1");
    assert.equal(packetLedger.counts.scheduled, 1);
    assert.deepEqual(packetLedger.packets[0].findings, []);
    assert.ok(existsSync(join(installedPackageRoot, "schemas", "packet-responses.schema.json")));
    const packetResponses = join(workDirectory, "responses.json");
    writeFileSync(packetResponses, JSON.stringify(packetLedger.packets.map((packet) => ({
      packet_id: packet.packet_id,
      packet_digest: packet.packet_digest,
      decided: packet.review_targets.map((item) => ({ item_id: item.item_id, verdict: "completed" })),
    }))));
    const responseScan = runProcess(process.execPath, [installedCli, "scan", packetSource, "--format", "json", "--packet-discover", "--packet-out", packetOutput, "--packet-responses", packetResponses]);
    assert.equal(responseScan.status, 0, responseScan.stderr);
    assert.deepEqual(JSON.parse(responseScan.stdout), JSON.parse(packetScan.stdout));
    const appliedLedger = JSON.parse(readFileSync(join(packetOutput, "ledger.json"), "utf8"));
    assert.equal(appliedLedger.review_complete, true);
    assert.deepEqual(appliedLedger.packets, packetLedger.packets);
    const completeResponses = JSON.parse(readFileSync(packetResponses, "utf8"));
    const lateFailurePath = join(workDirectory, "late-failure.json");
    writeFileSync(lateFailurePath, JSON.stringify([...completeResponses, {
      packet_id: packetLedger.packets[0].packet_id,
      packet_digest: packetLedger.packets[0].packet_digest,
      timed_out: true,
    }]));
    const lateFailure = runProcess(process.execPath, [installedCli, "scan", packetSource, "--format", "json", "--packet-discover", "--packet-out", packetOutput, "--packet-responses", lateFailurePath]);
    assert.equal(lateFailure.status, 2, lateFailure.stderr);
    assert.equal(JSON.parse(readFileSync(join(packetOutput, "ledger.json"), "utf8")).review_complete, false);

    const skillProject = join(workDirectory, "skill-project");
    mkdirSync(skillProject);
    const initialized = runProcess(process.execPath, [installedCli, "init", skillProject, "--target", "both"]);
    assert.equal(initialized.status, 0, initialized.stderr);
    const python = detectPythonRuntime({ rootPath: packetSource });
    assert.ok(python, "installed skills need the supported Python used by the CLI");
    for (const host of [".agents", ".claude"]) {
      const skillOutput = join(workDirectory, `packet-output-${host}`);
      mkdirSync(skillOutput);
      const skillScanner = join(skillProject, host, "skills", "audit-production-readiness", "scripts", "scan_repo.py");
      const skillScan = runProcess(python.command, [...python.argumentPrefix, skillScanner, packetSource, "--format", "json", "--packet-discover", "--packet-out", skillOutput]);
      assert.equal(skillScan.status, 0, skillScan.stderr);
      assert.deepEqual(JSON.parse(skillScan.stdout), JSON.parse(packetScan.stdout));
      assert.deepEqual(JSON.parse(readFileSync(join(skillOutput, "ledger.json"), "utf8")), packetLedger);
      const skillResponse = runProcess(python.command, [...python.argumentPrefix, skillScanner, packetSource, "--format", "json", "--packet-discover", "--packet-out", skillOutput, "--packet-responses", packetResponses]);
      assert.equal(skillResponse.status, 0, skillResponse.stderr);
      assert.deepEqual(JSON.parse(skillResponse.stdout), JSON.parse(packetScan.stdout));
      assert.deepEqual(JSON.parse(readFileSync(join(skillOutput, "ledger.json"), "utf8")), appliedLedger);
    }
    writeFileSync(join(packetSource, "entry.ts"), "export const value = 2;\n");
    const staleResponse = runProcess(process.execPath, [installedCli, "scan", packetSource, "--packet-discover", "--packet-out", packetOutput, "--packet-responses", packetResponses]);
    assert.equal(staleResponse.status, 2);

    const impactSource = join(workDirectory, "impact-source");
    mkdirSync(impactSource);
    const querySource = "function queryUser(value) { return db." + "query(value); }\napp.get('/user', (req, res) => { return queryUser(req.query.id); });\n";
    writeFileSync(join(impactSource, "entry.js"), "// bounded padding\n".repeat(24000) + querySource);
    const crossCoverage = runProcess(process.execPath, [installedCli, "scan", impactSource, "--cross-file", "--format", "json"]);
    assert.equal(crossCoverage.status, 1, crossCoverage.stderr);
    assert.equal(JSON.parse(crossCoverage.stdout).summary.completeness.is_complete, false);
    const partialImpact = runProcess(process.execPath, [installedCli, "labs", "impact", "entry.js", "--root", impactSource, "--format", "json"]);
    assert.equal(partialImpact.status, 2, partialImpact.stderr);
    assert.equal(JSON.parse(partialImpact.stdout).completeness.is_complete, false);

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

    const mcpWithoutPeers = runProcess(process.execPath, [installedCli, "mcp"], {
      cwd: consumerDirectory,
    });
    assert.equal(mcpWithoutPeers.status, 2, mcpWithoutPeers.stderr);
    assert.match(mcpWithoutPeers.stderr, /MCP support is unavailable/);

    if (peerVersion) {
      // Explicit maintainer mode only: the default smoke test remains peer-free.
      const peers = runProcess(process.execPath, [
        npmCliPath(), "install", tarballPath, "--ignore-scripts", "--no-audit", "--no-fund",
        "--no-save", "--package-lock=false", "@modelcontextprotocol/sdk@1.32.1",
        `zod@${peerVersion}`,
      ], { cwd: consumerDirectory, timeout: 180_000 });
      assert.equal(peers.status, 0, peers.stderr || peers.error?.message);
      const testsDirectory = join(consumerDirectory, "tests", "node");
      mkdirSync(testsDirectory, { recursive: true });
      const contractPath = join(testsDirectory, "mcp-handshake.test.mjs");
      copyFileSync(join(PACKAGE_ROOT, "tests", "node", "mcp-handshake.test.mjs"), contractPath);
      const handshake = runProcess(process.execPath, [contractPath], {
        cwd: consumerDirectory,
        timeout: 120_000,
        env: {
          ...process.env,
          SHIPPROOF_MCP_REQUIRE_PEERS: "1",
          SHIPPROOF_MCP_EXPECT_ZOD: peerVersion,
          SHIPPROOF_MCP_SERVER_ENTRY: join(installedPackageRoot, "lib", "mcp-server.mjs"),
        },
      });
      assert.equal(handshake.status, 0, handshake.stdout + handshake.stderr);
      assert.doesNotMatch(handshake.stdout, /# SKIP/);
      console.log(`packed MCP contracts: PASS (Zod ${peerVersion}, SDK 1.32.1)`);
    }

    console.log(
      `package smoke: PASS (tarball ${tarballName}, isolated CLI/Action, optional MCP failure, 2 skills, ${VERSION})`,
    );
  } finally {
    rmSync(workDirectory, { recursive: true, force: true });
  }
}

try {
  main(requestedMcpPeer(process.argv.slice(2)));
} catch (error) {
  console.error(`package smoke: FAIL — ${error.message}`);
  process.exitCode = 1;
}
