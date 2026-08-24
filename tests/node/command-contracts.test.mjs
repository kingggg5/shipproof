import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { basename, isAbsolute, join, relative } from "node:path";
import test from "node:test";

import { internals } from "../../lib/cli.mjs";

const ROOT = internals.PACKAGE_ROOT;
const CLI = join(ROOT, "bin", "shipproof.mjs");
const CONTRACT_DIRECTORY = join(ROOT, "fixtures", "command-contracts");
const UPDATE_CONTRACTS = process.env.UPDATE_SHIPPROOF_COMMAND_CONTRACTS === "1";

const CASES = [
  {
    name: "scan-report",
    status: 0,
    argumentsList: ["scan", "fixtures/golden-contract", "--format", "json", "--fail-on", "none"],
  },
  {
    name: "check-report",
    status: 1,
    argumentsList: ["check", "fixtures/golden-contract", "--format", "json"],
  },
  {
    name: "budget-report",
    status: 1,
    argumentsList: [
      "gate", "budget",
      "--baseline", "fixtures/performance-regression/baseline.json",
      "--current", "fixtures/performance-regression/current.json",
      "--budget", "fixtures/performance-regression/budget.json",
      "--format", "json",
    ],
  },
  {
    name: "capacity-report",
    status: 0,
    argumentsList: [
      "labs", "capacity", "--config", "examples/capacity/shipproof.config.json", "--format", "json",
    ],
  },
  {
    name: "cost-report",
    status: 0,
    argumentsList: [
      "labs", "cost", "fixtures/golden-contract", "--context-tokens", "1000", "--format", "json",
    ],
  },
  {
    name: "impact-report",
    status: 0,
    argumentsList: [
      "labs", "impact", "server.py", "--root", "fixtures/golden-contract", "--format", "json",
    ],
  },
  {
    name: "invariants-report",
    status: 0,
    argumentsList: ["labs", "invariants", "fixtures/golden-contract", "--format", "json"],
  },
  {
    name: "evidence-report",
    status: 0,
    buildArguments() {
      const project = mkdtempSync(join(tmpdir(), "shipproof-evidence-contract-"));
      const compilerDirectory = join(project, "node_modules", "typescript", "bin");
      mkdirSync(compilerDirectory, { recursive: true });
      writeFileSync(join(project, "tsconfig.json"), "{}\n", "utf8");
      writeFileSync(
        join(compilerDirectory, "tsc"),
        'if (process.argv.includes("--version")) console.log("Version 5.9.2"); else process.exit(0);\n',
        "utf8",
      );
      return {
        argumentsList: [
          "gate", "evidence", project, "--adapter", "typescript",
          "--allow-project-code", "--format", "json",
        ],
        cleanup: () => rmSync(project, { recursive: true, force: true }),
      };
    },
  },
];

function normalizeAbsolutePath(value) {
  const relativePath = relative(ROOT, value);
  if (relativePath && !relativePath.startsWith("..") && !isAbsolute(relativePath)) {
    return `<PACKAGE_ROOT>/${relativePath.replaceAll("\\", "/").normalize("NFC")}`;
  }
  return `<ABSOLUTE>/${basename(value).normalize("NFC")}`;
}

function normalizeReport(value, key = "") {
  if (Array.isArray(value)) return value.map((item) => normalizeReport(item));
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value).map(([childKey, childValue]) => [
        childKey,
        normalizeReport(childValue, childKey),
      ]),
    );
  }
  if (key === "root" && typeof value === "string") return "<ROOT>";
  if (["source", "policy_path"].includes(key) && typeof value === "string" && isAbsolute(value)) {
    return normalizeAbsolutePath(value);
  }
  return value;
}

function runContractCase(contractCase) {
  const built = contractCase.buildArguments?.() || {
    argumentsList: contractCase.argumentsList,
    cleanup: () => {},
  };
  try {
    const completed = spawnSync(process.execPath, [CLI, ...built.argumentsList], {
      cwd: ROOT,
      encoding: "utf8",
      maxBuffer: 8_000_000,
      shell: false,
      windowsHide: true,
    });
    return completed;
  } finally {
    built.cleanup();
  }
}

for (const contractCase of CASES) {
  test(`${contractCase.name} matches its versioned command contract`, (context) => {
    const completed = runContractCase(contractCase);
    if (completed.error?.code === "EPERM") {
      context.skip("subprocess creation is blocked by the host sandbox");
      return;
    }
    assert.ifError(completed.error);
    assert.equal(completed.status, contractCase.status, completed.stderr);
    let report;
    try {
      report = normalizeReport(JSON.parse(completed.stdout));
    } catch (error) {
      assert.fail(
        `${contractCase.name} returned invalid JSON: ${error.message}\nstdout: ${completed.stdout}\nstderr: ${completed.stderr}`,
      );
    }
    const fixturePath = join(CONTRACT_DIRECTORY, `${contractCase.name}.v1.json`);
    if (UPDATE_CONTRACTS) {
      mkdirSync(CONTRACT_DIRECTORY, { recursive: true });
      writeFileSync(fixturePath, `${JSON.stringify(report, null, 2)}\n`, "utf8");
    }
    const expected = JSON.parse(readFileSync(fixturePath, "utf8"));
    assert.deepEqual(report, expected);
  });
}
