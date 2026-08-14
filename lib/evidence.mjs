import { spawnSync } from "node:child_process";
import { existsSync, realpathSync, statSync } from "node:fs";
import { basename, join, resolve } from "node:path";

import { VERSION } from "./package-info.mjs";

const ADAPTERS = Object.freeze({
  typescript: {
    marker: "tsconfig.json",
    description: "TypeScript compiler diagnostics",
    build(root) {
      const compiler = join(root, "node_modules", "typescript", "bin", "tsc");
      return existsSync(compiler)
        ? { command: process.execPath, argumentsList: [compiler, "--noEmit", "--pretty", "false"] }
        : null;
    },
  },
  go: {
    marker: "go.mod",
    description: "Go vet diagnostics with dependency downloads disabled",
    build() {
      return { command: "go", argumentsList: ["vet", "./..."] };
    },
    environment: { GOPROXY: "off", GOTOOLCHAIN: "local" },
  },
  rust: {
    marker: "Cargo.toml",
    description: "Rust Clippy diagnostics in offline mode",
    build() {
      return {
        command: "cargo",
        argumentsList: ["clippy", "--offline", "--all-targets", "--message-format=short", "--", "-D", "warnings"],
      };
    },
    requiresProjectCodeApproval: true,
  },
});

function repositoryRoot(inputPath) {
  const root = realpathSync.native(resolve(inputPath || "."));
  if (!statSync(root).isDirectory()) throw new Error(`not a directory: ${root}`);
  return root;
}

function executableAvailable(command, environment) {
  if (command === process.execPath || existsSync(command)) return true;
  const result = spawnSync(command, ["--version"], {
    encoding: "utf8",
    env: environment,
    shell: false,
    timeout: 3_000,
    windowsHide: true,
  });
  return result.status === 0;
}

export function discoverEvidenceAdapters(inputPath = ".") {
  const root = repositoryRoot(inputPath);
  return Object.entries(ADAPTERS).map(([name, adapter]) => {
    const detected = existsSync(join(root, adapter.marker));
    const invocation = detected ? adapter.build(root) : null;
    const environment = { ...process.env, ...adapter.environment };
    return {
      name,
      description: adapter.description,
      detected,
      available: Boolean(invocation && executableAvailable(invocation.command, environment)),
      requires_project_code_approval: Boolean(adapter.requiresProjectCodeApproval),
    };
  });
}

function boundedDiagnostics(stdout, stderr) {
  return `${stdout || ""}\n${stderr || ""}`
    .split(/\r?\n/)
    .map((line) => line.trimEnd())
    .filter(Boolean)
    .slice(0, 200);
}

export function runEvidenceAdapter(inputPath, adapterName, { allowProjectCode = false } = {}) {
  const root = repositoryRoot(inputPath);
  const adapter = ADAPTERS[adapterName];
  if (!adapter) throw new Error(`unsupported adapter: ${adapterName}`);
  if (!existsSync(join(root, adapter.marker))) {
    throw new Error(`${adapterName} adapter did not find ${adapter.marker}`);
  }
  if (adapter.requiresProjectCodeApproval && !allowProjectCode) {
    throw new Error("rust analysis may execute build.rs; pass --allow-project-code after review");
  }
  const invocation = adapter.build(root);
  const environment = { ...process.env, ...adapter.environment };
  if (!invocation || !executableAvailable(invocation.command, environment)) {
    throw new Error(`${adapterName} analyzer is not installed or not available offline`);
  }
  const result = spawnSync(invocation.command, invocation.argumentsList, {
    cwd: root,
    encoding: "utf8",
    env: environment,
    maxBuffer: 2_000_000,
    shell: false,
    timeout: 120_000,
    windowsHide: true,
  });
  if (result.error) throw new Error(`${adapterName} analyzer failed: ${result.error.message}`);
  const passed = result.status === 0;
  return {
    schema_version: "1.0",
    tool: { name: "ShipProof", version: VERSION, command: "evidence" },
    verdict: passed ? "PASS_WITH_EVIDENCE" : "BLOCK",
    root,
    adapter: adapterName,
    analyzer: adapterName === "typescript" ? "tsc" : basename(invocation.command),
    process_exit_code: result.status,
    passed,
    diagnostics: boundedDiagnostics(result.stdout, result.stderr),
    limitations: [
      "This adapter normalizes analyzer output; it does not prove runtime correctness or security.",
      "Dependencies are not downloaded, so an uncached dependency may make analysis unavailable.",
    ],
  };
}

function parseArguments(commandArguments) {
  const parsed = { path: ".", list: false, adapter: null, format: "markdown", allowProjectCode: false };
  let positionals = 0;
  for (let index = 0; index < commandArguments.length; index += 1) {
    const value = commandArguments[index];
    if (["--adapter", "--format"].includes(value)) {
      const nextValue = commandArguments[index + 1];
      if (!nextValue || nextValue.startsWith("-")) throw new Error(`${value} requires a value`);
      if (value === "--adapter") parsed.adapter = nextValue;
      else parsed.format = nextValue;
      index += 1;
    } else if (value === "--list") {
      parsed.list = true;
    } else if (value === "--allow-project-code") {
      parsed.allowProjectCode = true;
    } else if (value.startsWith("-")) {
      throw new Error(`unknown option: ${value}`);
    } else if (positionals === 0) {
      parsed.path = value;
      positionals += 1;
    } else {
      throw new Error("too many positional arguments");
    }
  }
  if (!new Set(["json", "markdown"]).has(parsed.format)) throw new Error("unsupported format");
  if (parsed.adapter && !Object.hasOwn(ADAPTERS, parsed.adapter)) {
    throw new Error(`unsupported adapter: ${parsed.adapter}`);
  }
  return parsed;
}

function renderMarkdown(report) {
  const lines = [
    `# ShipProof ${report.adapter} evidence: ${report.passed ? "PASS" : "BLOCK"}`,
    "",
    `Analyzer: \`${report.analyzer}\``,
    `Exit code: \`${report.process_exit_code}\``,
    "",
    "## Diagnostics",
    "",
    ...(report.diagnostics.length ? report.diagnostics.map((line) => `- ${line}`) : ["- None"]),
    "",
  ];
  return lines.join("\n");
}

export function runEvidenceCli(commandArguments) {
  try {
    const parsed = parseArguments(commandArguments);
    const adapters = discoverEvidenceAdapters(parsed.path);
    if (parsed.list) {
      if (parsed.format === "json") console.log(JSON.stringify(adapters, null, 2));
      else for (const adapter of adapters) {
        console.log(`${adapter.name}: ${adapter.detected && adapter.available ? "ready" : "unavailable"}`);
      }
      return 0;
    }
    const ready = adapters.filter((adapter) => adapter.detected && adapter.available);
    const adapterName = parsed.adapter || (ready.length === 1 ? ready[0].name : null);
    if (!adapterName) throw new Error("select one detected adapter with --adapter; use --list to inspect");
    const report = runEvidenceAdapter(parsed.path, adapterName, {
      allowProjectCode: parsed.allowProjectCode,
    });
    console.log(parsed.format === "json" ? JSON.stringify(report, null, 2) : renderMarkdown(report));
    return report.passed ? 0 : 1;
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.error(`shipproof: ${message}`);
    return 2;
  }
}

export const internals = { ADAPTERS };
