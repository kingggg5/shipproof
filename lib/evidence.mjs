import { spawnSync } from "node:child_process";
import { existsSync, realpathSync, statSync } from "node:fs";
import { basename, isAbsolute, join, resolve, sep } from "node:path";

import { VERSION } from "./package-info.mjs";
import { resolveRepositoryPath } from "./safe-path.mjs";

const PROBE_TIMEOUT_MS = 3_000;
const ADAPTER_TIMEOUT_MS = 120_000;
const ADAPTER_MAX_BUFFER_BYTES = 2_000_000;
const MAX_DIAGNOSTIC_LINES = 200;
const MAX_DIAGNOSTIC_LINE_CHARS = 4_096;

const ADAPTERS = Object.freeze({
  typescript: {
    marker: "tsconfig.json",
    description: "TypeScript compiler diagnostics",
    build(root) {
      const compiler = join(root, "node_modules", "typescript", "bin", "tsc");
      if (!existsSync(compiler)) return null;
      const resolvedCompiler = resolveRepositoryPath(
        root,
        join("node_modules", "typescript", "bin", "tsc"),
        "file",
      );
      return {
        command: process.execPath,
        argumentsList: [resolvedCompiler, "--noEmit", "--pretty", "false"],
        versionArguments: [resolvedCompiler, "--version"],
        versionRequiresProjectCodeApproval: true,
      };
    },
    requiresProjectCodeApproval: true,
    approvalReason: "typescript analysis executes the repository-local compiler",
    diagnosticExitCodes: [1, 2],
  },
  go: {
    marker: "go.mod",
    description: "Go vet diagnostics with dependency downloads disabled",
    build() {
      return { command: "go", argumentsList: ["vet", "./..."], versionArguments: ["version"] };
    },
    environment: { GOPROXY: "off", GOTOOLCHAIN: "local" },
    diagnosticExitCodes: [1],
  },
  rust: {
    marker: "Cargo.toml",
    description: "Rust Clippy diagnostics in offline mode",
    build() {
      return {
        command: "cargo",
        argumentsList: ["clippy", "--offline", "--all-targets", "--message-format=short", "--", "-D", "warnings"],
        versionArguments: ["--version"],
      };
    },
    requiresProjectCodeApproval: true,
    approvalReason: "rust analysis may execute build.rs",
    diagnosticExitCodes: [101],
  },
});

function repositoryRoot(inputPath) {
  const root = realpathSync.native(resolve(inputPath || "."));
  if (!statSync(root).isDirectory()) throw new Error(`not a directory: ${root}`);
  return root;
}

function probeExecutable(command, environment, versionArguments = ["--version"]) {
  // Only path-like commands can be probed with existsSync; a bare command name
  // must go through the shell-free spawn probe (a repo file named `go` or
  // `cargo` must not fake availability).
  if ((isAbsolute(command) || command.includes(sep)) && !existsSync(command)) {
    return { available: false, version: null };
  }
  const result = spawnSync(command, versionArguments, {
    encoding: "utf8",
    env: environment,
    shell: false,
    timeout: PROBE_TIMEOUT_MS,
    windowsHide: true,
  });
  const version = redactDiagnosticLine(`${result.stdout || ""}${result.stderr || ""}`.trim());
  return {
    available: result.status === 0 && !result.error && Boolean(version),
    version: result.status === 0 && !result.error && version ? version.slice(0, 256) : null,
  };
}

export function discoverEvidenceAdapters(inputPath = ".", { allowProjectCode = false } = {}) {
  const root = repositoryRoot(inputPath);
  return Object.entries(ADAPTERS).map(([name, adapter]) => {
    const detected = existsSync(join(root, adapter.marker));
    const invocation = detected ? adapter.build(root) : null;
    const environment = { ...process.env, ...adapter.environment };
    const approvalRequired = Boolean(
      invocation?.versionRequiresProjectCodeApproval && !allowProjectCode,
    );
    const probe = invocation && !approvalRequired
      ? probeExecutable(invocation.command, environment, invocation.versionArguments)
      : { available: false, version: null };
    return {
      name,
      description: adapter.description,
      detected,
      available: probe.available,
      analyzer_version: probe.version,
      approval_required: approvalRequired,
      requires_project_code_approval: Boolean(adapter.requiresProjectCodeApproval),
    };
  });
}

export function redactDiagnosticLine(value) {
  return String(value || "")
    .replace(/\bBearer\s+[^\s,;]+/giu, "Bearer [REDACTED]")
    .replace(
      /\b((?:password|passwd|token|secret|api[_-]?key|authorization|cookie)\s*[:=]\s*)(?:"[^"]*"|'[^']*'|[^\s,;]+)/giu,
      "$1[REDACTED]",
    )
    .replace(/\b(?:gh[pousr]_|sk-(?:proj-)?)[A-Za-z0-9_-]{12,}/gu, "[REDACTED]")
    .replace(/\bAKIA[A-Z0-9]{16}\b/gu, "[REDACTED]")
    .replace(/\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/gu, "[REDACTED]")
    .replace(/:\/\/[^\s/:@]+:[^\s/@]+@/gu, "://[REDACTED]@");
}

function boundedDiagnostics(stdout, stderr) {
  const sourceLines = `${stdout || ""}\n${stderr || ""}`
    .split(/\r?\n/)
    .map((line) => line.trimEnd())
    .filter(Boolean);
  const diagnostics = sourceLines.slice(0, MAX_DIAGNOSTIC_LINES).map((line) => {
    const redacted = redactDiagnosticLine(line);
    return redacted.length > MAX_DIAGNOSTIC_LINE_CHARS
      ? `${redacted.slice(0, MAX_DIAGNOSTIC_LINE_CHARS)}…[truncated]`
      : redacted;
  });
  return {
    diagnostics,
    truncated: sourceLines.length > MAX_DIAGNOSTIC_LINES
      || sourceLines.some((line) => redactDiagnosticLine(line).length > MAX_DIAGNOSTIC_LINE_CHARS),
  };
}

export function classifyDiagnostics(diagnostics) {
  const counts = { error: 0, warning: 0, other: 0 };
  for (const line of diagnostics) {
    if (/:\s*error\b/i.test(line)) counts.error += 1;
    else if (/:\s*warning\b/i.test(line)) counts.warning += 1;
    else counts.other += 1;
  }
  return counts;
}

export function runEvidenceAdapter(
  inputPath,
  adapterName,
  {
    allowProjectCode = false,
    timeoutMs = ADAPTER_TIMEOUT_MS,
    maxBufferBytes = ADAPTER_MAX_BUFFER_BYTES,
  } = {},
) {
  const root = repositoryRoot(inputPath);
  const adapter = ADAPTERS[adapterName];
  if (!adapter) throw new Error(`unsupported adapter: ${adapterName}`);
  if (!existsSync(join(root, adapter.marker))) {
    throw new Error(`${adapterName} adapter did not find ${adapter.marker}`);
  }
  if (adapter.requiresProjectCodeApproval && !allowProjectCode) {
    throw new Error(`${adapter.approvalReason}; pass --allow-project-code after review`);
  }
  const invocation = adapter.build(root);
  const environment = { ...process.env, ...adapter.environment };
  const probe = invocation
    ? probeExecutable(invocation.command, environment, invocation.versionArguments)
    : { available: false, version: null };
  if (!invocation || !probe.available) {
    throw new Error(`${adapterName} analyzer is not installed or not available offline`);
  }
  const result = spawnSync(invocation.command, invocation.argumentsList, {
    cwd: root,
    encoding: "utf8",
    env: environment,
    maxBuffer: maxBufferBytes,
    shell: false,
    timeout: timeoutMs,
    windowsHide: true,
  });
  if (result.error?.code === "ETIMEDOUT") {
    throw new Error(`${adapterName} analyzer timed out without usable evidence`);
  }
  if (result.error?.code === "ENOBUFS") {
    throw new Error(`${adapterName} analyzer exceeded the output cap without usable evidence`);
  }
  if (result.error) throw new Error(`${adapterName} analyzer failed without usable evidence`);
  if (result.signal || result.status === null) {
    throw new Error(`${adapterName} analyzer terminated without usable evidence`);
  }
  const bounded = boundedDiagnostics(result.stdout, result.stderr);
  const diagnostics = bounded.diagnostics;
  if (
    result.status !== 0
    && !adapter.diagnosticExitCodes?.includes(result.status)
  ) {
    throw new Error(`${adapterName} analyzer failed with exit code ${result.status}`);
  }
  if (result.status !== 0 && diagnostics.length === 0) {
    throw new Error(`${adapterName} analyzer failed without diagnostics`);
  }
  const passed = result.status === 0;
  return {
    schema_version: "1.0",
    tool: { name: "ShipProof", version: VERSION, command: "evidence" },
    verdict: passed ? "PASS_WITH_EVIDENCE" : "BLOCK",
    root,
    adapter: adapterName,
    analyzer: adapterName === "typescript" ? "tsc" : basename(invocation.command),
    analyzer_version: probe.version,
    process_exit_code: result.status,
    passed,
    diagnostics,
    diagnostics_truncated: bounded.truncated,
    severity_counts: classifyDiagnostics(diagnostics),
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
    const adapters = discoverEvidenceAdapters(parsed.path, {
      allowProjectCode: parsed.allowProjectCode,
    });
    if (parsed.list) {
      if (parsed.format === "json") console.log(JSON.stringify(adapters, null, 2));
      else for (const adapter of adapters) {
        const state = adapter.approval_required
          ? "approval required"
          : adapter.detected && adapter.available ? "ready" : "unavailable";
        console.log(`${adapter.name}: ${state}`);
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

export const internals = {
  ADAPTERS,
  classifyDiagnostics,
  redactDiagnosticLine,
  bounds: {
    adapter_timeout_ms: ADAPTER_TIMEOUT_MS,
    max_buffer_bytes: ADAPTER_MAX_BUFFER_BYTES,
    max_diagnostic_lines: MAX_DIAGNOSTIC_LINES,
    max_diagnostic_line_chars: MAX_DIAGNOSTIC_LINE_CHARS,
  },
};
