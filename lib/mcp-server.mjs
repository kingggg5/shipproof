import { spawn } from "node:child_process";
import { join, resolve } from "node:path";

import { PACKAGE_ROOT, VERSION } from "./package-info.mjs";
import { resolveRepositoryPath } from "./safe-path.mjs";
import { detectPythonRuntime } from "./runtime.mjs";

const MAX_OUTPUT_BYTES = 2_000_000;
const MAX_SNIPPET_CHARS = 200_000;
const MAX_SNIPPET_BYTES = 200_000;
const DEFAULT_TOOL_TIMEOUT_MS = 30_000;
const MIN_TOOL_TIMEOUT_MS = 1_000;
const MAX_TOOL_TIMEOUT_MS = 600_000;

function resolveNonNegativeIntEnv(name, fallback, maximum) {
  const raw = process.env[name];
  if (raw === undefined) return fallback;
  const value = Number(raw);
  if (!Number.isSafeInteger(value) || value < 0 || value > maximum) {
    throw new Error(`${name} must be an integer from 0 through ${maximum}`);
  }
  return value;
}

function resolveToolTimeoutMs() {
  const raw = process.env.SHIPPROOF_MCP_TIMEOUT_MS;
  if (raw === undefined) return DEFAULT_TOOL_TIMEOUT_MS;
  const value = Number(raw);
  if (!Number.isSafeInteger(value) || value < MIN_TOOL_TIMEOUT_MS || value > MAX_TOOL_TIMEOUT_MS) {
    throw new Error(
      `SHIPPROOF_MCP_TIMEOUT_MS must be an integer from ${MIN_TOOL_TIMEOUT_MS} through ${MAX_TOOL_TIMEOUT_MS}`,
    );
  }
  return value;
}

const TOOL_TIMEOUT_MS = resolveToolTimeoutMs();
// Optional short-lived scan result cache, off by default (0). Scan tools are
// declared idempotent; a TTL keeps repeated IDE calls cheap without serving
// results older than the configured window.
const MCP_CACHE_MS = resolveNonNegativeIntEnv("SHIPPROOF_MCP_CACHE_MS", 0, 3_600_000);
const scanResultCache = new Map();

async function runPythonJsonCached(command, argumentsList, abortSignal) {
  if (MCP_CACHE_MS <= 0 || command !== "scan") {
    return runPythonJson(command, argumentsList, abortSignal);
  }
  const key = JSON.stringify(argumentsList);
  const cached = scanResultCache.get(key);
  if (cached && cached.expiresAt > Date.now()) return cached.report;
  const report = await runPythonJson(command, argumentsList, abortSignal);
  scanResultCache.set(key, { report, expiresAt: Date.now() + MCP_CACHE_MS });
  if (scanResultCache.size > 16) scanResultCache.delete(scanResultCache.keys().next().value);
  return report;
}

const PYTHON_SCRIPTS = Object.freeze({
  scan: "skills/audit-production-readiness/scripts/scan_repo.py",
  budget: "skills/engineer-production-systems/scripts/check_budget.py",
  capacity: "skills/audit-production-readiness/scripts/capacity_model.py",
});

export { resolveRepositoryPath } from "./safe-path.mjs";

export function buildScanArguments({
  path,
  fail_on = "high",
  max_file_bytes = 1_000_000,
  exclude = [],
  min_confidence = undefined,
  cross_file = false,
}) {
  const argumentsList = [
    path,
    "--format",
    "json",
    "--fail-on",
    fail_on,
    "--max-file-bytes",
    String(max_file_bytes),
  ];
  for (const pattern of exclude) {
    if (
      typeof pattern !== "string"
      || !pattern
      || pattern.length > 512
      || /[\0\r\n]/.test(pattern)
    ) {
      throw new Error("exclude patterns must be plain repository-relative globs");
    }
    argumentsList.push("--exclude", pattern);
  }
  if (min_confidence !== undefined) {
    if (!["high", "medium", "low"].includes(min_confidence)) {
      throw new Error("min_confidence must be high, medium, or low");
    }
    argumentsList.push("--min-confidence", min_confidence);
  }
  if (cross_file) argumentsList.push("--cross-file");
  return argumentsList;
}

export function buildPythonInvocation(command, argumentsList) {
  const script = PYTHON_SCRIPTS[command];
  if (!script) throw new Error("unsupported ShipProof tool");
  if (!Array.isArray(argumentsList) || argumentsList.some((value) => typeof value !== "string")) {
    throw new Error("tool arguments must be strings");
  }
  return [join(PACKAGE_ROOT, script), ...argumentsList];
}

function runPythonProcess(command, argumentsList, { abortSignal, stdin } = {}) {
  const python = detectPythonRuntime();
  if (!python) {
    return Promise.reject(new Error("Python 3.10+ is required for ShipProof MCP tools"));
  }
  const invocation = buildPythonInvocation(command, argumentsList);
  return new Promise((resolvePromise, rejectPromise) => {
    if (abortSignal?.aborted) {
      rejectPromise(new Error("tool call was cancelled"));
      return;
    }
    const child = spawn(python.command, [...python.argumentPrefix, ...invocation], {
      shell: false,
      windowsHide: true,
      stdio: [stdin === undefined ? "ignore" : "pipe", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    let stdoutBytes = 0;
    let stderrBytes = 0;
    let settled = false;

    const finish = (error, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      abortSignal?.removeEventListener("abort", onAbort);
      if (error) rejectPromise(error);
      else resolvePromise(value);
    };
    const onAbort = () => {
      child.kill();
      finish(new Error("tool call was cancelled"));
    };
    const timeout = setTimeout(() => {
      child.kill();
      finish(new Error(`tool call exceeded the ${TOOL_TIMEOUT_MS / 1000} second limit`));
    }, TOOL_TIMEOUT_MS);
    abortSignal?.addEventListener("abort", onAbort, { once: true });

    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk) => {
      stdoutBytes += Buffer.byteLength(chunk);
      stdout += chunk;
      if (stdoutBytes > MAX_OUTPUT_BYTES) {
        child.kill();
        finish(new Error("tool output exceeded the 2 MB limit"));
      }
    });
    child.stderr.on("data", (chunk) => {
      stderrBytes += Buffer.byteLength(chunk);
      stderr += chunk;
      if (stderrBytes > MAX_OUTPUT_BYTES) {
        child.kill();
        finish(new Error("tool diagnostics exceeded the 2 MB limit"));
      }
    });
    child.on("error", (error) => finish(error));
    child.on("close", (status) => {
      if (settled) return;
      finish(null, { status, stdout, stderr });
    });
    if (stdin !== undefined) {
      child.stdin.on("error", (error) => finish(error));
      child.stdin.end(stdin, "utf8");
    }
  });
}

async function runPythonJson(command, argumentsList, abortSignal, options = {}) {
  const { status, stdout, stderr } = await runPythonProcess(command, argumentsList, {
    abortSignal,
    stdin: options.stdin,
  });
  if (status !== 0 && status !== 1) {
    throw new Error(
      stderr.trim()
        || `tool was terminated before producing a result (status ${status ?? "unknown"})`,
    );
  }
  try {
    const report = JSON.parse(stdout);
    if (!report || typeof report !== "object" || Array.isArray(report)) {
      throw new Error("tool returned an invalid JSON object");
    }
    return report;
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    const diagnostics = stderr.trim();
    throw new Error(
      `could not parse tool result: ${message}${diagnostics ? `; ${diagnostics}` : ""}`,
    );
  }
}

function toolSuccess(report) {
  return {
    content: [{ type: "text", text: JSON.stringify(report, null, 2) }],
    structuredContent: report,
  };
}

function toolFailure(error) {
  const message = error instanceof Error ? error.message : String(error);
  return { content: [{ type: "text", text: `ShipProof tool error: ${message}` }], isError: true };
}

export function buildMcpOutputSchemas(z) {
  const tool = z.object({
    name: z.literal("ShipProof"),
    version: z.string(),
    command: z.string(),
  });
  const verdict = z.enum(["PASS", "PASS_WITH_EVIDENCE", "CONDITIONAL", "WARN", "BLOCK"]);
  const common = {
    schema_version: z.literal("1.0"),
    tool,
    verdict,
    limitations: z.array(z.string()),
  };
  const explainDetails = z.object({
    context_level: z.enum(["summary", "overview", "full"]),
    rule_id: z.string(),
    title: z.string(),
    category: z.string(),
    severity: z.string(),
    confidence: z.string(),
    cwe: z.string().optional(),
    owasp: z.string().optional(),
    message: z.string(),
    remediation: z.string(),
    why: z.string().optional(),
    attack: z.string().optional(),
    false_positive: z.string().optional(),
    test: z.string().optional(),
    engineering_dimensions: z.array(z.string()).optional(),
    implicit_requirements: z.array(z.string()).optional(),
    failure_scenarios: z.array(z.string()).optional(),
  });
  return {
    scan: {
      ...common,
      root: z.string(),
      summary: z.record(z.string(), z.unknown()),
      findings: z.array(z.record(z.string(), z.unknown())),
    },
    budget: {
      ...common,
      passed: z.boolean(),
      results: z.array(z.record(z.string(), z.unknown())),
      artifacts: z.array(z.record(z.string(), z.unknown())).optional(),
    },
    capacity: {
      ...common,
      inputs: z.record(z.string(), z.unknown()),
      derived: z.record(z.string(), z.unknown()),
      load_test_stages: z.array(z.record(z.string(), z.unknown())),
      required_evidence: z.array(z.string()),
      warning: z.string(),
    },
    explain: {
      format: z.enum(["text", "json"]),
      context_level: z.enum(["summary", "overview", "full"]),
      rule_id: z.string(),
      explanation: z.string(),
      details: explainDetails.optional(),
    },
  };
}

export async function startMcpServer() {
  let McpServer;
  let StdioServerTransport;
  let z;
  try {
    ({ McpServer } = await import("@modelcontextprotocol/sdk/server/mcp.js"));
    ({ StdioServerTransport } = await import("@modelcontextprotocol/sdk/server/stdio.js"));
    ({ z } = await import("zod"));
  } catch {
    throw new Error("MCP support is unavailable; reinstall ShipProof with optional dependencies enabled");
  }

  const repositoryRoot = resolveRepositoryPath(
    process.env.SHIPPROOF_MCP_ROOT || process.cwd(),
    ".",
    "directory",
  );
  const server = new McpServer({ name: "shipproof", version: VERSION });
  const annotations = {
    readOnlyHint: true,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: false,
  };
  const outputSchemas = buildMcpOutputSchemas(z);

  server.registerTool(
    "shipproof_scan",
    {
      description: "Run ShipProof's deterministic repository scanner without executing project code.",
      inputSchema: {
        path: z.string().default("."),
        fail_on: z.enum(["critical", "high", "medium", "low", "none"]).default("high"),
        max_file_bytes: z.number().int().min(1024).max(100_000_000).default(1_000_000),
        exclude: z
          .array(z.string().min(1).max(512).regex(/^[^\0\r\n]+$/u))
          .max(100)
          .default([]),
        min_confidence: z.enum(["high", "medium", "low"]).optional(),
        cross_file: z.boolean().default(false),
      },
      outputSchema: outputSchemas.scan,
      annotations,
    },
    async (input, extra) => {
      try {
        const target = resolveRepositoryPath(repositoryRoot, input.path, "directory");
        const report = await runPythonJsonCached(
          "scan",
          buildScanArguments({ ...input, path: target }),
          extra.signal,
        );
        return toolSuccess(report);
      } catch (error) {
        return toolFailure(error);
      }
    },
  );

  server.registerTool(
    "shipproof_budget",
    {
      description: "Compare existing benchmark JSON files against reviewed resource budgets.",
      inputSchema: {
        baseline: z.string().min(1),
        current: z.string().min(1),
        budget: z.string().min(1),
      },
      outputSchema: outputSchemas.budget,
      annotations,
    },
    async ({ baseline, current, budget }, extra) => {
      try {
        const paths = [baseline, current, budget].map((value) =>
          resolveRepositoryPath(repositoryRoot, value, "file")
        );
        const report = await runPythonJson(
          "budget",
          ["--baseline", paths[0], "--current", paths[1], "--budget", paths[2], "--format", "json"],
          extra.signal,
        );
        return toolSuccess(report);
      } catch (error) {
        return toolFailure(error);
      }
    },
  );

  const optionalPositive = z.number().finite().positive().optional();
  server.registerTool(
    "shipproof_capacity",
    {
      description: "Build a capacity hypothesis from explicit, reviewable workload inputs.",
      inputSchema: {
        users: z.number().int().positive(),
        dau_ratio: z.number().min(0).max(1).optional(),
        peak_hour_ratio: z.number().min(0).max(1).optional(),
        actions_per_session: optionalPositive,
        requests_per_action: optionalPositive,
        burst_multiplier: optionalPositive,
        p95_latency_ms: optionalPositive,
        instance_rps: optionalPositive,
        headroom: z.number().min(1).optional(),
      },
      outputSchema: outputSchemas.capacity,
      annotations,
    },
    async (input, extra) => {
      try {
        const argumentsList = ["--users", String(input.users), "--format", "json"];
        const fields = {
          dau_ratio: "--dau-ratio",
          peak_hour_ratio: "--peak-hour-ratio",
          actions_per_session: "--actions-per-session",
          requests_per_action: "--requests-per-action",
          burst_multiplier: "--burst-multiplier",
          p95_latency_ms: "--p95-latency-ms",
          instance_rps: "--instance-rps",
          headroom: "--headroom",
        };
        for (const [field, flag] of Object.entries(fields)) {
          if (input[field] !== undefined) argumentsList.push(flag, String(input[field]));
        }
        return toolSuccess(await runPythonJson("capacity", argumentsList, extra.signal));
      } catch (error) {
        return toolFailure(error);
      }
    },
  );

  server.registerTool(
    "shipproof_explain",
    {
      description: "Get detailed threat scenario, false-positive analysis, and regression test guidance for a ShipProof rule (e.g. SP108, SP004, SP304).",
      inputSchema: {
        rule_id: z.string().min(1),
        format: z.enum(["text", "json"]).default("text"),
        context_level: z.enum(["summary", "overview", "full"]).default("full"),
      },
      outputSchema: outputSchemas.explain,
      annotations,
    },
    async ({ rule_id, format = "text", context_level = "full" }, extra) => {
      try {
        const args = ["--explain", rule_id, "--context-level", context_level];
        if (format === "json") args.push("--format", "json");
        const { status, stdout, stderr } = await runPythonProcess("scan", args, {
          abortSignal: extra.signal,
        });
        if (status !== 0) {
          throw new Error(stderr.trim() || `tool exited with status ${status}`);
        }
        const explanation = stdout.trim();
        if (!explanation) throw new Error("scanner returned an empty explanation");
        const report = { format, context_level, rule_id, explanation };
        if (format === "json") {
          const details = JSON.parse(explanation);
          if (!details || typeof details !== "object" || Array.isArray(details)) {
            throw new Error("scanner returned an invalid explanation object");
          }
          report.details = details;
        }
        return {
          content: [{ type: "text", text: explanation }],
          structuredContent: report,
        };
      } catch (error) {
        return toolFailure(error);
      }
    },
  );

  server.registerTool(
    "shipproof_lint_snippet",
    {
      description: "Lint an in-memory code snippet directly without saving to disk. Validates AI code before writing to files.",
      inputSchema: {
        code: z.string().max(MAX_SNIPPET_CHARS),
        filename: z
          .string()
          .min(1)
          .max(128)
          .regex(/^[^/\\\0\r\n]+$/u)
          .refine((value) => value !== "." && value !== "..", "invalid virtual filename")
          .default("snippet.py"),
      },
      outputSchema: outputSchemas.scan,
      annotations,
    },
    async ({ code, filename }, extra) => {
      try {
        if (Buffer.byteLength(code, "utf8") > MAX_SNIPPET_BYTES) {
          throw new Error(`snippet exceeds the ${MAX_SNIPPET_BYTES}-byte limit`);
        }
        const report = await runPythonJson(
          "scan",
          [repositoryRoot, "--snippet-stdin", "--snippet-file", filename, "--format", "json"],
          extra.signal,
          { stdin: code },
        );
        return toolSuccess(report);
      } catch (error) {
        return toolFailure(error);
      }
    },
  );

  await server.connect(new StdioServerTransport());
}

export const internals = { buildScanArguments, runPythonJson, runPythonProcess };

if (process.argv.includes("--help")) {
  console.log("Usage: shipproof mcp\n\nStarts the read-only ShipProof MCP server over stdio.");
} else if (process.argv[1] && resolve(process.argv[1]) === resolve(PACKAGE_ROOT, "lib/mcp-server.mjs")) {
  startMcpServer().catch((error) => {
    const message = error instanceof Error ? error.message : String(error);
    console.error(`shipproof-mcp: ${message}`);
    process.exitCode = 2;
  });
}
