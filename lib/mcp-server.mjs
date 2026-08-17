import { spawn, spawnSync } from "node:child_process";
import { join, resolve } from "node:path";

import { PACKAGE_ROOT, VERSION } from "./package-info.mjs";
import { resolveRepositoryPath } from "./safe-path.mjs";
const MAX_OUTPUT_BYTES = 2_000_000;
const TOOL_TIMEOUT_MS = 30_000;

const PYTHON_SCRIPTS = Object.freeze({
  scan: "skills/audit-production-readiness/scripts/scan_repo.py",
  budget: "skills/engineer-production-systems/scripts/check_budget.py",
  capacity: "skills/audit-production-readiness/scripts/capacity_model.py",
});

export { resolveRepositoryPath } from "./safe-path.mjs";

function detectPythonRuntime() {
  const candidates = [];
  if (process.env.SHIPPROOF_PYTHON) candidates.push([process.env.SHIPPROOF_PYTHON, []]);
  if (process.platform === "win32") candidates.push(["py", ["-3"]]);
  candidates.push(["python3", []], ["python", []]);
  for (const [command, prefix] of candidates) {
    const result = spawnSync(command, [...prefix, "--version"], {
      encoding: "utf8",
      shell: false,
      windowsHide: true,
    });
    const version = `${result.stdout || ""}${result.stderr || ""}`;
    const match = /Python\s+(\d+)\.(\d+)/.exec(version);
    if (
      result.status === 0
      && match
      && (Number(match[1]) > 3 || (Number(match[1]) === 3 && Number(match[2]) >= 10))
    ) {
      return { command, prefix };
    }
  }
  throw new Error("Python 3.10+ is required for ShipProof MCP tools");
}

export function buildPythonInvocation(command, argumentsList) {
  const script = PYTHON_SCRIPTS[command];
  if (!script) throw new Error("unsupported ShipProof tool");
  if (!Array.isArray(argumentsList) || argumentsList.some((value) => typeof value !== "string")) {
    throw new Error("tool arguments must be strings");
  }
  return [join(PACKAGE_ROOT, script), ...argumentsList];
}

function runPythonJson(command, argumentsList, abortSignal) {
  const python = detectPythonRuntime();
  const invocation = buildPythonInvocation(command, argumentsList);
  return new Promise((resolvePromise, rejectPromise) => {
    if (abortSignal?.aborted) {
      rejectPromise(new Error("tool call was cancelled"));
      return;
    }
    const child = spawn(python.command, [...python.prefix, ...invocation], {
      shell: false,
      windowsHide: true,
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
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
      finish(new Error("tool call exceeded the 30 second limit"));
    }, TOOL_TIMEOUT_MS);
    abortSignal?.addEventListener("abort", onAbort, { once: true });

    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk) => {
      stdout += chunk;
      if (Buffer.byteLength(stdout) > MAX_OUTPUT_BYTES) {
        child.kill();
        finish(new Error("tool output exceeded the 2 MB limit"));
      }
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk;
      if (Buffer.byteLength(stderr) > MAX_OUTPUT_BYTES) {
        child.kill();
        finish(new Error("tool diagnostics exceeded the 2 MB limit"));
      }
    });
    child.on("error", (error) => finish(error));
    child.on("close", (status) => {
      if (settled) return;
      try {
        const report = JSON.parse(stdout);
        if (!report || typeof report !== "object" || Array.isArray(report)) {
          throw new Error("tool returned an invalid evidence envelope");
        }
        if (status !== 0 && status !== 1) {
          throw new Error(stderr.trim() || `tool exited with status ${status}`);
        }
        finish(null, report);
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        finish(new Error(`could not parse tool result: ${message}`));
      }
    });
  });
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

  const repositoryRoot = process.env.SHIPPROOF_MCP_ROOT || process.cwd();
  resolveRepositoryPath(repositoryRoot, ".", "directory");
  const server = new McpServer({ name: "shipproof", version: VERSION });
  const annotations = {
    readOnlyHint: true,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: false,
  };
  const outputSchema = {
    schema_version: z.literal("1.0"),
    tool: z.object({
      name: z.literal("ShipProof"),
      version: z.string(),
      command: z.string(),
    }),
    verdict: z.enum(["PASS", "PASS_WITH_EVIDENCE", "CONDITIONAL", "WARN", "BLOCK"]),
    limitations: z.array(z.string()),
  };

  server.registerTool(
    "shipproof_scan",
    {
      description: "Run ShipProof's deterministic repository scanner without executing project code.",
      inputSchema: {
        path: z.string().default("."),
        fail_on: z.enum(["critical", "high", "medium", "low", "none"]).default("high"),
        max_file_bytes: z.number().int().min(1024).max(100_000_000).default(1_000_000),
      },
      outputSchema,
      annotations,
    },
    async ({ path, fail_on, max_file_bytes }, extra) => {
      try {
        const target = resolveRepositoryPath(repositoryRoot, path, "directory");
        const report = await runPythonJson(
          "scan",
          [target, "--format", "json", "--fail-on", fail_on, "--max-file-bytes", String(max_file_bytes)],
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
      outputSchema,
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
      outputSchema,
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
      },
      annotations,
    },
    async ({ rule_id, format = "text" }) => {
      try {
        const python = detectPythonRuntime();
        const args = ["--explain", rule_id];
        if (format === "json") args.push("--format", "json");
        const invocation = buildPythonInvocation("scan", args);
        const result = spawnSync(python.command, [...python.prefix, ...invocation], {
          encoding: "utf8",
          shell: false,
          windowsHide: true,
        });
        return {
          content: [{ type: "text", text: result.stdout || result.stderr || "No explanation found." }],
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
        code: z.string(),
        filename: z.string().default("snippet.py"),
      },
      outputSchema,
      annotations,
    },
    async ({ code, filename }, extra) => {
      try {
        const report = await runPythonJson(
          "scan",
          [".", "--snippet", code, "--snippet-file", filename, "--format", "json"],
          extra.signal,
        );
        return toolSuccess(report);
      } catch (error) {
        return toolFailure(error);
      }
    },
  );

  await server.connect(new StdioServerTransport());
}

export const internals = { runPythonJson };

if (process.argv.includes("--help")) {
  console.log("Usage: shipproof mcp\n\nStarts the read-only ShipProof MCP server over stdio.");
} else if (process.argv[1] && resolve(process.argv[1]) === resolve(PACKAGE_ROOT, "lib/mcp-server.mjs")) {
  startMcpServer().catch((error) => {
    const message = error instanceof Error ? error.message : String(error);
    console.error(`shipproof-mcp: ${message}`);
    process.exitCode = 2;
  });
}
