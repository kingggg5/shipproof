import { cpSync, existsSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join, relative, resolve, sep } from "node:path";
import { spawnSync } from "node:child_process";

import { runEvidenceCli } from "./evidence.mjs";
import { PACKAGE_ROOT, VERSION } from "./package-info.mjs";
import { buildPolicyGates, defaultPolicy, loadPolicy, parsePolicyText, validatePolicy } from "./policy.mjs";
import { detectPythonRuntime, isSupportedPythonVersion } from "./runtime.mjs";

const INSTALL_TARGETS = new Set(["codex", "claude", "both"]);
const PROMPT_FILES = new Map([
  ["build", "build.md"],
  ["audit", "audit.md"],
  ["threat-model", "threat-model.md"],
  ["database", "database.md"],
  ["performance", "performance.md"],
  ["systems", "systems.md"],
  ["incident", "incident.md"],
  ["ai-agent", "ai-agent.md"],
  ["loop", "loop.md"],
]);

const HELP = `ShipProof ${VERSION} — zero-dependency production gate for AI-written code

Usage:
  shipproof [command] [options]
  (Running \`shipproof\` with no command runs the production gate on the current directory.)

Stable production gate:
  check [path] [--config <file>]     Run full production gate (scan + policy + contracts)
  scan [path] [scanner options]      Static security scan & AI fix prompts (--fix-prompt)
  explain <rule-id> [--context-level <level>]
                                     Explain a rule at summary, overview, or full detail

Policy evidence (normally invoked by check):
  gate budget [budget options]       Enforce CPU/RAM/latency resource budgets
  gate evidence [path] [options]     Run an allowlisted local analyzer

Experimental analysis (never treated as proof):
  labs impact <file>[:line]          Estimate blast radius and affected tests
  labs invariants [path]             Analyze auth, tenant, and transaction boundaries
  labs cost [path] [options]         Estimate agent token footprint and USD cost
  labs capacity [options]            Model capacity and generate k6 load tests

Setup & integration:
  mcp                                Start read-only stdio MCP server for AI IDEs
  init [path] [--scope <scope>]      Add project or global skills and a project policy
  config validate [path]             Validate .shipproof.yml without running gates
  doctor [path] [--json]             Inspect local environment readiness
  version / help                     Print version or help documentation

Scopes: project (default), global. Hosts: codex, claude, both.
Legacy aliases remain available until 1.0.0 but are hidden from this help output.
Python 3.10+ is required for scan, check, gate budget, labs commands, and MCP execution.`;

const PYTHON_COMMANDS = new Map([
  ["scan", "skills/audit-production-readiness/scripts/scan_repo.py"],
  ["budget", "skills/engineer-production-systems/scripts/check_budget.py"],
  ["capacity", "skills/audit-production-readiness/scripts/capacity_model.py"],
  ["impact", "skills/audit-production-readiness/scripts/impact_graph.py"],
  ["invariants", "skills/audit-production-readiness/scripts/invariants.py"],
  ["cost", "skills/audit-production-readiness/scripts/cost_model.py"],
  ["worktree", "skills/audit-production-readiness/scripts/worktree_manager.py"],
  ["benchmark", "benchmarks/benchmark_suite.py"],
]);

const LAB_COMMANDS = new Set(["impact", "invariants", "cost", "capacity"]);
const LEGACY_COMMAND_REPLACEMENTS = new Map([
  ["install", "shipproof init --scope global"],
  ["prompt", "shipproof init"],
  ["hook", "configure pre-commit to run shipproof check"],
  ["impact", "shipproof labs impact"],
  ["invariants", "shipproof labs invariants"],
  ["cost", "shipproof labs cost"],
  ["capacity", "shipproof labs capacity"],
  ["budget", "shipproof gate budget"],
  ["evidence", "shipproof gate evidence"],
  ["benchmark", "npm run benchmark"],
  ["worktree", "git worktree"],
]);

function legacyAliasesEnabled(version = VERSION) {
  const match = /^(\d+)\./.exec(version);
  return Boolean(match) && Number(match[1]) < 1;
}

function assertLegacyCommandAvailable(commandName, version = VERSION) {
  if (!legacyAliasesEnabled(version)) {
    throw new Error(
      `unknown command: ${commandName}; this legacy alias was removed in 1.0.0. Use \`${LEGACY_COMMAND_REPLACEMENTS.get(commandName)}\``,
    );
  }
}

const POLICY_TEMPLATE = `# ShipProof Production Gate Policy (.shipproof.yml)
# Schema: https://raw.githubusercontent.com/kingggg5/shipproof/main/schemas/shipproof-policy.schema.json

version: 1

scan:
  path: .
  exclude:
    - node_modules/**
    - dist/**
    - build/**
  max_file_bytes: 1000000

security:
  fail_on: high

# Optional performance evidence gate:
# performance:
#   baseline: examples/performance/baseline.json
#   current: examples/performance/current.json
#   budget: examples/performance/budget.json

# Optional capacity hypothesis:
# capacity:
#   config: examples/capacity/shipproof.config.json
`;

function readOptionValue(commandArguments, optionName, fallback) {
  const index = commandArguments.indexOf(optionName);
  if (index < 0) return fallback;
  if (!commandArguments[index + 1] || commandArguments[index + 1].startsWith("--")) {
    throw new Error(`${optionName} requires a value`);
  }
  return commandArguments[index + 1];
}

function readPositionalArgument(commandArguments, fallback = ".", optionsWithValues = ["--target"]) {
  const valueOptions = new Set(optionsWithValues);
  for (let index = 0; index < commandArguments.length; index += 1) {
    const value = commandArguments[index];
    if (valueOptions.has(value)) {
      index += 1;
      continue;
    }
    if (!value.startsWith("-")) return value;
  }
  return fallback;
}

function validateCommandArguments(commandArguments, { values = [], flags = [], maxPositionals = 1 } = {}) {
  const valueOptions = new Set(values);
  const flagOptions = new Set(flags);
  let positionals = 0;
  for (let index = 0; index < commandArguments.length; index += 1) {
    const value = commandArguments[index];
    if (valueOptions.has(value)) {
      if (!commandArguments[index + 1] || commandArguments[index + 1].startsWith("-")) {
        throw new Error(`${value} requires a value`);
      }
      index += 1;
    } else if (flagOptions.has(value)) {
      continue;
    } else if (value.startsWith("-")) {
      throw new Error(`unknown option: ${value}`);
    } else {
      positionals += 1;
    }
  }
  if (positionals > maxPositionals) throw new Error("too many positional arguments");
}

function listSkillNames() {
  return readdirSync(join(PACKAGE_ROOT, "skills"), { withFileTypes: true })
    .filter((entry) => entry.isDirectory() && existsSync(join(PACKAGE_ROOT, "skills", entry.name, "SKILL.md")))
    .map((entry) => entry.name)
    .sort();
}

function copySkillDirectory(sourcePath, destinationRoot, skillName, force) {
  const resolvedRoot = resolve(destinationRoot);
  const destinationPath = resolve(resolvedRoot, skillName);
  if (destinationPath === resolvedRoot || !destinationPath.startsWith(`${resolvedRoot}${sep}`)) {
    throw new Error(`unsafe skill destination: ${destinationPath}`);
  }
  if (existsSync(destinationPath)) {
    if (!force) return "skipped";
    rmSync(destinationPath, { recursive: true, force: true });
  }
  mkdirSync(resolvedRoot, { recursive: true });
  cpSync(sourcePath, destinationPath, { recursive: true, errorOnExist: true, force: false });
  return "installed";
}

function resolveSkillDestinations(target, scope, projectRoot) {
  const userHome = homedir();
  const destinations = {
    codex: scope === "project"
      ? join(projectRoot, ".agents", "skills")
      : process.env.SHIPPROOF_CODEX_SKILLS_DIR || join(userHome, ".agents", "skills"),
    claude: scope === "project"
      ? join(projectRoot, ".claude", "skills")
      : process.env.SHIPPROOF_CLAUDE_SKILLS_DIR || join(userHome, ".claude", "skills"),
  };
  return target === "both" ? Object.entries(destinations) : [[target, destinations[target]]];
}

export function installSkills({ target = "both", scope = "user", projectRoot = ".", force = false } = {}) {
  if (!INSTALL_TARGETS.has(target)) throw new Error(`unsupported target: ${target}`);
  const installationResults = [];
  for (const [hostName, destinationRoot] of resolveSkillDestinations(target, scope, resolve(projectRoot))) {
    for (const skillName of listSkillNames()) {
      const sourcePath = join(PACKAGE_ROOT, "skills", skillName);
      installationResults.push({
        host: hostName,
        name: skillName,
        path: join(resolve(destinationRoot), skillName),
        status: copySkillDirectory(sourcePath, destinationRoot, skillName, force),
      });
    }
  }
  return installationResults;
}

function runDoctorCommand(rootPath, useJsonOutput) {
  const repositoryRoot = resolve(rootPath);
  if (!existsSync(repositoryRoot) || !statSync(repositoryRoot).isDirectory()) {
    throw new Error(`not a directory: ${repositoryRoot}`);
  }
  const pythonRuntime = detectPythonRuntime();
  const pathExists = (...parts) => existsSync(join(repositoryRoot, ...parts));
  const hasCodexIntegration = pathExists(".agents", "skills") || pathExists(".codex-plugin") || pathExists("skills");
  const hasClaudeIntegration = pathExists(".claude", "skills") || pathExists(".claude-plugin") || pathExists("skills");
  const checks = [
    { id: "node", status: "pass", detail: process.version },
    { id: "python-gates", status: pythonRuntime ? "pass" : "warn", detail: pythonRuntime?.version || "Python 3.10+ not found" },
    { id: "source-control", status: pathExists(".git") ? "pass" : "warn", detail: pathExists(".git") ? "Git repository detected" : "No .git directory" },
    { id: "ci", status: pathExists(".github", "workflows") ? "pass" : "warn", detail: pathExists(".github", "workflows") ? "CI workflow directory detected" : "No GitHub Actions workflow directory" },
    { id: "security-policy", status: pathExists("SECURITY.md") ? "pass" : "warn", detail: pathExists("SECURITY.md") ? "Private reporting policy detected" : "SECURITY.md not found" },
    { id: "codex-skill", status: hasCodexIntegration ? "pass" : "warn", detail: hasCodexIntegration ? "Codex skill integration detected" : "No Codex skill integration" },
    { id: "claude-skill", status: hasClaudeIntegration ? "pass" : "warn", detail: hasClaudeIntegration ? "Claude skill integration detected" : "No Claude skill integration" },
    { id: "lockfile", status: ["package-lock.json", "pnpm-lock.yaml", "yarn.lock", "uv.lock", "poetry.lock", "Cargo.lock", "go.sum"].some((filename) => pathExists(filename)) ? "pass" : "warn", detail: "Reproducible dependency lock" },
  ];
  const report = {
    schema_version: "1.0",
    tool: { name: "ShipProof", version: VERSION, command: "doctor" },
    root: repositoryRoot,
    verdict: checks.some((check) => check.status === "warn") ? "WARN" : "PASS",
    checks,
    limitations: [
      "Doctor checks repository structure and local runtimes; it does not prove production readiness.",
    ],
  };
  if (useJsonOutput) console.log(JSON.stringify(report, null, 2));
  else {
    console.log(`ShipProof doctor: ${report.verdict}\n`);
    for (const check of checks) {
      console.log(`${check.status === "pass" ? "[ok]" : "[!!]"} ${check.id}: ${check.detail}`);
    }
    if (!pythonRuntime) {
      console.log("\n  -> To enable all static analysis and capacity gates, install Python 3.10+ (Download at https://www.python.org/downloads/):");
      if (process.platform === "darwin") console.log("     macOS: brew install python");
      else if (process.platform === "win32") console.log("     Windows: winget install Python.Python.3.13");
      else console.log("     Linux: sudo apt-get install python3 python3-pip");
    }
  }
  return report.verdict === "PASS" ? 0 : 1;
}

function runPythonCommand(scriptPath, commandArguments) {
  const pythonRuntime = detectPythonRuntime();
  if (!pythonRuntime) {
    console.error("shipproof: Python 3.10+ is required for this command. Run `shipproof doctor` for details.");
    return 2;
  }
  const processResult = spawnSync(pythonRuntime.command, [
    ...pythonRuntime.argumentPrefix,
    join(PACKAGE_ROOT, scriptPath),
    ...commandArguments,
  ], {
    stdio: "inherit",
    shell: false,
    windowsHide: true,
  });
  if (processResult.error) {
    console.error(`shipproof: ${processResult.error.message}`);
    return 2;
  }
  const status = processResult.status;
  // The scanner contract defines only 0 (pass), 1 (gate failure), and
  // 2 (invalid evidence). Crash codes (including Windows NTSTATUS values)
  // must never masquerade as a security block.
  if (status === 0 || status === 1 || status === 2) return status;
  if (status !== null) {
    console.error(
      `shipproof: ${scriptPath} exited with status ${status}; treating it as invalid evidence (exit 2)`,
    );
  }
  return 2;
}

const HOOK_MARKER = "# shipproof-managed-pre-commit-hook";

function gitOutput(repositoryRoot, argumentsList, { allowMissing = false } = {}) {
  const result = spawnSync("git", ["-C", repositoryRoot, ...argumentsList], {
    encoding: "utf8",
    shell: false,
    windowsHide: true,
  });
  if (result.error) throw result.error;
  if (result.status !== 0) {
    if (allowMissing && result.status === 1) return "";
    throw new Error((result.stderr || result.stdout || "git command failed").trim());
  }
  return result.stdout.trim();
}

function resolveGitHooksDirectory(repositoryRoot) {
  if (gitOutput(repositoryRoot, ["rev-parse", "--is-inside-work-tree"]) !== "true") {
    throw new Error("not a git worktree");
  }
  const configuredPath = gitOutput(
    repositoryRoot,
    ["config", "--path", "--get", "core.hooksPath"],
    { allowMissing: true },
  );
  const hooksPath =
    configuredPath || gitOutput(repositoryRoot, ["rev-parse", "--git-path", "hooks"]);
  return resolve(repositoryRoot, hooksPath);
}

function isShipProofManagedHook(content) {
  const normalized = content.replaceAll("\r\n", "\n");
  return normalized.startsWith(`#!/bin/sh\n${HOOK_MARKER}\n`);
}

function runHookCommand(commandArguments, { repositoryRoot = process.cwd() } = {}) {
  const action = commandArguments[0] || "install";
  if (!["install", "remove"].includes(action)) {
    throw new Error("usage: shipproof hook [install|remove]");
  }
  const hooksDir = resolveGitHooksDirectory(repositoryRoot);
  if (!existsSync(hooksDir)) {
    mkdirSync(hooksDir, { recursive: true });
  }
  const hookFile = join(hooksDir, "pre-commit");
  if (action === "install") {
    if (existsSync(hookFile) && !isShipProofManagedHook(readFileSync(hookFile, "utf8"))) {
      throw new Error(
        ".git/hooks/pre-commit already exists and was not installed by shipproof; remove it manually before installing",
      );
    }
    const preCommitHook = `#!/bin/sh
${HOOK_MARKER}
# Run the local scanner on staged files before allowing a commit.
if command -v shipproof >/dev/null 2>&1; then
  shipproof check . || exit 1
else
  node "${join(PACKAGE_ROOT, "bin", "shipproof.mjs")}" check . || exit 1
fi
`;
    writeFileSync(hookFile, preCommitHook, { encoding: "utf8", mode: 0o755 });
    console.log(`shipproof: installed pre-commit hook at ${hookFile}`);
    return 0;
  }
  if (action === "remove") {
    if (!existsSync(hookFile)) {
      console.log("shipproof: no pre-commit hook found");
      return 0;
    }
    if (!isShipProofManagedHook(readFileSync(hookFile, "utf8"))) {
      console.log("shipproof: existing pre-commit hook was not installed by shipproof; left unchanged");
      return 0;
    }
    rmSync(hookFile);
    console.log("shipproof: removed .git/hooks/pre-commit");
    return 0;
  }
  return 0;
}

function resolvePositiveIntEnv(name, fallback, minimum = 1, environment = process.env) {
  const raw = environment[name];
  if (raw === undefined) return fallback;
  const value = Number(raw);
  if (!Number.isSafeInteger(value) || value < minimum) {
    throw new Error(`${name} must be an integer >= ${minimum}`);
  }
  return value;
}

function resolveGateLimits(environment = process.env) {
  return {
    timeoutMs: resolvePositiveIntEnv("SHIPPROOF_GATE_TIMEOUT_MS", 60_000, 1_000, environment),
    maxBufferBytes: resolvePositiveIntEnv(
      "SHIPPROOF_MAX_BUFFER_BYTES",
      16_000_000,
      65_536,
      environment,
    ),
  };
}

function describeGateSpawnError(scriptPath, error, limits) {
  if (error?.code === "ETIMEDOUT" || /timed?\s?out/i.test(String(error?.message || ""))) {
    return `policy gate \`${scriptPath}\` exceeded the ${limits.timeoutMs} ms timeout; set SHIPPROOF_GATE_TIMEOUT_MS to adjust`;
  }
  if (/maxBuffer/i.test(String(error?.message || ""))) {
    return `policy gate \`${scriptPath}\` exceeded the ${limits.maxBufferBytes} byte output limit; set SHIPPROOF_MAX_BUFFER_BYTES to adjust`;
  }
  return `policy gate \`${scriptPath}\` failed to run: ${error?.message || "unknown spawn error"}`;
}

function runPythonJsonCommand(scriptPath, commandArguments, spawnImpl = spawnSync) {
  const limits = resolveGateLimits();
  const pythonRuntime = detectPythonRuntime();
  if (!pythonRuntime) throw new Error("Python 3.10+ is required for policy gates");
  const processResult = spawnImpl(pythonRuntime.command, [
    ...pythonRuntime.argumentPrefix,
    join(PACKAGE_ROOT, scriptPath),
    ...commandArguments,
  ], {
    encoding: "utf8",
    maxBuffer: limits.maxBufferBytes,
    shell: false,
    timeout: limits.timeoutMs,
    windowsHide: true,
  });
  if (processResult.error) {
    throw new Error(describeGateSpawnError(scriptPath, processResult.error, limits));
  }
  if (processResult.status === null || processResult.signal) {
    throw new Error(
      `policy gate \`${scriptPath}\` was terminated (signal ${processResult.signal || "unknown"}); `
        + `it likely exceeded the ${limits.timeoutMs} ms timeout`,
    );
  }
  const status = processResult.status;
  if (status > 1) {
    throw new Error(
      (processResult.stderr || processResult.stdout || `policy gate exited with status ${status}`).trim(),
    );
  }
  try {
    return { status, report: JSON.parse(processResult.stdout) };
  } catch {
    throw new Error(`policy gate \`${scriptPath}\` returned invalid JSON`);
  }
}

function formatCheckReport(report) {
  const lines = [
    `# ShipProof policy: ${report.verdict}`,
    "",
    "| Gate | Status | Evidence verdict |",
    "| --- | --- | --- |",
  ];
  for (const gate of report.gates) {
    lines.push(`| ${gate.name} | ${gate.status.toUpperCase()} | ${gate.verdict} |`);
  }
  lines.push("", `Policy: \`${report.policy_path}\``);
  return lines.join("\n");
}

function detectProjectContext(repositoryRoot) {
  const pathExists = (...parts) => existsSync(join(repositoryRoot, ...parts));
  const detected = [];
  if (pathExists("package.json")) detected.push("Node.js");
  if (pathExists("pyproject.toml") || pathExists("setup.py") || pathExists("requirements.txt")) detected.push("Python");
  if (pathExists("go.mod")) detected.push("Go");
  if (pathExists("Cargo.toml")) detected.push("Rust");
  if (pathExists("tsconfig.json")) detected.push("TypeScript");
  if (pathExists(".github", "workflows")) detected.push("GitHub Actions");
  if (pathExists("Dockerfile") || pathExists("docker-compose.yml") || pathExists("docker-compose.yaml")) detected.push("Docker");
  return detected;
}

function runCheckCommand(rootPath, commandArguments) {
  const repositoryRoot = resolve(rootPath);
  if (!existsSync(repositoryRoot) || !statSync(repositoryRoot).isDirectory()) {
    throw new Error(`not a directory: ${repositoryRoot}`);
  }
  const requestedPolicyPath = readOptionValue(commandArguments, "--config", ".shipproof.yml");
  const hasExplicitConfig = commandArguments.includes("--config");
  const format = readOptionValue(commandArguments, "--format", "markdown");
  if (!new Set(["json", "markdown"]).has(format)) {
    throw new Error("--format must be json or markdown");
  }

  const loaded = loadPolicy(repositoryRoot, requestedPolicyPath, { allowMissing: !hasExplicitConfig });
  let policy, policyPath;
  if (loaded) {
    policy = loaded.policy;
    policyPath = loaded.path;
  } else {
    policy = defaultPolicy();
    policyPath = "(default)";
    const detected = detectProjectContext(repositoryRoot);
    console.error(`shipproof: no .shipproof.yml found — using default policy (scan + fail-on high)`);
    if (detected.length) {
      console.error(`shipproof: detected: ${detected.join(", ")}`);
    }
  }

  const gates = buildPolicyGates(repositoryRoot, policy).map((gate) => {
    const scriptPath = PYTHON_COMMANDS.get(gate.command);
    if (!scriptPath) throw new Error(`unsupported policy gate: ${gate.command}`);
    const result = runPythonJsonCommand(scriptPath, gate.argumentsList);
    return {
      name: gate.name,
      status: result.status === 0 ? "pass" : "fail",
      verdict: result.report.verdict || "UNKNOWN",
      evidence: result.report,
    };
  });
  const passed = gates.every((gate) => gate.status === "pass");
  const report = {
    schema_version: "1.0",
    tool: { name: "ShipProof", version: VERSION, command: "check" },
    root: repositoryRoot,
    policy_path: policyPath,
    verdict: passed ? "PASS_WITH_EVIDENCE" : "BLOCK",
    passed,
    gates,
    limitations: [
      "A passing policy proves only the declared deterministic gates; deployment still requires human review.",
    ],
  };
  console.log(format === "json" ? JSON.stringify(report, null, 2) : formatCheckReport(report));
  return passed ? 0 : 1;
}

function runMcpServer() {
  const processResult = spawnSync(process.execPath, [join(PACKAGE_ROOT, "lib/mcp-server.mjs")], {
    stdio: "inherit",
    shell: false,
    windowsHide: true,
  });
  if (processResult.error) {
    console.error(`shipproof: ${processResult.error.message}`);
    return 2;
  }
  return processResult.status === 0 ? 0 : 2;
}

function printInstallationSummary(installationResults, scope) {
  for (const installation of installationResults) {
    console.log(`${installation.status}: ${installation.host}/${installation.name} -> ${installation.path}`);
  }
  console.log(scope === "project" ? "Project skills are ready for source control review." : "Personal skills are ready. Restart the host only if it does not detect them.");
}

function printPrompt(promptName) {
  if (promptName === "list" || !promptName) {
    console.log([...PROMPT_FILES.keys()].join("\n"));
    return 0;
  }
  const filename = PROMPT_FILES.get(promptName);
  if (!filename) throw new Error(`unknown prompt: ${promptName}. Run \`shipproof prompt list\`.`);
  console.log(readFileSync(join(PACKAGE_ROOT, "prompts", filename), "utf8").trim());
  return 0;
}

function parseInstallOptions(commandArguments) {
  const target = readOptionValue(commandArguments, "--target", "both");
  if (!INSTALL_TARGETS.has(target)) throw new Error("--target must be codex, claude, or both");
  const force = commandArguments.includes("--force");
  return { target, force };
}

function warnLegacyCommand(commandName, replacement) {
  console.error(
    `shipproof: warning: \`shipproof ${commandName}\` is a legacy alias scheduled for removal in 1.0.0; use \`${replacement}\` instead`,
  );
}

function runLabsCommand(commandArguments) {
  const [labName, ...labArguments] = commandArguments;
  if (!LAB_COMMANDS.has(labName)) {
    throw new Error("usage: shipproof labs <impact|invariants|cost|capacity> [options]");
  }
  return runPythonCommand(PYTHON_COMMANDS.get(labName), labArguments);
}

function runGateCommand(commandArguments) {
  const [gateName, ...gateArguments] = commandArguments;
  if (gateName === "budget") return runPythonCommand(PYTHON_COMMANDS.get("budget"), gateArguments);
  if (gateName === "evidence") return runEvidenceCli(gateArguments);
  throw new Error("usage: shipproof gate <budget|evidence> [options]");
}

function runConfigCommand(commandArguments) {
  const [action, ...actionArguments] = commandArguments;
  if (action !== "validate") {
    throw new Error("usage: shipproof config validate [path] [--config <file>] [--format <text|json>]");
  }
  validateCommandArguments(actionArguments, { values: ["--config", "--format"] });
  const repositoryRoot = resolve(readPositionalArgument(actionArguments, ".", ["--config", "--format"]));
  if (!existsSync(repositoryRoot) || !statSync(repositoryRoot).isDirectory()) {
    throw new Error(`not a directory: ${repositoryRoot}`);
  }
  const requestedPolicyPath = readOptionValue(actionArguments, "--config", ".shipproof.yml");
  const format = readOptionValue(actionArguments, "--format", "text");
  if (!new Set(["text", "json"]).has(format)) throw new Error("--format must be text or json");
  const loaded = loadPolicy(repositoryRoot, requestedPolicyPath);
  const report = {
    schema_version: "1.0",
    tool: { name: "ShipProof", version: VERSION, command: "config validate" },
    root: repositoryRoot,
    policy_path: loaded.path,
    verdict: "PASS_WITH_EVIDENCE",
    valid: true,
  };
  if (format === "json") console.log(JSON.stringify(report, null, 2));
  else console.log(`shipproof: policy valid: ${relative(repositoryRoot, loaded.path) || ".shipproof.yml"}`);
  return 0;
}

function runInitCommand(commandArguments) {
  const scope = readOptionValue(commandArguments, "--scope", "project");
  if (!new Set(["project", "global"]).has(scope)) throw new Error("--scope must be project or global");
  validateCommandArguments(commandArguments, {
    values: ["--target", "--scope"],
    flags: ["--force"],
    maxPositionals: scope === "global" ? 0 : 1,
  });
  const installOptions = parseInstallOptions(commandArguments);
  if (scope === "global") {
    printInstallationSummary(installSkills({ ...installOptions, scope: "user" }), "user");
    return 0;
  }

  const projectRoot = resolve(readPositionalArgument(commandArguments, ".", ["--target", "--scope"]));
  printInstallationSummary(installSkills({ ...installOptions, scope: "project", projectRoot }), "project");
  const policyPath = join(projectRoot, ".shipproof.yml");
  if (!existsSync(policyPath)) {
    validatePolicy(parsePolicyText(POLICY_TEMPLATE));
    writeFileSync(policyPath, POLICY_TEMPLATE, "utf8");
    console.log("shipproof: created validated .shipproof.yml production gate policy");
  }
  return 0;
}

export function runCli(argumentsList) {
  const [commandName = "scan", ...commandArguments] = argumentsList;
  try {
    if (["help", "--help", "-h"].includes(commandName)) {
      console.log(HELP);
      return 0;
    }
    if (["version", "--version", "-v"].includes(commandName)) {
      console.log(VERSION);
      return 0;
    }
    if (commandName === "doctor") {
      validateCommandArguments(commandArguments, { flags: ["--json"] });
      return runDoctorCommand(readPositionalArgument(commandArguments), commandArguments.includes("--json"));
    }
    if (commandName === "init") return runInitCommand(commandArguments);
    if (commandName === "config") return runConfigCommand(commandArguments);
    if (commandName === "labs") return runLabsCommand(commandArguments);
    if (commandName === "gate") return runGateCommand(commandArguments);
    if (commandName === "install") {
      assertLegacyCommandAvailable(commandName);
      warnLegacyCommand("install", "shipproof init --scope global");
      validateCommandArguments(commandArguments, { values: ["--target"], flags: ["--force"], maxPositionals: 0 });
      return runInitCommand([...commandArguments, "--scope", "global"]);
    }
    if (commandName === "prompt") {
      assertLegacyCommandAvailable(commandName);
      warnLegacyCommand("prompt", "shipproof init");
      validateCommandArguments(commandArguments);
      return printPrompt(commandArguments[0] || "list");
    }
    if (commandName === "mcp") {
      validateCommandArguments(commandArguments, { maxPositionals: 0 });
      return runMcpServer();
    }
    if (commandName === "check") {
      validateCommandArguments(commandArguments, { values: ["--config", "--format"] });
      const rootPath = readPositionalArgument(commandArguments, ".", ["--config", "--format"]);
      return runCheckCommand(rootPath, commandArguments);
    }
    if (commandName === "explain") {
      validateCommandArguments(commandArguments, {
        values: ["--context-level", "--format"],
        maxPositionals: 1,
      });
      const ruleId = readPositionalArgument(commandArguments, null, [
        "--context-level",
        "--format",
      ]);
      if (!ruleId) throw new Error("usage: shipproof explain <rule-id>");
      return runPythonCommand(
        PYTHON_COMMANDS.get("scan"),
        ["--explain", ...commandArguments],
      );
    }
    if (commandName === "hook") {
      assertLegacyCommandAvailable(commandName);
      console.error(
        "shipproof: warning: `shipproof hook` is legacy; configure your pre-commit framework to run `shipproof check`",
      );
      return runHookCommand(commandArguments);
    }
    if (commandName === "badge") {
      throw new Error(
        "badge was retired because static CLI output cannot attest repository status; use a CI workflow-status badge",
      );
    }
    if (LAB_COMMANDS.has(commandName)) {
      assertLegacyCommandAvailable(commandName);
      warnLegacyCommand(commandName, `shipproof labs ${commandName}`);
      return runLabsCommand([commandName, ...commandArguments]);
    }
    if (commandName === "budget") {
      assertLegacyCommandAvailable(commandName);
      warnLegacyCommand("budget", "shipproof gate budget");
      return runGateCommand(["budget", ...commandArguments]);
    }
    if (commandName === "evidence") {
      assertLegacyCommandAvailable(commandName);
      warnLegacyCommand("evidence", "shipproof gate evidence");
      return runGateCommand(["evidence", ...commandArguments]);
    }
    if (commandName === "benchmark") {
      assertLegacyCommandAvailable(commandName);
      warnLegacyCommand("benchmark", "npm run benchmark");
      return runPythonCommand(PYTHON_COMMANDS.get("benchmark"), commandArguments);
    }
    if (commandName === "worktree") {
      assertLegacyCommandAvailable(commandName);
      warnLegacyCommand("worktree", "git worktree");
      return runPythonCommand(PYTHON_COMMANDS.get("worktree"), commandArguments);
    }
    const pythonScript = PYTHON_COMMANDS.get(commandName);
    if (pythonScript) return runPythonCommand(pythonScript, commandArguments);
    throw new Error(`unknown command: ${commandName}. Run \`shipproof help\`.`);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.error(`shipproof: ${message}`);
    return 2;
  }
}

export const internals = {
  PACKAGE_ROOT,
  LEGACY_COMMAND_REPLACEMENTS,
  PROMPT_FILES,
  isShipProofManagedHook,
  assertLegacyCommandAvailable,
  legacyAliasesEnabled,
  isSupportedPythonVersion,
  listSkillNames,
  resolveGitHooksDirectory,
  resolveGateLimits,
  runHookCommand,
  runPythonJsonCommand,
};
