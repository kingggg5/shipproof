import { cpSync, existsSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join, relative, resolve, sep } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const PACKAGE_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const VERSION = JSON.parse(readFileSync(join(PACKAGE_ROOT, "package.json"), "utf8")).version;
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
]);

const HELP = `ShipProof ${VERSION} — evidence-first production engineering

Usage:
  shipproof <command> [options]

Commands:
  doctor [path] [--json]            Inspect local readiness without changing files
  init [path] [--target <host>]      Add project skills (.agents/.claude)
  install [--target <host>]          Add personal skills for Codex/Claude
  prompt <name|list>                 Print a focused agent prompt
  scan [path] [scanner options]      Run the local repository scanner
  budget [budget options]            Enforce CPU/RAM/latency budgets
  capacity [capacity options]        Model an explicit workload hypothesis
  help                               Show this help
  version                            Print the version

Hosts: codex, claude, both. Existing skills are skipped; pass --force to replace.
Python 3.10+ is required only for scan, budget, and capacity.`;

const PYTHON_COMMANDS = new Map([
  ["scan", "skills/audit-production-readiness/scripts/scan_repo.py"],
  ["budget", "skills/engineer-production-systems/scripts/check_budget.py"],
  ["capacity", "skills/audit-production-readiness/scripts/capacity_model.py"],
]);

function readOptionValue(commandArguments, optionName, fallback) {
  const index = commandArguments.indexOf(optionName);
  if (index < 0) return fallback;
  if (!commandArguments[index + 1] || commandArguments[index + 1].startsWith("--")) {
    throw new Error(`${optionName} requires a value`);
  }
  return commandArguments[index + 1];
}

function readPositionalArgument(commandArguments, fallback = ".") {
  const optionsWithValues = new Set(["--target"]);
  for (let index = 0; index < commandArguments.length; index += 1) {
    const value = commandArguments[index];
    if (optionsWithValues.has(value)) {
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

function readExecutableVersion(command, commandArguments = ["--version"]) {
  const processResult = spawnSync(command, commandArguments, {
    encoding: "utf8",
    shell: false,
    windowsHide: true,
  });
  return processResult.status === 0
    ? (processResult.stdout || processResult.stderr).trim().split(/\r?\n/, 1)[0]
    : null;
}

function isSupportedPythonVersion(version) {
  const match = /^Python\s+(\d+)\.(\d+)/.exec(version);
  return Boolean(match) && (Number(match[1]) > 3 || (Number(match[1]) === 3 && Number(match[2]) >= 10));
}

function detectPythonRuntime() {
  const candidates = [];
  if (process.env.SHIPPROOF_PYTHON) candidates.push([process.env.SHIPPROOF_PYTHON, []]);
  if (process.platform === "win32") candidates.push(["py", ["-3"]]);
  candidates.push(["python3", []], ["python", []]);
  for (const [command, argumentPrefix] of candidates) {
    const version = readExecutableVersion(command, [...argumentPrefix, "--version"]);
    if (version && isSupportedPythonVersion(version)) {
      return { command, argumentPrefix, version };
    }
  }
  return null;
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
    root: repositoryRoot,
    verdict: checks.some((check) => check.status === "warn") ? "WARN" : "PASS",
    checks,
  };
  if (useJsonOutput) console.log(JSON.stringify(report, null, 2));
  else {
    console.log(`ShipProof doctor: ${report.verdict}\n`);
    for (const check of checks) {
      console.log(`${check.status === "pass" ? "[ok]" : "[!!]"} ${check.id}: ${check.detail}`);
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
  return processResult.status ?? 2;
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

export function runCli(argumentsList) {
  const [commandName = "help", ...commandArguments] = argumentsList;
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
    if (commandName === "prompt") {
      validateCommandArguments(commandArguments);
      return printPrompt(commandArguments[0] || "list");
    }
    if (commandName === "init") {
      validateCommandArguments(commandArguments, { values: ["--target"], flags: ["--force"] });
      const installOptions = parseInstallOptions(commandArguments);
      const projectRoot = resolve(readPositionalArgument(commandArguments));
      printInstallationSummary(installSkills({ ...installOptions, scope: "project", projectRoot }), "project");
      return 0;
    }
    if (commandName === "install") {
      validateCommandArguments(commandArguments, { values: ["--target"], flags: ["--force"], maxPositionals: 0 });
      printInstallationSummary(installSkills({ ...parseInstallOptions(commandArguments), scope: "user" }), "user");
      return 0;
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

export const internals = { PACKAGE_ROOT, PROMPT_FILES, isSupportedPythonVersion, listSkillNames };
