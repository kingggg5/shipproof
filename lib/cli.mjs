import { cpSync, existsSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join, relative, resolve, sep } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const PACKAGE_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const VERSION = JSON.parse(readFileSync(join(PACKAGE_ROOT, "package.json"), "utf8")).version;
const HOSTS = new Set(["codex", "claude", "both"]);
const PROMPTS = new Map([
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

function option(args, name, fallback) {
  const index = args.indexOf(name);
  if (index < 0) return fallback;
  if (!args[index + 1] || args[index + 1].startsWith("--")) {
    throw new Error(`${name} requires a value`);
  }
  return args[index + 1];
}

function positional(args, fallback = ".") {
  const optionsWithValues = new Set(["--target"]);
  for (let index = 0; index < args.length; index += 1) {
    const value = args[index];
    if (optionsWithValues.has(value)) {
      index += 1;
      continue;
    }
    if (!value.startsWith("-")) return value;
  }
  return fallback;
}

function validateCommandArgs(args, { values = [], flags = [], maxPositionals = 1 } = {}) {
  const valueOptions = new Set(values);
  const flagOptions = new Set(flags);
  let positionals = 0;
  for (let index = 0; index < args.length; index += 1) {
    const value = args[index];
    if (valueOptions.has(value)) {
      if (!args[index + 1] || args[index + 1].startsWith("-")) throw new Error(`${value} requires a value`);
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

function skillNames() {
  return readdirSync(join(PACKAGE_ROOT, "skills"), { withFileTypes: true })
    .filter((entry) => entry.isDirectory() && existsSync(join(PACKAGE_ROOT, "skills", entry.name, "SKILL.md")))
    .map((entry) => entry.name)
    .sort();
}

function safeReplace(source, base, name, force) {
  const root = resolve(base);
  const destination = resolve(root, name);
  if (destination === root || !destination.startsWith(`${root}${sep}`)) {
    throw new Error(`unsafe skill destination: ${destination}`);
  }
  if (existsSync(destination)) {
    if (!force) return "skipped";
    rmSync(destination, { recursive: true, force: true });
  }
  mkdirSync(root, { recursive: true });
  cpSync(source, destination, { recursive: true, errorOnExist: true, force: false });
  return "installed";
}

function roots(target, scope, projectRoot) {
  const home = homedir();
  const mapping = {
    codex: scope === "project"
      ? join(projectRoot, ".agents", "skills")
      : process.env.SHIPPROOF_CODEX_SKILLS_DIR || join(home, ".agents", "skills"),
    claude: scope === "project"
      ? join(projectRoot, ".claude", "skills")
      : process.env.SHIPPROOF_CLAUDE_SKILLS_DIR || join(home, ".claude", "skills"),
  };
  return target === "both" ? Object.entries(mapping) : [[target, mapping[target]]];
}

export function installSkills({ target = "both", scope = "user", projectRoot = ".", force = false } = {}) {
  if (!HOSTS.has(target)) throw new Error(`unsupported target: ${target}`);
  const results = [];
  for (const [host, base] of roots(target, scope, resolve(projectRoot))) {
    for (const name of skillNames()) {
      const source = join(PACKAGE_ROOT, "skills", name);
      results.push({ host, name, path: join(resolve(base), name), status: safeReplace(source, base, name, force) });
    }
  }
  return results;
}

function executable(command, args = ["--version"]) {
  const result = spawnSync(command, args, { encoding: "utf8", shell: false, windowsHide: true });
  return result.status === 0 ? (result.stdout || result.stderr).trim().split(/\r?\n/, 1)[0] : null;
}

function python() {
  const candidates = [];
  if (process.env.SHIPPROOF_PYTHON) candidates.push([process.env.SHIPPROOF_PYTHON, []]);
  if (process.platform === "win32") candidates.push(["py", ["-3"]]);
  candidates.push(["python3", []], ["python", []]);
  for (const [command, prefix] of candidates) {
    const version = executable(command, [...prefix, "--version"]);
    if (version) return { command, prefix, version };
  }
  return null;
}

function doctor(rootArg, json) {
  const root = resolve(rootArg);
  if (!existsSync(root) || !statSync(root).isDirectory()) throw new Error(`not a directory: ${root}`);
  const py = python();
  const has = (...parts) => existsSync(join(root, ...parts));
  const checks = [
    { id: "node", status: "pass", detail: process.version },
    { id: "python-gates", status: py ? "pass" : "warn", detail: py?.version || "Python 3.10+ not found" },
    { id: "source-control", status: has(".git") ? "pass" : "warn", detail: has(".git") ? "Git repository detected" : "No .git directory" },
    { id: "ci", status: has(".github", "workflows") ? "pass" : "warn", detail: has(".github", "workflows") ? "CI workflow directory detected" : "No GitHub Actions workflow directory" },
    { id: "security-policy", status: has("SECURITY.md") ? "pass" : "warn", detail: has("SECURITY.md") ? "Private reporting policy detected" : "SECURITY.md not found" },
    { id: "codex-skill", status: has(".agents", "skills") || has(".codex-plugin") || has("skills") ? "pass" : "warn", detail: "Codex project skill or plugin source" },
    { id: "claude-skill", status: has(".claude", "skills") || has(".claude-plugin") || has("skills") ? "pass" : "warn", detail: "Claude project skill or plugin source" },
    { id: "lockfile", status: ["package-lock.json", "pnpm-lock.yaml", "yarn.lock", "uv.lock", "poetry.lock", "Cargo.lock", "go.sum"].some((name) => has(name)) ? "pass" : "warn", detail: "Reproducible dependency lock" },
  ];
  const report = { schema_version: "1.0", root, verdict: checks.some((item) => item.status === "warn") ? "WARN" : "PASS", checks };
  if (json) console.log(JSON.stringify(report, null, 2));
  else {
    console.log(`ShipProof doctor: ${report.verdict}\n`);
    for (const check of checks) console.log(`${check.status === "pass" ? "[ok]" : "[!!]"} ${check.id}: ${check.detail}`);
  }
  return report.verdict === "PASS" ? 0 : 1;
}

function runPython(script, args) {
  const runtime = python();
  if (!runtime) {
    console.error("shipproof: Python 3.10+ is required for this command. Run `shipproof doctor` for details.");
    return 2;
  }
  const result = spawnSync(runtime.command, [...runtime.prefix, join(PACKAGE_ROOT, script), ...args], {
    stdio: "inherit",
    shell: false,
    windowsHide: true,
  });
  if (result.error) {
    console.error(`shipproof: ${result.error.message}`);
    return 2;
  }
  return result.status ?? 2;
}

function printInstall(results, scope) {
  for (const item of results) console.log(`${item.status}: ${item.host}/${item.name} -> ${item.path}`);
  console.log(scope === "project" ? "Project skills are ready for source control review." : "Personal skills are ready. Restart the host only if it does not detect them.");
}

function printPrompt(name) {
  if (name === "list" || !name) {
    console.log([...PROMPTS.keys()].join("\n"));
    return 0;
  }
  const filename = PROMPTS.get(name);
  if (!filename) throw new Error(`unknown prompt: ${name}. Run \`shipproof prompt list\`.`);
  console.log(readFileSync(join(PACKAGE_ROOT, "prompts", filename), "utf8").trim());
  return 0;
}

function targetArgs(args) {
  const target = option(args, "--target", "both");
  if (!HOSTS.has(target)) throw new Error("--target must be codex, claude, or both");
  const force = args.includes("--force");
  return { target, force };
}

export async function run(argv) {
  const [command = "help", ...args] = argv;
  try {
    if (["help", "--help", "-h"].includes(command)) {
      console.log(HELP);
      return 0;
    }
    if (["version", "--version", "-v"].includes(command)) {
      console.log(VERSION);
      return 0;
    }
    if (command === "doctor") {
      validateCommandArgs(args, { flags: ["--json"] });
      return doctor(positional(args), args.includes("--json"));
    }
    if (command === "prompt") return printPrompt(args[0] || "list");
    if (command === "init") {
      validateCommandArgs(args, { values: ["--target"], flags: ["--force"] });
      const values = targetArgs(args);
      const root = resolve(positional(args));
      printInstall(installSkills({ ...values, scope: "project", projectRoot: root }), "project");
      return 0;
    }
    if (command === "install") {
      validateCommandArgs(args, { values: ["--target"], flags: ["--force"], maxPositionals: 0 });
      printInstall(installSkills({ ...targetArgs(args), scope: "user" }), "user");
      return 0;
    }
    if (command === "scan") {
      return runPython("skills/audit-production-readiness/scripts/scan_repo.py", args);
    }
    if (command === "budget") {
      return runPython("skills/engineer-production-systems/scripts/check_budget.py", args);
    }
    if (command === "capacity") {
      return runPython("skills/audit-production-readiness/scripts/capacity_model.py", args);
    }
    throw new Error(`unknown command: ${command}. Run \`shipproof help\`.`);
  } catch (error) {
    console.error(`shipproof: ${error.message}`);
    return 2;
  }
}

export const internals = { PACKAGE_ROOT, PROMPTS, skillNames };
