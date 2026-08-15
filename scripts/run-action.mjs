import { appendFileSync, existsSync, realpathSync, statSync } from "node:fs";
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const ACTION_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const FORMATS = new Set(["json", "markdown", "sarif"]);
const SEVERITIES = new Set(["critical", "high", "medium", "low", "none"]);

function isInside(root, candidate) {
  const pathFromRoot = relative(root, candidate);
  return pathFromRoot === "" || (
    pathFromRoot !== ".."
    && !pathFromRoot.startsWith(`..${sep}`)
    && !isAbsolute(pathFromRoot)
  );
}

function resolveInside(root, candidate, label) {
  if (typeof candidate !== "string" || /[\0\r\n]/.test(candidate)) {
    throw new Error(`${label} contains invalid characters`);
  }
  if (isAbsolute(candidate)) throw new Error(`${label} must be repository-relative`);
  const resolvedRoot = resolve(root);
  const resolvedCandidate = resolve(resolvedRoot, candidate);
  const pathFromRoot = relative(resolvedRoot, resolvedCandidate);
  if (pathFromRoot === ".." || pathFromRoot.startsWith(`..${sep}`) || isAbsolute(pathFromRoot)) {
    throw new Error(`${label} escapes the repository workspace`);
  }
  return resolvedCandidate;
}

function readBoolean(environment, name, fallback = "false") {
  const value = environment[name] || fallback;
  if (!["true", "false"].includes(value)) throw new Error(`${name} must be true or false`);
  return value === "true";
}

function readExcludePatterns(environment) {
  const value = environment.SHIPPROOF_INPUT_EXCLUDE || "";
  const patterns = value.split(/\r?\n/).map((item) => item.trim()).filter(Boolean);
  if (patterns.length > 100) throw new Error("exclude accepts at most 100 patterns");
  return patterns;
}

export function validateActionInputs(environment = process.env) {
  const workspace = environment.GITHUB_WORKSPACE;
  if (!workspace) throw new Error("GITHUB_WORKSPACE is required");
  const format = environment.SHIPPROOF_INPUT_FORMAT || "sarif";
  const failOn = environment.SHIPPROOF_INPUT_FAIL_ON || "high";
  if (!FORMATS.has(format)) throw new Error(`unsupported report format: ${format}`);
  if (!SEVERITIES.has(failOn)) throw new Error(`unsupported fail-on severity: ${failOn}`);

  const maxFileBytes = Number(environment.SHIPPROOF_INPUT_MAX_FILE_BYTES || "1000000");
  if (!Number.isSafeInteger(maxFileBytes) || maxFileBytes < 1024 || maxFileBytes > 100_000_000) {
    throw new Error("max-file-bytes must be an integer from 1024 through 100000000");
  }
  const includeGas = readBoolean(environment, "SHIPPROOF_INPUT_INCLUDE_GAS");
  const exclude = readExcludePatterns(environment);

  const realWorkspace = realpathSync.native(resolve(workspace));
  const targetCandidate = resolveInside(workspace, environment.SHIPPROOF_INPUT_PATH || ".", "path");
  if (!existsSync(targetCandidate) || !statSync(targetCandidate).isDirectory()) {
    throw new Error(`scan path is not a directory: ${targetCandidate}`);
  }
  const target = realpathSync.native(targetCandidate);
  if (!isInside(realWorkspace, target)) throw new Error("scan path resolves outside the workspace");
  const outputCandidate = resolveInside(workspace, environment.SHIPPROOF_INPUT_OUTPUT || "shipproof.sarif", "output");
  const outputParent = dirname(outputCandidate);
  if (!existsSync(outputParent) || !statSync(outputParent).isDirectory()) {
    throw new Error(`output directory does not exist: ${outputParent}`);
  }
  const realOutputParent = realpathSync.native(outputParent);
  if (!isInside(realWorkspace, realOutputParent)) {
    throw new Error("output directory resolves outside the workspace");
  }
  if (existsSync(outputCandidate) && !statSync(outputCandidate).isFile()) {
    throw new Error("output path is not a file");
  }
  const output = existsSync(outputCandidate)
    ? realpathSync.native(outputCandidate)
    : join(realOutputParent, basename(outputCandidate));
  if (!isInside(realWorkspace, output)) throw new Error("output path resolves outside the workspace");
  const baselineValue = environment.SHIPPROOF_INPUT_BASELINE || "";
  const baselineCandidate = baselineValue ? resolveInside(workspace, baselineValue, "baseline") : null;
  if (baselineCandidate && (!existsSync(baselineCandidate) || !statSync(baselineCandidate).isFile())) {
    throw new Error(`baseline is not a file: ${baselineCandidate}`);
  }
  const baseline = baselineCandidate ? realpathSync.native(baselineCandidate) : null;
  if (baseline && !isInside(realWorkspace, baseline)) {
    throw new Error("baseline resolves outside the workspace");
  }
  return { target, format, output, failOn, baseline, maxFileBytes, includeGas, exclude };
}

export function buildScannerArguments(inputs) {
  const argumentsList = [
    resolve(ACTION_ROOT, "skills/audit-production-readiness/scripts/scan_repo.py"),
    inputs.target,
    "--format",
    inputs.format,
    "--output",
    inputs.output,
    "--fail-on",
    inputs.failOn,
    "--max-file-bytes",
    String(inputs.maxFileBytes),
  ];
  if (inputs.includeGas) argumentsList.push("--include-gas");
  for (const pattern of inputs.exclude || []) argumentsList.push("--exclude", pattern);
  if (inputs.baseline) argumentsList.push("--baseline", inputs.baseline);
  return argumentsList;
}

function findPython() {
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
  throw new Error("Python 3.10+ is required by the ShipProof action");
}

export function main(environment = process.env) {
  try {
    const inputs = validateActionInputs(environment);
    const python = findPython();
    const result = spawnSync(python.command, [...python.prefix, ...buildScannerArguments(inputs)], {
      stdio: "inherit",
      shell: false,
      windowsHide: true,
    });
    if (environment.GITHUB_OUTPUT) {
      appendFileSync(environment.GITHUB_OUTPUT, `report-path=${inputs.output}\n`, "utf8");
    }
    return result.status ?? 2;
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.error(`shipproof-action: ${message}`);
    return 2;
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exitCode = main();
}
