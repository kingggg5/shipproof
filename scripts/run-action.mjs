import { appendFileSync, existsSync, readFileSync, realpathSync, statSync, unlinkSync } from "node:fs";
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

import { detectPythonRuntime } from "../lib/runtime.mjs";

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
  const changedSince = environment.SHIPPROOF_INPUT_CHANGED_SINCE || "";
  if (changedSince && !/^[A-Za-z0-9._/@][A-Za-z0-9._/@~-]*$/.test(changedSince)) {
    throw new Error("changed-since must be a plain git ref (branch, tag, or commit)");
  }
  return { target, format, output, failOn, baseline, maxFileBytes, changedSince };
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
  if (inputs.baseline) argumentsList.push("--baseline", inputs.baseline);
  if (inputs.changedSince) argumentsList.push("--changed-since", inputs.changedSince);
  return argumentsList;
}

function findPython() {
  const runtime = detectPythonRuntime();
  if (!runtime) throw new Error("Python 3.10+ is required by the ShipProof action");
  return { command: runtime.command, prefix: runtime.argumentPrefix };
}

const MAX_SUMMARY_ROWS = 200;
const MAX_SUMMARY_INPUT_BYTES = 1_000_000;

function markdownCell(value) {
  return String(value ?? "")
    .replaceAll("|", "\\|")
    .replaceAll("\r", " ")
    .replaceAll("\n", " ");
}

function gateSummaryHeading(exitCode, failOn) {
  const verdict = exitCode === 0 ? "PASSED" : exitCode === 1 ? "BLOCKED" : "UNAVAILABLE";
  return `### 🛡️ ShipProof Gate: **${verdict}** (fail-on: \`${failOn}\`)`;
}

export function formatActionSummary(
  reportPath,
  format,
  { exitCode = 0, failOn = "high" } = {},
) {
  try {
    if (!existsSync(reportPath)) return "";
    const heading = gateSummaryHeading(exitCode, failOn);
    const reportBytes = statSync(reportPath).size;
    if (reportBytes > MAX_SUMMARY_INPUT_BYTES) {
      return `${heading}\n\nSummary omitted because the report exceeds the ${MAX_SUMMARY_INPUT_BYTES}-byte display limit. Download the full report artifact.`;
    }
    const content = readFileSync(reportPath, "utf8");
    if (format === "markdown") {
      return `${heading}\n\n${content}`;
    }
    if (format === "json") {
      const data = JSON.parse(content);
      const verdict = data.verdict || "UNKNOWN";
      const findings = data.findings || [];
      const lines = [
        heading,
        "",
        `Evidence verdict: **${verdict}**`,
        "",
        `Scanned **${data.summary?.files_scanned || 0}** files • Found **${findings.length}** issues`,
        "",
      ];
      if (findings.length > 0) {
        lines.push("| Severity | Rule | Location | Description |");
        lines.push("| :--- | :--- | :--- | :--- |");
        for (const f of findings.slice(0, MAX_SUMMARY_ROWS)) {
          const sevIcon = f.severity === "critical" || f.severity === "high" ? "🔴" : f.severity === "medium" ? "🟡" : "🟢";
          lines.push(`| ${sevIcon} ${markdownCell(f.severity?.toUpperCase())} | \`${markdownCell(f.rule_id)}\` | \`${markdownCell(f.path)}:${markdownCell(f.line)}\` | ${markdownCell(f.title)} |`);
        }
        if (findings.length > MAX_SUMMARY_ROWS) {
          lines.push("", `…and ${findings.length - MAX_SUMMARY_ROWS} more findings in the full report artifact.`);
        }
      }
      return lines.join("\n");
    }
    if (format === "sarif") {
      const sarif = JSON.parse(content);
      const results = sarif.runs?.[0]?.results || [];
      const lines = [
        heading,
        "",
        `Found **${results.length}** issue(s)`,
        "",
      ];
      if (results.length > 0) {
        lines.push("| Level | Rule | Location | Message |");
        lines.push("| :--- | :--- | :--- | :--- |");
        for (const r of results.slice(0, MAX_SUMMARY_ROWS)) {
          const loc = r.locations?.[0]?.physicalLocation;
          const pathStr = loc?.artifactLocation?.uri ? `${loc.artifactLocation.uri}:${loc.region?.startLine || 1}` : "unknown";
          const levelIcon = r.level === "error" ? "🔴" : r.level === "warning" ? "🟡" : "🟢";
          lines.push(`| ${levelIcon} ${markdownCell(r.level?.toUpperCase() || "NOTE")} | \`${markdownCell(r.ruleId)}\` | \`${markdownCell(pathStr)}\` | ${markdownCell(r.message?.text || "")} |`);
        }
        if (results.length > MAX_SUMMARY_ROWS) {
          lines.push("", `…and ${results.length - MAX_SUMMARY_ROWS} more findings in the SARIF artifact.`);
        }
      }
      return lines.join("\n");
    }
  } catch {
    return "";
  }
  return "";
}

export function main(environment = process.env) {
  try {
    const inputs = validateActionInputs(environment);
    const python = findPython();
    if (existsSync(inputs.output)) unlinkSync(inputs.output);
    const result = spawnSync(python.command, [...python.prefix, ...buildScannerArguments(inputs)], {
      stdio: "inherit",
      shell: false,
      windowsHide: true,
    });
    let exitCode = result.error ? 2 : (result.status ?? 2);
    // Scanner crashes surface as unusual statuses (including raw Windows
    // NTSTATUS values); the action contract only defines 0/1/2.
    if (exitCode !== 0 && exitCode !== 1 && exitCode !== 2) {
      console.error(`shipproof-action: scanner exited with status ${exitCode}; reporting unavailable evidence`);
      exitCode = 2;
    }
    const reportAvailable = (
      (exitCode === 0 || exitCode === 1)
      && existsSync(inputs.output)
      && statSync(inputs.output).isFile()
    );
    if ((exitCode === 0 || exitCode === 1) && !reportAvailable) {
      console.error("shipproof-action: scanner did not produce a fresh report");
      return 2;
    }
    if (!reportAvailable && existsSync(inputs.output)) unlinkSync(inputs.output);
    if (reportAvailable && environment.GITHUB_OUTPUT) {
      appendFileSync(environment.GITHUB_OUTPUT, `report-path=${inputs.output}\n`, "utf8");
    }
    if (reportAvailable && environment.GITHUB_STEP_SUMMARY) {
      const summary = formatActionSummary(inputs.output, inputs.format, {
        exitCode,
        failOn: inputs.failOn,
      });
      if (summary) {
        appendFileSync(environment.GITHUB_STEP_SUMMARY, `${summary}\n`, "utf8");
      }
    }
    return exitCode;
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.error(`shipproof-action: ${message}`);
    return 2;
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exitCode = main();
}
